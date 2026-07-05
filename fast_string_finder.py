import idaapi
import idc
import idautils
import ida_bytes
import ida_segment
from PyQt5 import QtWidgets, QtCore, QtGui

PLUGIN_NAME = "Fast String Finder"
PLUGIN_HOTKEY = "Ctrl-Shift-F12"

MIN_STRING_LEN = 4       # match C++: string.length() > 3
MAX_STRING_LEN = 2048    # sanity cap when reading a candidate string


class StringScanner:
    """Manually decodes RIP-relative LEA instructions straight from the raw
    bytes of the executable segments -- it never touches IDA's analysis cache
    (no heads, no functions), so it works even on builds IDA can't analyze.

    A LEA reg, [rip+disp32] encodes as:
        [REX prefix]  0x8D  modrm  disp32
    where modrm has mod=00, rm=101  ->  (modrm & 0xC7) == 0x05.
    We scan .text for 0x8D, validate the modrm, compute the target, and check
    whether it lands on a printable, null-terminated string in a data segment.
    """

    def __init__(self):
        self.strings = {}   # target address -> decoded string
        self.xrefs = {}     # target address -> [lea instruction addresses]
        self._data_ranges = []   # (start, end, bytes) for non-exec segments
        self._is64 = idaapi.get_inf_structure().is_64bit()

    # ------------------------------------------------------------------ data
    def _load_data_segments(self):
        self._data_ranges = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None or (seg.perm & ida_segment.SEGPERM_EXEC):
                continue
            size = seg.end_ea - seg.start_ea
            if size <= 0:
                continue
            data = ida_bytes.get_bytes(seg.start_ea, size)
            if data:
                self._data_ranges.append((seg.start_ea, seg.end_ea, data))

    def _read_string_at(self, ea):
        """Return the decoded string at `ea` if it is a printable,
        null-terminated ASCII string longer than MIN_STRING_LEN, else None."""
        for start, end, data in self._data_ranges:
            if start <= ea < end:
                off = ea - start
                n = len(data)
                i = off
                limit = min(n, off + MAX_STRING_LEN)
                while i < limit:
                    b = data[i]
                    if b == 0:
                        length = i - off
                        if length >= MIN_STRING_LEN:
                            return data[off:i].decode("ascii", "replace")
                        return None
                    # allow tab/newline/CR + printable ASCII
                    if b < 0x09 or (0x0D < b < 0x20) or b > 0x7E:
                        return None
                    i += 1
                return None
        return None

    # ------------------------------------------------------------------ scan
    def scan(self, progress_cb=None):
        self.strings.clear()
        self.xrefs.clear()
        self._load_data_segments()

        exec_segs = []
        total_bytes = 0
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
                continue
            size = seg.end_ea - seg.start_ea
            if size <= 0:
                continue
            exec_segs.append((seg.start_ea, size))
            total_bytes += size

        done_bytes = 0
        last_pct = -1
        for seg_start, size in exec_segs:
            buf = ida_bytes.get_bytes(seg_start, size)
            if not buf:
                done_bytes += size
                continue
            n = len(buf)
            pos = 0
            while True:
                i = buf.find(0x8D, pos)
                if i < 0:
                    break
                pos = i + 1
                # need modrm + 4-byte disp after the opcode
                if i + 5 >= n:
                    continue
                modrm = buf[i + 1]
                if (modrm & 0xC7) != 0x05:
                    continue

                disp = int.from_bytes(buf[i + 2:i + 6], "little", signed=True)
                opcode_ea = seg_start + i
                if self._is64:
                    # RIP base is the address of the next instruction = opcode + 6
                    target = (opcode_ea + 6 + disp) & 0xFFFFFFFFFFFFFFFF
                else:
                    target = disp & 0xFFFFFFFF

                if target in self.strings:
                    s = self.strings[target]
                else:
                    s = self._read_string_at(target)
                    if s is None:
                        continue
                    self.strings[target] = s

                # LEA start accounts for an optional REX prefix byte
                lea_ea = opcode_ea
                if i > 0 and 0x40 <= buf[i - 1] <= 0x4F:
                    lea_ea = opcode_ea - 1
                self.xrefs.setdefault(target, []).append(lea_ea)

                if progress_cb is not None:
                    pct = int((done_bytes + pos) * 100 / total_bytes) if total_bytes else 100
                    if pct != last_pct:
                        last_pct = pct
                        progress_cb(pct)
            done_bytes += size
            if progress_cb is not None and total_bytes:
                pct = int(done_bytes * 100 / total_bytes)
                if pct != last_pct:
                    last_pct = pct
                    progress_cb(pct)

        total_xrefs = sum(len(v) for v in self.xrefs.values())
        return len(self.strings), total_xrefs


# Session-wide cache. Lives as long as the IDB is open, so closing and
# reopening the window keeps the last scan. Pressing "Find Strings" rebuilds it.
_SCANNER = StringScanner()
_HAS_SCANNED = False


class FastStringFinderForm(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        self.scanner = _SCANNER
        self.all_rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._build_ui()
        self._restore_from_cache()

    def _restore_from_cache(self):
        if not _HAS_SCANNED:
            return
        self.all_rows = sorted(self.scanner.strings.items(), key=lambda kv: kv[0])
        total_xrefs = sum(len(v) for v in self.scanner.xrefs.values())
        self.stats_label.setText(
            f"{len(self.all_rows)} strings found, {total_xrefs} xrefs")
        self._populate_table(self.all_rows)
        self._show_empty_xrefs()

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout()
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # --- top bar (fixed height, pinned to top) -----------------------
        top_bar = QtWidgets.QHBoxLayout()
        self.find_button = QtWidgets.QPushButton("Find Strings")
        self.find_button.clicked.connect(self.on_find_strings)
        self.stats_label = QtWidgets.QLabel("0 strings found, 0 xrefs")
        top_bar.addWidget(self.find_button)
        top_bar.addStretch(1)
        top_bar.addWidget(self.stats_label)

        top_widget = QtWidgets.QWidget()
        top_widget.setLayout(top_bar)
        top_widget.setSizePolicy(QtWidgets.QSizePolicy.Preferred,
                                 QtWidgets.QSizePolicy.Fixed)
        root.addWidget(top_widget, 0)

        # --- splitter with the two panels --------------------------------
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left: strings table + search bar
        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.string_table = QtWidgets.QTableWidget()
        self.string_table.setColumnCount(2)
        self.string_table.setHorizontalHeaderLabels(["Address", "String"])
        self.string_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.string_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.string_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.string_table.verticalHeader().setVisible(False)
        h = self.string_table.horizontalHeader()
        h.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        self.string_table.itemSelectionChanged.connect(self.on_string_selected)
        self.string_table.doubleClicked.connect(self.on_string_double_click)

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search strings... (Ctrl+F)")
        self.search_box.textChanged.connect(self.on_filter_changed)

        left_layout.addWidget(self.string_table, 1)
        left_layout.addWidget(self.search_box, 0)

        # Right: xrefs
        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.xref_stack = QtWidgets.QStackedWidget()
        self.empty_label = QtWidgets.QLabel(
            "There's nothing to show here come back later :)")
        self.empty_label.setAlignment(QtCore.Qt.AlignCenter)
        self.empty_label.setWordWrap(True)

        self.xref_table = QtWidgets.QTableWidget()
        self.xref_table.setColumnCount(2)
        self.xref_table.setHorizontalHeaderLabels(["Address", "Function"])
        self.xref_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.xref_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.xref_table.verticalHeader().setVisible(False)
        xh = self.xref_table.horizontalHeader()
        xh.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        xh.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        self.xref_table.doubleClicked.connect(self.on_xref_double_click)

        self.xref_stack.addWidget(self.empty_label)  # index 0
        self.xref_stack.addWidget(self.xref_table)    # index 1
        self.xref_stack.setCurrentIndex(0)

        right_layout.addWidget(QtWidgets.QLabel("XREFs"), 0)
        right_layout.addWidget(self.xref_stack, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        root.addWidget(splitter, 1)   # stretch=1 -> splitter fills the window
        self.parent.setLayout(root)

        find_shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+F"), self.parent)
        find_shortcut.activated.connect(self._focus_search)

    def _focus_search(self):
        self.search_box.setFocus()
        self.search_box.selectAll()

    # ------------------------------------------------------------- scanning
    def _on_progress(self, pct):
        self.stats_label.setText(f"Scanning... ({pct}% complete)")
        QtWidgets.QApplication.processEvents()

    def on_find_strings(self):
        global _HAS_SCANNED
        self.find_button.setEnabled(False)
        self.stats_label.setText("Scanning... (0% complete)")
        QtWidgets.QApplication.processEvents()
        try:
            # scan() clears the previous results before rebuilding the cache
            count, total_xrefs = self.scanner.scan(progress_cb=self._on_progress)
            _HAS_SCANNED = True
        except Exception as e:
            idaapi.msg(f"[fast string finder] scan failed: {e}\n")
            count, total_xrefs = 0, 0
        finally:
            self.find_button.setEnabled(True)

        self.all_rows = sorted(self.scanner.strings.items(), key=lambda kv: kv[0])
        self.stats_label.setText(f"{count} strings found, {total_xrefs} xrefs")
        self.search_box.clear()
        self._populate_table(self.all_rows)
        self._show_empty_xrefs()

    def _populate_table(self, rows):
        self.string_table.setRowCount(len(rows))
        for row, (ea, text) in enumerate(rows):
            addr_item = QtWidgets.QTableWidgetItem(f"0x{ea:X}")
            addr_item.setData(QtCore.Qt.UserRole, ea)
            self.string_table.setItem(row, 0, addr_item)

            str_item = QtWidgets.QTableWidgetItem(text)
            str_item.setData(QtCore.Qt.UserRole, ea)
            self.string_table.setItem(row, 1, str_item)

    def on_filter_changed(self, text):
        text = text.strip().lower()
        if not text:
            filtered = self.all_rows
        else:
            filtered = [(ea, s) for ea, s in self.all_rows
                        if text in s.lower() or text in f"{ea:x}"]
        self._populate_table(filtered)
        self._show_empty_xrefs()

    def _show_empty_xrefs(self):
        self.xref_stack.setCurrentIndex(0)

    def on_string_selected(self):
        items = self.string_table.selectedItems()
        if not items:
            self._show_empty_xrefs()
            return
        ea = items[0].data(QtCore.Qt.UserRole)
        xrefs = self.scanner.xrefs.get(ea, [])
        if not xrefs:
            self._show_empty_xrefs()
            return

        xrefs = sorted(xrefs)
        self.xref_table.setRowCount(len(xrefs))
        for i, xref_ea in enumerate(xrefs):
            addr_item = QtWidgets.QTableWidgetItem(f"0x{xref_ea:X}")
            addr_item.setData(QtCore.Qt.UserRole, xref_ea)
            self.xref_table.setItem(i, 0, addr_item)
            func_item = QtWidgets.QTableWidgetItem(idc.get_func_name(xref_ea) or "")
            self.xref_table.setItem(i, 1, func_item)
        self.xref_stack.setCurrentIndex(1)

    def on_string_double_click(self, index):
        item = self.string_table.item(index.row(), 0)
        if item:
            idc.jumpto(item.data(QtCore.Qt.UserRole))

    def on_xref_double_click(self, index):
        item = self.xref_table.item(index.row(), 0)
        if item:
            idc.jumpto(item.data(QtCore.Qt.UserRole))

    def OnClose(self, form):
        pass


class FastStringFinderPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Finds strings referenced via LEA in code and lists their xrefs"
    help = PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = FastStringFinderForm()
        form.Show(PLUGIN_NAME)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return FastStringFinderPlugin()
