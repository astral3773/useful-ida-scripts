import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt
import ida_name
import ida_xref
import ida_ua
import ida_segment
from PyQt5 import QtWidgets, QtCore

PLUGIN_NAME = "Constants Viewer"
PLUGIN_HOTKEY = "Ctrl+Shift+K"

class ConstantsViewer(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        self.title = "Constants Viewer"
        self.constants_data = []
        
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        
    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()
        
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Type", "Address", "Reference", "Ref Count", "Name", "Value"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self.on_double_click)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
        
        layout.addWidget(self.table)
        self.parent.setLayout(layout)
        
        self.refresh_constants()
        
    def get_constant_type(self, ea):
        flags = ida_bytes.get_flags(ea)
        
        if ida_bytes.is_strlit(flags):
            return "string"
        elif ida_bytes.is_dword(flags):
            return "dword"
        elif ida_bytes.is_qword(flags):
            return "qword"
        elif ida_bytes.is_float(flags):
            return "float"
        elif ida_bytes.is_double(flags):
            return "double"
        elif ida_bytes.is_struct(flags):
            return "struct"
        elif ida_bytes.is_align(flags):
            return "align"
        elif ida_bytes.is_data(flags):
            item_size = ida_bytes.get_item_size(ea)
            if item_size == 4:
                return "dword"
            elif item_size == 8:
                return "qword"
            elif item_size == 16:
                return "xmmword"
            elif item_size > 4:
                return f"data_{item_size}"
        
        return None
    
    def get_constant_value(self, ea, const_type):
        try:
            if const_type == "string":
                str_content = idc.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
                if str_content:
                    return f'"{str_content.decode("utf-8", errors="replace")}"'
                str_content = idc.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
                if str_content:
                    return f'"{str_content.decode("utf-16", errors="replace")}"'
                return '"Invalid string"'
            elif const_type in ["dword", "qword"]:
                size = {"dword": 4, "qword": 8}[const_type]
                if size == 4:
                    return f"0x{ida_bytes.get_wide_dword(ea):08X}"
                elif size == 8:
                    return f"0x{ida_bytes.get_qword(ea):016X}"
            elif const_type == "xmmword":
                return f"xmmword_{ea:X}"
            elif const_type == "float":
                import struct
                data = ida_bytes.get_bytes(ea, 4)
                return f"{struct.unpack('f', data)[0]:.6f}" if data else "0.0"
            elif const_type == "double":
                import struct
                data = ida_bytes.get_bytes(ea, 8)
                return f"{struct.unpack('d', data)[0]:.6f}" if data else "0.0"
            else:
                size = ida_bytes.get_item_size(ea)
                data = ida_bytes.get_bytes(ea, min(size, 16))
                if data:
                    return ' '.join(f'{b:02X}' for b in data) + ('...' if size > 16 else '')
        except Exception as e:
            return f"Error: {str(e)}"
        
        return "N/A"
    
    def get_reference_info(self, ea, func_ea):
        func = idaapi.get_func(func_ea)
        if not func:
            return [], 0
            
        refs_in_func = []
        total_refs = 0
        
        for ref in idautils.DataRefsTo(ea):
            total_refs += 1
            if func.start_ea <= ref < func.end_ea:
                refs_in_func.append(ref)
        
        for ref in idautils.CodeRefsTo(ea, 0):
            total_refs += 1
            if func.start_ea <= ref < func.end_ea:
                refs_in_func.append(ref)
        
        return refs_in_func, total_refs
    
    def collect_constants_in_function(self, func_ea):
        constants = []
        func = idaapi.get_func(func_ea)
        if not func:
            return constants
            
        # Get all .rdata segment addresses
        rdata_segment = ida_segment.get_segm_by_name(".rdata")
        if not rdata_segment:
            return constants
            
        # Look for all instructions in the function that reference .rdata
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                # Check for data references from this instruction
                for ref_ea in idautils.DataRefsFrom(head):
                    seg = ida_segment.getseg(ref_ea)
                    if seg and seg.start_ea == rdata_segment.start_ea:
                        constants.append(ref_ea)
                
                # Check for code references from this instruction  
                for ref_ea in idautils.CodeRefsFrom(head, 0):
                    seg = ida_segment.getseg(ref_ea)
                    if seg and seg.start_ea == rdata_segment.start_ea:
                        constants.append(ref_ea)
                
        return list(set(constants))
    
    def refresh_constants(self):
        current_ea = idc.get_screen_ea()
        func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
        
        if func_ea == idc.BADADDR:
            return
            
        func_name = idc.get_func_name(func_ea)
        self.parent.window().setWindowTitle(f"Constants Viewer - {func_name}")
        
        self.constants_data = []
        self.table.setRowCount(0)
        
        constants = self.collect_constants_in_function(func_ea)
        
        if not constants:
            return
            
        for const_ea in constants:
            const_type = self.get_constant_type(const_ea)
            if const_type is None:
                continue
                
            const_name = ida_name.get_name(const_ea)
            const_value = self.get_constant_value(const_ea, const_type)
            refs_in_func, total_refs = self.get_reference_info(const_ea, func_ea)
            
            self.constants_data.append({
                'ea': const_ea,
                'type': const_type,
                'name': const_name,
                'value': const_value,
                'refs_in_func': refs_in_func,
                'total_refs': total_refs
            })
        
        self.table.setRowCount(len(self.constants_data))
        
        for row, data in enumerate(self.constants_data):
            type_item = QtWidgets.QTableWidgetItem(data['type'])
            type_item.setData(QtCore.Qt.UserRole, data['ea'])
            self.table.setItem(row, 0, type_item)
            
            addr_item = QtWidgets.QTableWidgetItem(f"0x{data['ea']:X}")
            addr_item.setData(QtCore.Qt.UserRole, data['ea'])
            self.table.setItem(row, 1, addr_item)
            
            ref_text = f"0x{data['refs_in_func'][0]:X}" if data['refs_in_func'] else "None"
            ref_item = QtWidgets.QTableWidgetItem(ref_text)
            ref_item.setData(QtCore.Qt.UserRole, data['refs_in_func'])
            self.table.setItem(row, 2, ref_item)
            
            count_item = QtWidgets.QTableWidgetItem()
            count_item.setData(QtCore.Qt.DisplayRole, data['total_refs'])
            self.table.setItem(row, 3, count_item)
            
            name_item = QtWidgets.QTableWidgetItem(data['name'])
            self.table.setItem(row, 4, name_item)
            
            value_item = QtWidgets.QTableWidgetItem(str(data['value']))
            self.table.setItem(row, 5, value_item)
    
    def on_double_click(self, index):
        row = index.row()
        col = index.column()
        
        if row < 0 or row >= len(self.constants_data):
            return
            
        data = self.constants_data[row]
        
        if col == 1:
            idc.jumpto(data['ea'])
        elif col == 2:
            if data['refs_in_func']:
                idc.jumpto(data['refs_in_func'][0])
    
    def OnClose(self, form):
        pass

class ConstantsViewerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Shows all constants in the selected function"
    help = PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = ConstantsViewer()
        form.Show(PLUGIN_NAME)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return ConstantsViewerPlugin()