import idaapi
import idc
import idautils
import ida_struct
import re
import struct

PLUGIN_NAME = "Arg Fixer"
HOTKEY = "Ctrl+Shift+U"

JUNK_VAR_THRESHOLD = -0x10000
JUNK_ARG_THRESHOLD = 0x10000    

def get_max_stack_offset(func):
    max_offset = 0
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if not idc.is_code(idc.get_full_flags(head)):
            continue
        for i in range(2):
            op_type = idc.get_operand_type(head, i)
            if op_type in (idc.o_displ, idc.o_phrase):
                operand = idc.print_operand(head, i)
                m = re.search(r'\[(?:rbp|rsp)[\+\-]([0-9A-Fa-f]+)h?\]', operand)
                if m:
                    offset = int(m.group(1), 16)
                    if offset > max_offset:
                        max_offset = offset
    return max_offset

def remove_junk_vars_from_frame(func):
    frame = idaapi.get_frame(func)
    if not frame:
        print("[arg fixer] No frame found for function")
        return

    members_to_remove = []
    for i in range(frame.memqty):
        member = frame.get_member(i)
        name = idaapi.get_member_name(member.id)
        if not name:
            continue
        if name.startswith("arg_") and member.soff > JUNK_ARG_THRESHOLD:
            members_to_remove.append(i)
        elif name.startswith("var_") and member.soff < JUNK_VAR_THRESHOLD:
            members_to_remove.append(i)

    members_to_remove.sort(reverse=True, key=lambda idx: frame.get_member(idx).soff)

    for idx in members_to_remove:
        member = frame.get_member(idx)
        name = idaapi.get_member_name(member.id)
        print(f"[arg fixer] Attempting to remove junk var: {name}")
        if not ida_struct.del_struc_member(frame, member.soff):
            print(f"[arg fixer] Failed to delete member {name}, renaming and zeroing instead")
            ida_struct.set_member_name(frame, member.soff, "")
            ida_bytes.patch_byte(member.soff, 0)

    idaapi.update_func(func)

def remove_junk_from_current_function():
    start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
    end = idc.get_func_attr(idc.here(), idc.FUNCATTR_END)
    if start == idc.BADADDR or end == idc.BADADDR:
        print("[arg fixer] Failed to get function boundaries.")
        return

    func = idaapi.get_func(start)
    if not func:
        print("[arg fixer] Failed to get function object")
        return

    max_offset = get_max_stack_offset(func)
    new_frame_size = (max_offset + 0x10 + 0xF) & ~0xF
    print(f"[arg fixer] Calculated new frame size: 0x{new_frame_size:X}")

    ea = start
    while ea < end:
        mnem = idc.print_insn_mnem(ea)
        if mnem == "lea":
            disasm = idc.generate_disasm_line(ea, 0)
            m = re.search(r'\[rsp\+([0-9A-Fa-f]+)h\+arg_([0-9A-Fa-f]+)\]', disasm)
            if m:
                offset1 = int(m.group(1), 16)
                offset2 = int(m.group(2), 16)
                total_offset = offset1 + offset2
                if offset2 > 0x10000:
                    reg = idc.print_operand(ea, 0)
                    new_disp = "rsp+{:X}h".format(total_offset)
                    new_asm = "lea {}, [{}]".format(reg, new_disp)
                    print(f"[arg fixer] Patching {ea:X}: {disasm} -> {new_asm}")

                    insn = idaapi.insn_t()
                    length = idaapi.decode_insn(insn, ea)
                    if length == 0:
                        print(f"[arg fixer] Failed to decode instruction at {ea:X}")
                        ea = idc.next_head(ea, end)
                        continue

                    op = insn.ops[1]
                    reg_name = idaapi.get_reg_name(op.reg, getattr(op, "size", 8))
                    if reg_name and reg_name.lower() == "rsp":
                        disp_off = op.offb
                        if disp_off != 0 and disp_off < length:
                            disp_bytes = struct.pack("<I", total_offset)
                            idaapi.patch_bytes(ea + disp_off, disp_bytes)
                            print(f"[arg fixer] Patched displacement bytes at {ea + disp_off:X}")
                        else:
                            print(f"[arg fixer] Could not find displacement offset to patch at {ea:X}")
                    else:
                        print(f"[arg fixer] Operand base register is not rsp at {ea:X}")

        ea = idc.next_head(ea, end)

    current_size = idaapi.get_frame_size(func)
    print(f"[arg fixer] Current stack frame size: 0x{current_size:X}")

    if current_size > new_frame_size:
        print(f"[arg fixer] Resizing frame to 0x{new_frame_size:X}")
        idaapi.set_frame_size(func, new_frame_size, True, True)
        idaapi.update_func(func)
    else:
        print("[arg fixer] Frame size is already smaller than calculated size")

    remove_junk_vars_from_frame(func)

class ArgFixer(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = HOTKEY

    def init(self):
        print("[arg fixer] initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        remove_junk_from_current_function()

    def term(self):
        print("[arg fixer] terminated.")

def PLUGIN_ENTRY():
    return ArgFixer()
