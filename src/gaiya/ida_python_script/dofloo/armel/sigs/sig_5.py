import idc
import idaapi
import idautils
import json

def sig_parser(ea_list):
    def _get_bytes(ea):
        values = []
        for i in range(4):
            values.append((idc.Byte(ea + i)))
        values.reverse()
        values = ''.join('{:02x}'.format(x) for x in values)
        return values

    def _get_ip_str(ins_ea):
        target_ea = ins_ea
        ip = []
        while idc.Byte(target_ea) != 0x0:
            ip.append(chr(idc.Byte(target_ea)))
            target_ea += 1
        print("[>>>>>>] ip:{}".format(ip))
        return "".join(ip)

    print("[>>>>>>] sig_parser is called. {}".format(ea_list))
    ins_0_ea = ea_list[0]
    addr = idc.GetOperandValue(ins_0_ea, 1)
    print("[>>>>>>] addr:{}".format(hex(addr)))
    target_ea = int(_get_bytes(addr), base=16)
    print("[>>>>>>] target_ea:{}".format(hex(target_ea)))
    ip_str = _get_ip_str(target_ea)
    ins_19_ea = ea_list[19]
    delta = idc.GetOperandValue(ins_19_ea, 2)
    ip = "".join([chr(ord(item) - 5) for item in ip_str])
    print("[>>>>>>] delta:{}".format(delta))
    print("[>>>>>>] ip_str:{}".format((ip)))

    ins_41_ea = ea_list[41]
    addr = idc.GetOperandValue(ins_41_ea, 1)
    target_ea = _get_bytes(addr)
    print("[>>>>>>] target_ea:{}".format(target_ea))
    ins_42_ea = ea_list[42]
    offset = idc.GetOperandValue(ins_42_ea, 1)
    print("[>>>>>>] offset:{}".format(hex(offset)))
    target_ea = int(target_ea, base=16) + offset
    print("[>>>>>>] target_ea:{}".format(hex(target_ea)))
    port = _get_bytes(target_ea)
    port = int(port, base=16)
    ins_45_ea = ea_list[45]
    ins_46_ea = ea_list[46]
    delta = idc.GetOperandValue(ins_45_ea, 2) + idc.GetOperandValue(ins_46_ea, 2)
    port = port - delta
    print("[>>>>>>] port:{}".format((port)))

    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_arm_2019_10_28_1",
       "md5": "e45320bdca1a9a230a194b7fd641bf85",
       "date": "2019-10-28_10:07:14",
       "code_sig": "LDR_BL_MOV_STR_SUB_MOV_MOV_MOV_MOV_BL_MOV_STR_B_LDR_LDR_SUB_ADD_ADD_LDRB_SUB_AND_LDR_LDR_SUB_ADD_ADD_STRB_LDR_ADD_STR_LDR_SUB_MOV_BL_MOV_CMP_BCC_SUB_MOV_MOV_BL_LDR_LDR_MOV_MOV_SUB_SUB_MOV_MOV_MOV_BL",
       "code_ea": "0xf2b8",
       "func_sig": "STMFD_ADD_SUB_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL",
       "func_ea": "0xf1ec",
       "parser": sig_parser}

