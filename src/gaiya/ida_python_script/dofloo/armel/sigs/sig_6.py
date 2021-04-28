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

    # get port
    ins_1_ea = ea_list[1]
    addr = idc.GetOperandValue(ins_1_ea, 1)
    port = int(_get_bytes(addr), base=16)
    print("[>>>>>>] port:{}".format((port)))

    # get ip
    ins_18_ea = ea_list[18]
    addr = idc.GetOperandValue(ins_18_ea, 1)
    target_ea = int(_get_bytes(addr), base=16)
    ip_str = _get_ip_str(target_ea)
    if ip_str[0] == '\xe4':
        return False, None, None, None
    ins_22_ea = ea_list[22]
    delta = idc.GetOperandValue(ins_22_ea, 2)
    ip = "".join([chr(ord(x) - delta) for x in ip_str])
    print("[>>>>>>] ip:{}".format((ip)))
    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_arm_2019_10_28_2",
       "md5": "e45320bdca1a9a230a194b7fd641bf85",
       "date": "2019-10-28_10:35:28",
       "code_sig": "BL_LDR_BL_MOV_STRH_MOV_STRH_MOV_STR_SUB_MOV_MOV_MOV_MOV_BL_MOV_STR_B_LDR_LDR_ADD_LDRB_SUB_AND_LDR_LDR_SUB_ADD_ADD_STRB_LDR_ADD_STR_LDR_LDR_BL_MOV_CMP_BCC_SUB_MOV_BL",
       "code_ea": "0xf988",
       "func_sig": "STMFD_ADD_SUB_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL",
       "func_ea": "0xf8d8",
       "parser": sig_parser}
