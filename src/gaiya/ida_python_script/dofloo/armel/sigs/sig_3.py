import idc
import idaapi
import idautils
import json

# code_sig_raw
# 7A CD 00 EB                                                   0  BL      bzero
# 4C 32 9F E5                                                   1  LDR     R3, =m_OnlineInfo
# 04 31 93 E5                                                   2  LDR     R3, [R3,#(m_OnlineInfo.Port - 0xC1FC4)]
# 03 38 A0 E1                                                   3  MOV     R3, R3,LSL#16
# 23 38 A0 E1                                                   4  MOV     R3, R3,LSR#16
# 03 00 A0 E1                                                   5  MOV     R0, R3
# 99 E0 00 EB                                                   6  BL      ntohs
# 00 30 A0 E1                                                   7  MOV     R3, R0
# B2 33 4B E1                                                   8  STRH    R3, [R11,#dest_addr.sin_port]
# 02 30 A0 E3                                                   9  MOV     R3, #2
# B4 33 4B E1                                                  10   STRH    R3, [R11,#dest_addr]
# 28 02 9F E5                                                  11   LDR     R0, =m_OnlineInfo.Ip ; szTarget
# C3 FE FF EB                                                  12   BL      _Z15AnalysisAddressPc ; AnalysisAddress(char *)
# 00 30 A0 E1                                                  13   MOV     R3, R0
# 30 30 0B E5                                                  14   STR     R3, [R11,#dest_addr.sin_addr]
# 01 30 A0 E3                                                  15   MOV     R3, #1
# 3C 30 0B E5                                                  16   STR     R3, [R11,#ul]
# 3C 30 4B E2                                                  17   SUB     R3, R11, #-ul
# 24 00 1B E5                                                  18   LDR     R0, [R11,#sockfd]
# 15 1B A0 E3 21 10 81 E2                                      19   MOV     R1, #0x5421
# 03 20 A0 E1                                                  20   MOV     R2, R3
# E3 D6 00 EB                                                  21   BL      ioctl


def sig_parser(ea_list):
    def _get_bytes(ea):
        values = []
        for i in range(4):
            values.append((idc.Byte(ea + i)))
        values.reverse()
        values = ''.join('{:02x}'.format(x) for x in values)
        return values

    print("[>>>>>>] sig_parser is called. {}".format(ea_list))
    # get port
    ins_1_ea = ea_list[1]
    addr = idc.GetOperandValue(ins_1_ea, 1)
    target_ea = _get_bytes(addr)
    print("[>>>>>>] target_ea:{}".format(target_ea))
    ins_2_ea = ea_list[2]
    offset = idc.GetOperandValue(ins_2_ea, 1)
    print("[>>>>>>] offset:{}".format(hex(offset)))
    target_ea = int(target_ea, base=16) + offset
    print("[>>>>>>] target_ea:{}".format(hex(target_ea)))
    port = _get_bytes(target_ea)
    port = int(port, base=16)
    print("[>>>>>>] ip:{}".format((port)))
    # get ip
    ins_11_ea = ea_list[11]
    addr = idc.GetOperandValue(ins_11_ea, 1)
    print("[>>>>>>] addr:{}".format(addr))
    target_ea = _get_bytes(addr)
    print("[>>>>>>] target_ea:{}".format(target_ea))
    ip = []
    target_ea = int(target_ea, base=16)
    while idc.Byte(target_ea) != 0x0:
        ip.append(chr(idc.Byte(target_ea)))
        target_ea += 1
    ip = "".join(ip)
    print("[>>>>>>] ip:{}".format(ip))
    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_arm_2019_10_24_1",
       "md5": "fd18764f714fc3778e5fe6907f7b7697",
       "date": "2019-10-24_11:26:53",
       "code_sig": "BL_LDR_LDR_MOV_MOV_MOV_BL_MOV_STRH_MOV_STRH_LDR_BL_MOV_STR_MOV_STR_SUB_LDR_MOV_MOV_BL",
       "code_ea": "0xb674",
       "func_sig": "STMFD_ADD_SUB_MOV_STR_LDR_SUB_LDMIA_STMIA_MOV_STR_LDR_SUB_LDMIA_STMIA_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL",
       "func_ea": "0xb5bc",
       "parser": sig_parser}
