import idc
import idaapi
import idautils
import json


# func_sig_raw
# 10 48 2D E9                                                     STMFD   SP!, {R4,R11,LR}
# 08 B0 8D E2                                                     ADD     R11, SP, #8
# E4 D0 4D E2                                                     SUB     SP, SP, #0xE4
# 00 30 A0 E3                                                     MOV     R3, #0
# 2C 30 0B E5                                                     STR     R3, [R11,#sockfd]
# 5C 33 9F E5                                                     LDR     R3, =_ZZ17ServerConnectCliAvE5C.372 ; ServerConnectCliA(void)::C.372
# 4C 20 4B E2                                                     SUB     R2, R11, #-timeo
# 03 00 93 E8                                                     LDMIA   R3, {R0,R1} ; ServerConnectCliA(void)::C.372
# 03 00 82 E8                                                     STMIA   R2, {R0,R1}
# 01 30 A0 E3                                                     MOV     R3, #1
# 50 30 0B E5                                                     STR     R3, [R11,#on]
# 48 33 9F E5                                                     LDR     R3, =_ZZ17ServerConnectCliAvE5C.373 ; ServerConnectCliA(void)::C.373
# 58 20 4B E2                                                     SUB     R2, R11, #-so_linger
# 03 00 93 E8                                                     LDMIA   R3, {R0,R1} ; ServerConnectCliA(void)::C.373
# 03 00 82 E8                                                     STMIA   R2, {R0,R1}
# 01 30 A0 E3                                                     MOV     R3, #1
# 24 30 0B E5                                                     STR     R3, [R11,#keepalive]
# 01 30 A0 E3                                                     MOV     R3, #1
# 20 30 0B E5                                                     STR     R3, [R11,#keepidle]
# 05 30 A0 E3                                                     MOV     R3, #5
# 1C 30 0B E5                                                     STR     R3, [R11,#keepinterval]
# 03 30 A0 E3                                                     MOV     R3, #3
# 18 30 0B E5                                                     STR     R3, [R11,#keepcount]
# 08 30 A0 E3                                                     MOV     R3, #8
# 5C 30 0B E5                                                     STR     R3, [R11,#len]
# 02 00 A0 E3                                                     MOV     R0, #2
# 01 10 A0 E3                                                     MOV     R1, #1
# 00 20 A0 E3                                                     MOV     R2, #0
# 48 DE 00 EB                                                     BL      socket

# code_sig_raw
# D0 32 9F E5                                                    0 LDR     R3, =JBrOK1
# 00 30 93 E5                                                    1 LDR     R3, [R3] ; "aaa.tfd"
# 03 00 A0 E1                                                    2 MOV     R0, R3
# D6 CA 00 EB                                                    3 BL      strlen
# 00 40 A0 E1                                                    4 MOV     R4, R0
# C0 32 9F E5                                                    5 LDR     R3, =GBjzk2
# 00 30 93 E5                                                    6 LDR     R3, [R3] ; "dos.net"
# 03 00 A0 E1                                                    7 MOV     R0, R3
# D1 CA 00 EB                                                    8 BL      strlen
# 00 30 A0 E1                                                     MOV     R3, R0
# 03 30 84 E0                                                     ADD     R3, R4, R3
# 01 30 83 E2                                                     ADD     R3, R3, #1
# 03 00 A0 E1                                                     MOV     R0, R3 ; unsigned int
# B4 4B 00 EB                                                     BL      _Znaj ; operator new[](uint)
# 00 30 A0 E1                                                     MOV     R3, R0
# 03 20 A0 E1                                                     MOV     R2, R3
# 98 32 9F E5                                                     LDR     R3, =IJTET3
# 00 20 83 E5                                                     STR     R2, [R3]
# 90 32 9F E5                                                     LDR     R3, =IJTET3
# 00 20 93 E5                                                     LDR     R2, [R3]
# 80 32 9F E5                                                     LDR     R3, =JBrOK1
# 00 30 93 E5                                                     LDR     R3, [R3] ; "aaa.tfd"
# 02 00 A0 E1                                                     MOV     R0, R2
# 03 10 A0 E1                                                     MOV     R1, R3
# 3C CA 00 EB                                                     BL      strcpy
# 74 32 9F E5                                                     LDR     R3, =IJTET3
# 00 20 93 E5                                                     LDR     R2, [R3]
# 68 32 9F E5                                                     LDR     R3, =GBjzk2
# 00 30 93 E5                                                     LDR     R3, [R3] ; "dos.net"
# 02 00 A0 E1                                                     MOV     R0, R2
# 03 10 A0 E1                                                     MOV     R1, R3
# D8 C9 00 EB                                                     BL      strcat
# 3C 30 4B E2                                                     SUB     R3, R11, #-dest_addr
# 03 00 A0 E1                                                     MOV     R0, R3
# 10 10 A0 E3                                                     MOV     R1, #0x10
# 3F CE 00 EB                                                     BL      bzero
# 7E 0E A0 E3                                                   -2  MOV     R0, #0x7E0
# 62 E1 00 EB                                                   -1  BL      ntohs

def sig_parser(ea_list):
    def _get_bytes(ea):
        values = []
        for i in range(4):
            values.append((idc.Byte(ea + i)))
        values.reverse()
        values = ''.join('{:02x}'.format(x) for x in values)
        return values

    def _get_ip_part(ins_ea):
        addr = idc.GetOperandValue(ins_ea, 1)
        print("[>>>>>>] addr:{}".format(hex(addr)))
        target_ea = int(_get_bytes(addr), base=16)
        print("[>>>>>>] target_ea:{}".format(hex(target_ea)))
        target_ea = int(_get_bytes(target_ea), base=16)
        print("[>>>>>>] target_ea:{}".format(hex(target_ea)))
        ip = []
        while idc.Byte(target_ea) != 0x0:
            ip.append(chr(idc.Byte(target_ea)))
            target_ea += 1
        print("[>>>>>>] ip:{}".format(ip))
        return "".join(ip)

    print("[>>>>>>] sig_parser is called. {}".format(ea_list))
    # get port
    ins_port_ea = ea_list[-2]
    port = idc.GetOperandValue(ins_port_ea, 1)
    print("[>>>>>>] addr:{}".format(port))
    # get ip
    ins_0_ea = ea_list[0]
    ip_part1 = _get_ip_part(ins_0_ea)
    print("[>>>>>>] ip_part1:{}".format(ip_part1))
    ins_5_ea = ea_list[5]
    ip_part2 = _get_ip_part(ins_5_ea)
    print("[>>>>>>] ip_part2:{}".format(ip_part2))

    ip = ip_part1 + ip_part2
    print("[>>>>>>] ip:{}".format(ip))
    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_arm_2019_10_24_2",
       "md5": "fd18764f714fc3778e5fe6907f7b7697_case2",
       "date": "2019-10-24_14:58:47",
       "code_sig": "LDR_LDR_MOV_BL_MOV_LDR_LDR_MOV_BL_MOV_ADD_ADD_MOV_BL_MOV_MOV_LDR_STR_LDR_LDR_LDR_LDR_MOV_MOV_BL_LDR_LDR_LDR_LDR_MOV_MOV_BL_SUB_MOV_MOV_BL_MOV_BL",
       "code_ea": "0xb2d4",
       "func_sig": "STMFD_ADD_SUB_MOV_STR_LDR_SUB_LDMIA_STMIA_MOV_STR_LDR_SUB_LDMIA_STMIA_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL",
       "func_ea": "0xb228",
       "parser": sig_parser}
