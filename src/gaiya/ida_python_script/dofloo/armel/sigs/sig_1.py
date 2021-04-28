import idc
import idaapi
import idautils

# # Begin dofloo_20191023_1
# func_sig_raw
# .text:0000F0CC 30 48 2D E9                                                  0   STMFD   SP!, {R4,R5,R11,LR}
# .text:0000F0D0 0C B0 8D E2                                                  1   ADD     R11, SP, #0xC
# .text:0000F0D4 D8 D0 4D E2                                                  2   SUB     SP, SP, #0xD8
# .text:0000F0D8 00 30 A0 E3                                                  3   MOV     R3, #0
# .text:0000F0DC 18 30 0B E5                                                  4   STR     R3, [R11,#var_18]
# .text:0000F0E0 05 30 A0 E3                                                  5   MOV     R3, #5
# .text:0000F0E4 4C 30 0B E5                                                  6   STR     R3, [R11,#var_4C]
# .text:0000F0E8 00 30 A0 E3                                                  7   MOV     R3, #0
# .text:0000F0EC 48 30 0B E5                                                  8   STR     R3, [R11,#var_48]
# .text:0000F0F0 01 30 A0 E3                                                  9   MOV     R3, #1
# .text:0000F0F4 50 30 0B E5                                                 10   STR     R3, [R11,#var_50]
# .text:0000F0F8 01 30 A0 E3                                                 11   MOV     R3, #1
# .text:0000F0FC 58 30 0B E5                                                 12   STR     R3, [R11,#var_58]
# .text:0000F100 00 30 A0 E3                               a                  13   MOV     R3, #0
# .text:0000F104 54 30 0B E5                                                 14    STR     R3, [R11,#var_54]
# .text:0000F108 01 30 A0 E3                                                 15    MOV     R3, #1
# .text:0000F10C 1C 30 0B E5                                                 16    STR     R3, [R11,#var_1C]
# .text:0000F110 01 30 A0 E3                                                 17    MOV     R3, #1
# .text:0000F114 20 30 0B E5                                                 18    STR     R3, [R11,#var_20]
# .text:0000F118 05 30 A0 E3                                                 19    MOV     R3, #5
# .text:0000F11C 24 30 0B E5                                                 20    STR     R3, [R11,#var_24]
# .text:0000F120 03 30 A0 E3                                                 21    MOV     R3, #3
# .text:0000F124 28 30 0B E5                                                 22    STR     R3, [R11,#var_28]
# .text:0000F128 08 30 A0 E3                                                 23    MOV     R3, #8
# .text:0000F12C 5C 30 0B E5                                                 24    STR     R3, [R11,#var_5C]
# .text:0000F130 02 00 A0 E3                                                 25    MOV     R0, #2
# .text:0000F134 01 10 A0 E3                                                 26    MOV     R1, #1
# .text:0000F138 00 20 A0 E3                                                 27    MOV     R2, #0
# .text:0000F13C 43 EB 00 EB                                                 28    BL      socket


# code_sig_raw
# .text:0000F17C 04 DB 00 EB                                                  0   BL      bzero
# .text:0000F180 60 32 9F E5                                                  1   LDR     R3, =m_OnlineInfo
# .text:0000F184 08 30 93 E5                                                  2   LDR     R3, [R3,#(dword_B0F04 - 0xB0EFC)]
# .text:0000F188 03 38 A0 E1                                                  3   MOV     R3, R3,LSL#16
# .text:0000F18C 23 38 A0 E1                                                  4   MOV     R3, R3,LSR#16
# .text:0000F190 4E 3C 83 E2                                                  5   ADD     R3, R3, #0x4E00
# .text:0000F194 20 30 83 E2                                                  6   ADD     R3, R3, #0x20
# .text:0000F198 03 38 A0 E1                                                  7   MOV     R3, R3,LSL#16
# .text:0000F19C 23 38 A0 E1                                                  8   MOV     R3, R3,LSR#16
# .text:0000F1A0 03 00 A0 E1                                                  9   MOV     R0, R3
# .text:0000F1A4 EA EC 00 EB                                                  10   BL      ntohs
# .text:0000F1A8 00 30 A0 E1                                                  11  MOV     R3, R0
# .text:0000F1AC BA 33 4B E1                                                  12   STRH    R3, [R11,#var_3A]
# .text:0000F1B0 02 30 A0 E3                                                  13   MOV     R3, #2
# .text:0000F1B4 BC 33 4B E1                                                  14   STRH    R3, [R11,#var_3C]
# .text:0000F1B8 28 32 9F E5                                                  15   LDR     R3, =m_OnlineInfo
# .text:0000F1BC 04 30 93 E5                                                  16   LDR     R3, [R3,#(dword_B0F00 - 0xB0EFC)]
# .text:0000F1C0 4E 3C 83 E2                                                  17   ADD     R3, R3, #0x4E00
# .text:0000F1C4 20 30 83 E2                                                  18   ADD     R3, R3, #0x20
# .text:0000F1C8 38 30 0B E5                                                  19   STR     R3, [R11,#var_38]
# .text:0000F1CC 01 30 A0 E3                                                  20   MOV     R3, #1
# .text:0000F1D0 44 30 0B E5                                                  21   STR     R3, [R11,#var_44]
# .text:0000F1D4 44 30 4B E2                                                  22   SUB     R3, R11, #-var_44
# .text:0000F1D8 18 00 1B E5                                                  23   LDR     R0, [R11,#var_18]
# .text:0000F1DC 08 12 9F E5                                                  24   LDR     R1, =0x5421
# .text:0000F1E0 03 20 A0 E1                                                  25   MOV     R2, R3
# .text:0000F1E4 21 E6 00 EB                                                  26   BL      ioctl

sig_1_code_sig = "BL_LDR_LDR_MOV_MOV_ADD_ADD_MOV_MOV_MOV_BL_MOV_STRH_MOV_STRH_LDR_LDR_ADD_ADD_STR_MOV_STR_SUB_LDR_LDR_MOV_BL"
sig_1_func_sig = "STMFD_ADD_SUB_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL"


def sig_1_parser(ea_list):
    def _get_bytes(ea):
        values = []
        for i in range(4):
            values.append((idc.Byte(ea + i)))
        values.reverse()
        values = ''.join('{:02x}'.format(x) for x in values)
        return values

    def _u32_le_2_ip(int_ip):
        ip = []
        ip.append(str(int_ip & 0xff))
        ip.append(str((int_ip & 0xff00) >> 8))
        ip.append(str((int_ip & 0xff0000) >> 16))
        ip.append(str((int_ip & 0xff000000) >> 24))
        return ".".join(ip)

    print("[>>>>>>] sig_1_parse is called.{}".format(len(ea_list)))
    ins_1_ea = ea_list[1]
    ins_2_ea = ea_list[2]
    print("[>>>>>>] ins_1_ea:{}".format(hex(ins_1_ea)))

    # get port ea
    target_ea = []
    addr = idc.GetOperandValue(ins_1_ea, 1)
    target_ea = _get_bytes(addr)
    print("[>>>>>>] {}".format(target_ea))
    # get port ea offset
    print("[>>>>>>] ins_2_ea:{}".format(hex(ins_2_ea)))
    offset = idc.GetOperandValue(ins_2_ea, 1)
    port_ea = int(target_ea, base=16) + offset
    port = _get_bytes(port_ea)
    # get port delta
    ins_5_ea = ea_list[5]
    ins_6_ea = ea_list[6]
    delta = idc.GetOperandValue(ins_5_ea, 2) + idc.GetOperandValue(ins_6_ea, 2)
    print("[>>>>>>] port delta:{}".format(delta))
    port = int(port, base=16) + delta
    print("[>>>>>>] {}".format(port))

    # get ip ea
    ins_15_ea = ea_list[15]
    ins_16_ea = ea_list[16]
    target_ea = []
    addr = idc.GetOperandValue(ins_15_ea, 1)
    target_ea = _get_bytes(addr)
    print("[>>>>>>] {}".format(target_ea))
    # get ip ea offset
    print("[>>>>>>] ins_16_ea:{}".format(hex(ins_16_ea)))
    offset = idc.GetOperandValue(ins_16_ea, 1)
    ip_ea = int(target_ea, base=16) + offset
    ip = _get_bytes(ip_ea)
    # get ip delta
    ins_17_ea = ea_list[17]
    ins_18_ea = ea_list[18]
    delta = idc.GetOperandValue(ins_17_ea, 2) + idc.GetOperandValue(ins_18_ea, 2)
    ip = int(ip, base=16) + delta
    ip = _u32_le_2_ip(ip)
    print("[>>>>>>] {}".format(ip))
    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_20191023_1",
       "md5": "20670144eddb6f3263abb2843e9787c9",
       "date": "2019-10-23_10:21",
       "code_sig": sig_1_code_sig,
       "code_ea": "0804F311",
       "func_sig": sig_1_func_sig,
       "func_ea": "0804F26F",
       "parser": sig_1_parser
       }
