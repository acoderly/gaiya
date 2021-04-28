import idc
import idaapi
import idautils
import json
# dofloo_20191023_2
# func_sig_raw
# .text:0000F3F0 30 48 2D E9                                                     STMFD   SP!, {R4,R5,R11,LR}
# .text:0000F3F4 0C B0 8D E2                                                     ADD     R11, SP, #0xC
# .text:0000F3F8 D8 D0 4D E2                                                     SUB     SP, SP, #0xD8
# .text:0000F3FC 00 30 A0 E3                                                     MOV     R3, #0
# .text:0000F400 18 30 0B E5                                                     STR     R3, [R11,#var_18]
# .text:0000F404 05 30 A0 E3                                                     MOV     R3, #5
# .text:0000F408 4C 30 0B E5                                                     STR     R3, [R11,#var_4C]
# .text:0000F40C 00 30 A0 E3                                                     MOV     R3, #0
# .text:0000F410 48 30 0B E5                                                     STR     R3, [R11,#var_48]
# .text:0000F414 01 30 A0 E3                                                     MOV     R3, #1
# .text:0000F418 50 30 0B E5                                                     STR     R3, [R11,#var_50]
# .text:0000F41C 01 30 A0 E3                                                     MOV     R3, #1
# .text:0000F420 58 30 0B E5                                                     STR     R3, [R11,#var_58]
# .text:0000F424 00 30 A0 E3                                                     MOV     R3, #0
# .text:0000F428 54 30 0B E5                                                     STR     R3, [R11,#var_54]
# .text:0000F42C 01 30 A0 E3                                                     MOV     R3, #1
# .text:0000F430 1C 30 0B E5                                                     STR     R3, [R11,#var_1C]
# .text:0000F434 01 30 A0 E3                                                     MOV     R3, #1
# .text:0000F438 20 30 0B E5                                                     STR     R3, [R11,#var_20]
# .text:0000F43C 05 30 A0 E3                                                     MOV     R3, #5
# .text:0000F440 24 30 0B E5                                                     STR     R3, [R11,#var_24]
# .text:0000F444 03 30 A0 E3                                                     MOV     R3, #3
# .text:0000F448 28 30 0B E5                                                     STR     R3, [R11,#var_28]
# .text:0000F44C 08 30 A0 E3                                                     MOV     R3, #8
# .text:0000F450 5C 30 0B E5                                                     STR     R3, [R11,#var_5C]
# .text:0000F454 02 00 A0 E3                                                     MOV     R0, #2
# .text:0000F458 01 10 A0 E3                                                     MOV     R1, #1
# .text:0000F45C 00 20 A0 E3                                                     MOV     R2, #0
# .text:0000F460 7A EA 00 EB                                                     BL      socket

# code_sig_raw
# .text:0000F4A0 3B DA 00 EB                                                   0  BL      bzero
# .text:0000F4A4 34 02 9F E5                                                   1  LDR     R0, =0xBBD0
# .text:0000F4A8 29 EC 00 EB                                                   2  BL      ntohs
# .text:0000F4AC 00 30 A0 E1                                                   3  MOV     R3, R0
# .text:0000F4B0 BA 33 4B E1                                                   4  STRH    R3, [R11,#var_3A]
# .text:0000F4B4 02 30 A0 E3                                                   5  MOV     R3, #2
# .text:0000F4B8 BC 33 4B E1                                                   6  STRH    R3, [R11,#var_3C]
# .text:0000F4BC 20 32 9F E5                                                   7  LDR     R3, =0xC7953CB7
# .text:0000F4C0 38 30 0B E5                                                   8  STR     R3, [R11,#var_38]
# .text:0000F4C4 01 30 A0 E3                                                   9  MOV     R3, #1
# .text:0000F4C8 44 30 0B E5                                                  10   STR     R3, [R11,#var_44]
# .text:0000F4CC 44 30 4B E2                                                  11   SUB     R3, R11, #-var_44
# .text:0000F4D0 18 00 1B E5                                                  12   LDR     R0, [R11,#var_18]
# .text:0000F4D4 0C 12 9F E5                                                  13   LDR     R1, =0x5421
# .text:0000F4D8 03 20 A0 E1                                                  14   MOV     R2, R3
# .text:0000F4DC 63 E5 00 EB                                                  15   BL      ioctl

sig_2_func_sig = "STMFD_ADD_SUB_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_STR_MOV_MOV_MOV_BL"
sig_2_code_sig = "BL_LDR_BL_MOV_STRH_MOV_STRH_LDR_STR_MOV_STR_SUB_LDR_LDR_MOV_BL"


def sig_2_parser(ea_list):
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

    print("[>>>>>>] sig_2_parser is called.")
    # get port ea
    ins_1_ea = ea_list[1]
    print("ins_1_ea:{}".format(hex(ins_1_ea)))
    target_ea = idc.GetOperandValue(ins_1_ea, 1)
    port = _get_bytes(target_ea)
    port = int(port, base=16)
    # get ip
    ins_7_ea = ea_list[7]
    print("ins_7_ea:{}".format(hex(ins_7_ea)))
    ip = idc.GetOperandValue(ins_7_ea, 1)
    target_ea = idc.GetOperandValue(ins_7_ea, 1)
    ip = _get_bytes(target_ea)
    ip = _u32_le_2_ip(int(ip, base=16))
    print("[>>>>>>] ip:{}".format((ip)))
    print("[>>>>>>] port:{}".format((port)))

    current_file = idaapi.get_root_filename()
    return True, current_file, ip, str(port)


sig = {"name": "dofloo_20191023_2",
       "md5": "20670144eddb6f3263abb2843e9787c9",
       "date": "2019-10-23_14:58",
       "code_sig": sig_2_code_sig,
       "code_ea": "0000F4A0",
       "func_sig": sig_2_func_sig,
       "func_ea": "0000F3F0",
       "parser": sig_2_parser}