import os
import logging.handlers
import pkgutil
import logging.handlers
import json

# Dismiss PyCharm "No module named ..." stuff.
try:
    import idc
    import idaapi
    import idautils
except ModuleNotFoundError as e:
    pass

try:
    log_path = idc.ARGV[1]
except Exception as e:
    log_path = os.getcwd()

result_path = os.path.join(log_path, "result.txt")


def load_all_sig():
    ret = []
    paths = [os.path.join(os.path.dirname(__file__), "sigs")]
    modules_to_load = []
    for finder, name, _ in pkgutil.iter_modules(paths):
        found_module = finder.find_module(name)
        modules_to_load.append((name, found_module))

    for (name, module) in sorted(modules_to_load, key=lambda x: x[0]):
        try:
            sig = module.load_module(name)
            ret.append(sig)
        except Exception as e:
            pass
    return ret


def create_logger():
    log_file = os.path.join(log_path, "log.txt")
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=10)
    handler.setFormatter(logging.Formatter("%(asctime)s-:%(message)s"))
    logger = logging.getLogger("log")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def get_target_func(sig):
    sig_name = sig["name"]
    func_sig = sig["func_sig"]
    func_ea = sig["func_ea"]
    func_len = len(func_sig.split("_"))
    func_sig = "".join(func_sig.split("_"))
    print("[******] The sig_name:<{}> func_sig:<{}> func_ea:<{}>".format(sig_name, func_sig, func_ea))

    target_func = []
    for func_ea in idautils.Functions():
        flags = idc.GetFunctionFlags(func_ea)
        if flags & idaapi.FUNC_LIB or flags & idaapi.FUNC_THUNK:
            continue
        dism_addr = list(idautils.FuncItems(func_ea))
        for idx in range(len(dism_addr)):
            try:
                dis_str = "".join(map(idc.GetMnem, dism_addr[idx:idx + func_len]))
                if dis_str == func_sig:
                    target_func.append(func_ea)
                    break
            except IndexError:
                break

    return target_func


def get_target_code(sig, target_func):
    # logger.info("[>>>>>>] process {} start".format(file_name))
    sig_name = sig["name"]
    code_sig = sig["code_sig"]
    code_len = len(code_sig.split("_"))
    code_ea = sig["code_ea"]
    code_sig = "".join(code_sig.split("_"))
    print("[******] The sig_name:<{}> code_sig:<{}> code_ea:<{}>".format(sig_name, code_sig, code_ea))
    ret = False
    print("[******] get_target_code param target_func:{}".format(target_func))
    for func_ea in target_func:
        dism_addr = list(idautils.FuncItems(func_ea))
        for idx in range(len(dism_addr)):
            try:
                dism_str = "".join(map(idc.GetMnem, dism_addr[idx:idx + code_len]))
                if dism_str == code_sig:
                    print("[******] get_target_code matched.")
                    parser = sig["parser"]
                    if parser != None:
                        ret, current_file, ip, port = parser(dism_addr[idx:idx + code_len])
                        if ret is not False:
                            result = {
                                "current_file": current_file,
                                "ip": ip,
                                "port": port
                            }
                            with open(result_path, "a") as f:
                                json.dump(result, f)
                                f.write(os.linesep)
                        else:
                            pass
            except IndexError:
                break
    return ret


def parser(sig_lst):
    for obj in sig_lst:
        sig = obj.sig
        target_func = get_target_func(sig)
        logger.debug("[******] c2 target_func:{}".format(target_func))
        for item in target_func:
            logger.debug("[******] c2 target_func_name:{}".format(idc.GetFunctionName(item)))
        ret = get_target_code(sig, target_func)
        if ret is True:
            logger.debug("[******] c2 process success.")
        else:
            logger.debug("[******] c2 process failed.")


sig_lst = load_all_sig()
logger = create_logger()
logger.info("Run")
idaapi.autoWait()

parser(sig_lst)

idc.Exit(0)
