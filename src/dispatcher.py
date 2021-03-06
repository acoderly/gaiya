import yara
import os
import lief
import hashlib

from gaiya.malware_family import MalwareFamily

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gaiya", "sample")
YARA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gaiya", "yara_rule")
YARA_RULES = os.path.join(YARA_DIR, "include.yara")


def get_elf_md5(file_abs_path):
    md5 = None
    md5_hash = hashlib.md5()
    with open(file_abs_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
        md5 = md5_hash.hexdigest()
    return md5


def get_elf_arch(file_abs_path):
    binary = lief.parse(file_abs_path)
    if binary.format != lief.EXE_FORMATS.ELF:
        return None
    arch = {
        lief.ELF.ARCH.i386: "x86",
        lief.ELF.ARCH.x86_64: "x86_64",
        lief.ELF.ARCH.ARM: "armel",
        lief.ELF.ARCH.MIPS: "mips",
    }[binary.header.machine_type]
    return arch


def init_family_dispatch_map():
    def process_yara_include():
        lines = []
        for name in os.listdir(YARA_DIR):
            if name == "include.yara":
                continue
            lines.append(f"include \"./{name}\"\n")
        with open(YARA_RULES, "w+") as f:
            for line in lines:
                f.write(line)

    def wrap_callback(file_abs_path, g_map):
        def callback(data):
            if data is None:
                return yara.CALLBACK_CONTINUE
            rule_name = data["rule"]
            family_dict = g_map.get(rule_name, {})
            meta_data = family_dict.get(file_abs_path, {})
            meta_data["arch"] = get_elf_arch(file_abs_path)
            meta_data["md5"] = get_elf_md5(file_abs_path)
            meta_data["file_name"] = os.path.basename(file_abs_path)
            meta_data["file_path"] = os.path.dirname(file_abs_path)
            family_dict[file_abs_path] = meta_data
            g_map[rule_name] = family_dict
            return yara.CALLBACK_CONTINUE

        return callback

    process_yara_include()
    rules = yara.compile(filepath=YARA_RULES)
    for file in os.listdir(DATA_DIR):
        file_path_abs = os.path.join(DATA_DIR, file)
        if os.path.isdir(file):
            continue
        rules.match(file_path_abs, callback=wrap_callback(file_path_abs, family_dispatch_map),
                    which_callbacks=yara.CALLBACK_MATCHES)


family_dispatch_map = {}
init_family_dispatch_map()

mf = MalwareFamily()
mf.initialize()
ability = mf.get_all_registered_family()
print(f"Gaiya's current ability:{ability}")
print((mf.get_all_registered_family()))
for family_name, data in family_dispatch_map.items():
    if family_name not in ability:
        print(f"Can not process family: {family_name}")
        continue
    # print(family_name, data)
    obj = mf.get(family_name)

    obj.run(data)
