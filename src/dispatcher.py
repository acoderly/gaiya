import os
from gaiya.malware_family import MalwareFamily
import lief

YARA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gaiya/yara_rule")
YARA_RULES = os.path.join(YARA_DIR, "include.yara")


def process_yara_include():
    lines = []
    for name in os.listdir(YARA_DIR):
        if name == "include.yara":
            continue
        lines.append(f"include \"./{name}\"\n")
    with open(YARA_RULES, "w+") as f:
        for line in lines:
            f.write(line)


process_yara_include()

mf = MalwareFamily()
mf.initialize()
obj = mf.get("dofloo")
obj.run()
