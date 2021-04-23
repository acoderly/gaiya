import os
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf import segments


def check_elf_by_segment(file_name):
    def _get_file_stringtable(ELFFile_Obj):
        return None

    file_obj = open(file_name, "rb")
    file_size = os.path.getsize(file_name)
    if file_size <= 0:
        return True
    orgi_get_file_stringtable = getattr(ELFFile, "_get_file_stringtable")
    setattr(ELFFile, "_get_file_stringtable", _get_file_stringtable)
    elf_file = ELFFile(file_obj)
    ph_offset_in_file = elf_file.header["e_phoff"]
    if ph_offset_in_file > file_size:
        return True
    for n in range(0, ELFFile.num_segments(elf_file)):
        segment_header = ELFFile._get_segment_header(elf_file, n)
        if segment_header['p_type'] == "PT_LOAD":
            loadable_segment = segments.Segment(segment_header, elf_file.stream)
            segment_start = loadable_segment['p_offset']
            segment_size = loadable_segment['p_filesz']
            if segment_start + segment_size > file_size:
                is_broken = True
                break
    else:
        is_broken = False

    return is_broken


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, )
    parser.add_argument("--sample_dir", help="Sample dir", required=True)
    args = parser.parse_args()
    sample_dir = args.sample_dir
    for file in os.listdir(sample_dir):
        file_path = "{}/{}".format(sample_dir, file)
        ret = check_elf_by_segment(file_path)
        if ret:
            print("File:{} is broken".format(file_path))
