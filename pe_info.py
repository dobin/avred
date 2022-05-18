
from pe_utils import get_sections, PE



def parse_pe(path):
    pe = PE()
    pe.filename = path
    pe.sections = get_sections(pe)

    if False:
        for section in pe.sections:
            print(f"Section {section.name}  addr: {section.addr}   size: {section.size} ")

    #pe.strings = parse_strings(sample_file, args.extensive, args.length)
    with open(path, "rb") as f:
        pe.data = f.read()
    return pe
