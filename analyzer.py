from pe_utils import *
from find import bytes_detection



"""
attempts to locate the part in a PE file that causes the antivirus detection
"""
def findDetectedSections(pe, scanner):
    detected_sections = []

    for section in pe.sections:
        new_pe = deepcopy(pe)
        hide_section(new_pe, section.name)

        status = scanner.scan(new_pe.data)
        section.detected =  status

        if not status:
            logging.info(f"Section {section.name} triggers the antivirus")
            detected_sections += [section]

    sectionCount = len(detected_sections)
    print(f"{sectionCount} section(s) trigger the antivirus")
    for section in detected_sections:
        print(f"  section: {section.name}")

    return detected_sections


def investigate(pe, scanner):
    detected = scanner.scan(pe.data)
    if not detected:
        logging.error(f"{pe.filename} is not detected by {scanner.scanner_name}")
        return

    # identify which sections get detected
    detected_sections = findDetectedSections(pe, scanner)

    # analyze each section
    matches = []
    for section in detected_sections:
        logging.info(f"Launching bytes analysis on section {section.name}")
        match = bytes_detection(pe.data, scanner, section.addr, section.addr+section.size)
        matches.append(match)

    return matches


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

