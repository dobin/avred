from reducer_orig import bytes_detection
from reducer_rutd import scanData
from copy import deepcopy
from pe_utils import hide_section, logging
from pe_info import parse_pe
import hexdump
from intervaltree import Interval, IntervalTree

def analyzeFile(filename, scanner, newAlgo=True):
    pe = parse_pe(filename)
    matches = investigate(pe, scanner, newAlgo)

    for match in matches:
        for i in sorted(match):
            size = i.end - i.begin
            print(f"[*] Signature between {i.begin} and {i.end} size {size}: ")
            data = pe.data[i.begin:i.end]
            print(hexdump.hexdump(data, result='return'))

    return pe, matches


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


def investigate(pe, scanner, newAlgo):
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
        
        if newAlgo:
            match = scanData(scanner, pe.data, section.addr, section.addr+section.size)
        else:
            match = bytes_detection(pe.data, scanner, section.addr, section.addr+section.size)
        matches.append(match)

    return matches
