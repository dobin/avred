import logging
import hexdump
from intervaltree import Interval, IntervalTree

from reducer_orig import bytes_detection
from reducer_rutd import scanData
from copy import deepcopy
from pe_utils import *


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


def investigate(pe, scanner, newAlgo=True, isolate=False):
    detected = scanner.scan(pe.data)
    if not detected:
        logging.error(f"{pe.filename} is not detected by {scanner.scanner_name}")
        return []

    #hide_section(pe, "Ressources")
    #hide_section(pe, "VersionInfo")

    # identify which sections get detected
    detected_sections = []
    if isolate:
        detected_sections = findDetectedSectionsIsolate(pe, scanner)
    else:
        detected_sections = findDetectedSections(pe, scanner)

    if len(detected_sections) == 0:
        print("No matches?!")
        return []

    print(f"{len(detected_sections)} section(s) trigger the antivirus")
    for section in detected_sections:
        print(f"  section: {section.name}")

    # analyze each detected section
    matches = []
    for section in detected_sections:
        logging.info(f"Launching bytes analysis on section {section.name}")
        if newAlgo:
            match = scanData(scanner, pe.data, section.addr, section.addr+section.size)
        else:
            match = bytes_detection(pe.data, scanner, section.addr, section.addr+section.size)
        matches.append(match)

    return matches


def findDetectedSectionsIsolate(pe, scanner):
    detected_sections = []

    for section in pe.sections:
        new_pe = deepcopy(pe)

        hide_all_sections_except(new_pe, section.name)
        status = scanner.scan(new_pe.data)

        if status:
            detected_sections += [section]

    return detected_sections


def findDetectedSections(pe, scanner):
    detected_sections = []

    for section in pe.sections:
        new_pe = deepcopy(pe)
        hide_section(new_pe, section.name)

        status = scanner.scan(new_pe.data)
        if not status:
            detected_sections += [section]

    return detected_sections
