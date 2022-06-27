import hexdump
import logging
from reducer_orig import bytes_detection
from reducer import scanData
from file_pe import FilePe
from copy import deepcopy
from utils import *


def analyzeFileExe(filepath, scanner, isolate=False, remove=False, verify=True, ignoreText=False):
    filePe = FilePe(filepath)
    filePe.load()
    filePe.printSections()    

    matches = investigate(filePe, scanner, isolate, remove, ignoreText)

    if len(matches) == 0:
        return filePe, []

    printMatches(filePe.data, matches)

    if verify:
        verifyFile(filePe, matches, scanner)

    return filePe, matches


def printMatches(data, matches):
    for i in matches:
        size = i.end - i.begin
        dataDump = data[i.begin:i.end]

        print(f"[*] Signature between {i.begin} and {i.end} size {size}: ")
        print(hexdump.hexdump(dataDump, result='return'))

        logging.info(f"[*] Signature between {i.begin} and {i.end} size {size}: " + "\n" + hexdump.hexdump(dataDump, result='return'))


def investigate(filePe, scanner, isolate=False, remove=False, ignoreText=False):
    if remove:
        logging.info("Remove: Ressources, Versioninfo")
        filePe.hideSection("Ressources")
        filePe.hideSection("VersionInfo")

    # check if its really being detected first
    detected = scanner.scan(filePe.data, filePe.filename)
    if not detected:
        logging.error(f"{filePe.filename} is not detected by {scanner.scanner_name}")
        return []

    # identify which sections get detected
    detected_sections = []
    if isolate:
        logging.info("Section Detection: Isolating sections (zero all others)")
        detected_sections = findDetectedSectionsIsolate(filePe, scanner)
    else:
        logging.info("Section Detection: Zero section (leave all others)")
        detected_sections = findDetectedSections(filePe, scanner)

    if len(detected_sections) == 0:
        print("No matches?!")
        return []

    print(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    logging.info(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    for section in detected_sections:
        print(f"  section: {section.name}")
        logging.info(f"  section: {section.name}")

    if len(detected_sections) > 3:
        print("More than 3 sections detected. That cant be right.")
        print("Try --isolate")
        logging.info("More than 3 sections detected. That cant be right.")
        return []

    # analyze each detected section
    matches = []
    for section in detected_sections:
        # reducing .text does not work well
        if ignoreText and section.name == '.text':
            continue

        logging.info(f"Launching bytes analysis on section {section.name}")

        # new algo
        match = scanData(scanner, filePe.data, filePe.filename, section.addr, section.addr+section.size)
        # original algo
        #match = bytes_detection(pe.data, scanner, section.addr, section.addr+section.size)

        matches += match

    return matches


def findDetectedSectionsIsolate(filePe, scanner):
    # isolate individual sections, and see which one gets detected
    detected_sections = []

    for section in filePe.sections:
        filePeCopy = deepcopy(filePe)

        filePeCopy.hideAllSectionsExcept(section.name)
        status = scanner.scan(filePeCopy.data, filePeCopy.filename)

        if status:
            detected_sections += [section]

        logging.info(f"Hide all except: {section.name} -> Detected: {status}")

    return detected_sections


def findDetectedSections(filePe, scanner):
    # remove stuff until it does not get detected anymore
    detected_sections = []

    for section in filePe.sections:
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideSection(section.name)

        status = scanner.scan(filePeCopy.data, filePeCopy.filename)
        if not status:
            detected_sections += [section]

        logging.info(f"Hide: {section.name} -> Detected: {status}")

    return detected_sections


def verifyFile(filePe, matches, scanner):
    print("Patching file with results...")
    logging.info("Patching file with results...")

    filePeCopy = deepcopy(filePe)

    for i in matches:
        size = i.end - i.begin
        print(f"Patch: {i.begin}-{i.end} size {size}")
        logging.info(f"Patch: {i.begin}-{i.end} size {size}")
        filePeCopy.hidePart(i.begin, size, fillType=FillType.lowentropy)

        if not scanner.scan(filePeCopy.data, filePeCopy.filename):
            print("Success, not detected!")
            logging.info("Success, not detected!")
            return

    print("Still detected? :-(")
    logging.info("Still detected? :-(")