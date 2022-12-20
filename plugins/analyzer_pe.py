
import logging
from reducer import scanData
from copy import deepcopy
from utils import *
import r2pipe
from ansi2html import Ansi2HTMLConverter
import json


def analyzeFileExe(filePe, scanner, isolate=False, remove=False, ignoreText=False):
    matchesIntervalTree = investigate(filePe, scanner, isolate, remove, ignoreText)
    #printMatches(filePe.data, matchesIntervalTree)
    #matches = augmentMatches(filePe, matchesIntervalTree)
    return matchesIntervalTree


def augmentFilePe(filePe, matches):
    matches = []

    conv = Ansi2HTMLConverter()
    r2 = r2pipe.open(filePe.filepath)
    r2.cmd("e scr.color=2") # enable terminal color output
    r2.cmd("aaa")

    baddr = r2.cmd("e bin.baddr")
    baseAddr = int(baddr, 16)

    MORE = 16
    for match in matches:
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdump.hexdump(data, result='return')
        sectionName = filePe.findSectionNameFor(match.fileOffset)

        addrDisasm = baseAddr + match.fileOffset - MORE
        sizeDisasm = match.size + MORE + MORE

        detail = None
        if sectionName == ".text":
            # r2: Print Dissabled (by bytes)
            asm = r2.cmd("pDJ {} @{}".format(sizeDisasm, addrDisasm))
            asm = json.loads(asm)
            for a in asm:
                relOffset = a['offset'] - baseAddr

                if relOffset >= match.start() and relOffset < match.end():
                    a['part'] = True

                a['textHtml'] = conv.convert(a['text'], full=False)
            detail = asm

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(sectionName)
        match.setDetail(detail)


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
        logging.info("Section Detection: Zero section (leave all others intact)")
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
        # reducing .text may not work well
        if ignoreText and section.name == '.text':
            continue

        logging.info(f"Launching bytes analysis on section {section.name}")

        # new algo
        match = scanData(scanner, filePe.data, filePe.filename, section.addr, section.addr+section.size)
        # original algo
        #match = bytes_detection(pe.data, scanner, section.addr, section.addr+section.size)

        matches += match

    return sorted(matches)


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