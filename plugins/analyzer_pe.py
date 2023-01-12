
import logging
from copy import deepcopy
from utils import *
import r2pipe
from ansi2html import Ansi2HTMLConverter
import json
from reducer import Reducer
from model.model import Match, FileInfo, Scanner, DisasmLine
from plugins.file_pe import FilePe
from intervaltree import Interval, IntervalTree
from typing import List


def analyzeFileExe(filePe: FilePe, scanner: Scanner, analyzerOptions={}) -> IntervalTree:
    # Scans a PE file given with filePe with Scanner scanner. 
    # Returns all matches.
    isolate = analyzerOptions.get("isolate", False)
    remove = analyzerOptions.get("remove", False)
    ignoreText = analyzerOptions.get("ignoreText", False)

    matchesIntervalTree = investigate(filePe, scanner, isolate, remove, ignoreText)
    return matchesIntervalTree


def augmentFilePe(filePe: FilePe, matches: List[Match]):
    # Augment the matches with R2 decompilation and section information.
    # Returns a FileInfo object with detailed file information too.

    conv = Ansi2HTMLConverter()
    r2 = r2pipe.open(filePe.filepath)
    r2.cmd("e scr.color=2") # enable terminal color output
    r2.cmd("aaa")

    baddr = r2.cmd("e bin.baddr")
    baseAddr = int(baddr, 16)

    MORE = 16
    for match in matches:
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        section = filePe.findSectionFor(match.fileOffset)

        # offset from .text segment (in file)
        offset = match.start() - section.addr
        # base=0x400000 + .text=0x1000 + offset=0x123
        addrDisasm = baseAddr + section.virtaddr + offset - MORE
        sizeDisasm = match.size + MORE + MORE

        detail = []
        if section.name == ".text":
            # r2: Print Dissabled (by bytes)
            asm = r2.cmd("pDJ {} @{}".format(sizeDisasm, addrDisasm))
            asm = json.loads(asm)
            for a in asm:
                relOffset = a['offset'] - baseAddr - section.virtaddr
                isPart = False
                if relOffset >= offset and relOffset < offset+match.size:
                    isPart = True
                
                text = a['text']
                textHtml = conv.convert(text, full=False)
            
                disasmLine = DisasmLine(
                    relOffset + section.addr, 
                    a['offset'],
                    isPart,
                    text, 
                    textHtml
                )
                detail.append(disasmLine)

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(section.name)
        match.setDetail(detail)


def investigate(filePe, scanner, isolate=False, remove=False, ignoreText=False):
    if remove:
        logging.info("Remove: Ressources, Versioninfo")
        filePe.hideSection("Ressources")
        filePe.hideSection("VersionInfo")

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
        print("More than 3 sections detected. Weird. Maybe try --isolate for better results")
        logging.info("More than 3 sections detected. Weird. Maybe try --isolate for better results")
        return []

    # analyze each detected section
    reducer = Reducer(filePe, scanner)
    matches = []
    for section in detected_sections:
        # reducing .text may not work well
        if ignoreText and section.name == '.text':
            continue

        logging.info(f"Launching bytes analysis on section {section.name}")

        # new algo
        match = reducer.scan(section.addr, section.addr+section.size)
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

