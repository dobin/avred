
import logging
from copy import deepcopy
from utils import *
import r2pipe
from ansi2html import Ansi2HTMLConverter
import json
from reducer import Reducer
from model.model import Match, FileInfo, UiDisasmLine, AsmInstruction
from model.extensions import Scanner
from plugins.file_pe import FilePe
from intervaltree import Interval, IntervalTree
from typing import List, Tuple


def analyzeFileExe(filePe: FilePe, scanner: Scanner, analyzerOptions={}) -> Tuple[IntervalTree, str]:
    # Scans a PE file given with filePe with Scanner scanner. 
    # Returns all matches.
    isolate = analyzerOptions.get("isolate", False)
    remove = analyzerOptions.get("remove", False)
    ignoreText = analyzerOptions.get("ignoreText", False)

    matchesIntervalTree, scannerInfo = investigate(filePe, scanner, isolate, remove, ignoreText)
    return matchesIntervalTree, scannerInfo


# Fix for https://github.com/radareorg/radare2-r2pipe/issues/146
def cmdcmd(r, cmd):
    first = r.cmd(cmd)
    return first if len(first) > 0 else r.cmd("")


def augmentFilePe(filePe: FilePe, matches: List[Match]) -> str:
    """Augments all matches with additional information from filePe"""

    # Augment the matches with R2 decompilation and section information.
    # Returns a FileInfo object with detailed file information too.
    r2 = r2pipe.open(filePe.filepath)
    r2.cmd("aaa")

    for match in matches:
        matchBytes: bytes = filePe.Data().getBytesRange(start=match.start(), end=match.end())
        matchHexdump: str = hexdmp(matchBytes, offset=match.start())
        matchDisasmLines: List[UiDisasmLine] = []
        matchAsmInstructions: List[AsmInstruction] = []

        matchSection = filePe.sectionsBag.getSectionByAddr(match.start())
        matchSectionName = '<unknown>'
        if matchSection is not None:
            matchSectionName = matchSection.name

        if matchSection is None: 
            logging.warn("No section found for offset {}".format(match.fileOffset))
        elif matchSection.name == ".text":
            matchAsmInstructions, matchDisasmLines = disassemble(
                r2, filePe, match.start(), match.size)

        match.setData(matchBytes)
        match.setDataHexdump(matchHexdump)
        match.setSectionInfo(matchSectionName)
        match.setDisasmLines(matchDisasmLines)
        match.setAsmInstructions(matchAsmInstructions)

    # file structure
    s = ''
    for matchSection in filePe.sectionsBag.sections:
        s += "{0:<16}: File Offset: {1:<7}  Virtual Addr: {2:<6}  size {3:<6}  scanned:{4}\n".format(
            matchSection.name, matchSection.addr, matchSection.virtaddr, matchSection.size, matchSection.scan)
    return s


conv = Ansi2HTMLConverter()
def disassemble(r2, filePe, fileOffset: int, size: int, moreUiLines=True):
    baseAddr = filePe.baseAddr
    matchSection = filePe.sectionsBag.getSectionByAddr(fileOffset)

    # Decompiling
    # offset: of fileOffset from .text segment file offset
    offset = fileOffset - matchSection.addr

    # base=0x400000 + .text=0x1000 + offset=0x123
    addrDisasm = baseAddr + matchSection.virtaddr + offset
    sizeDisasm = size
    matchDisasmLines: List[UiDisasmLine] = []
    matchAsmInstructions: List[AsmInstruction] = []

    MORE = 0
    if moreUiLines:
        MORE = 16

    # r2: Disassemble by bytes, no color escape codes, more data (like esil, type)
    #r2.cmd("e scr.color=0")
    asm = cmdcmd(r2, "pdj {} @{}".format(sizeDisasm, addrDisasm))
    asm = json.loads(asm)
    for a in asm:
        offset = a['offset']
        relOffset = offset - baseAddr - matchSection.virtaddr
        isPart = False
        if relOffset >= offset and relOffset < offset+size:
            isPart = True
        
        esil = a.get('esil', '')
        type = a.get('type', '')
        disasm = a.get('disasm', '')
        size = a.get('size', 0)
    
        asmInstruction = AsmInstruction(
            relOffset + matchSection.addr,
            int(a['offset']),
            esil,
            type,
            disasm,
            size)
        matchAsmInstructions.append(asmInstruction)

    addrDisasm -= MORE
    sizeDisasm += MORE

    # r2: Disassemble by bytes, color
    #r2.cmd("e scr.color=2")
    asmColor = cmdcmd(r2, "pDJ {} @{}".format(sizeDisasm, addrDisasm))
    asmColor = json.loads(asmColor)
    # ui disassemly lines
    for a in asmColor:
        offset = a['offset']
        relOffset = offset - baseAddr - matchSection.virtaddr
        isPart = False
        if relOffset >= offset and relOffset < offset+size:
            isPart = True
        
        # get disassembly with color
        text = a['text']
        textHtml = conv.convert(text, full=False)

        disasmLine = UiDisasmLine(
            relOffset + matchSection.addr, 
            int(a['offset']),
            isPart,
            text, 
            textHtml, 
        )
        matchDisasmLines.append(disasmLine)
    return matchAsmInstructions, matchDisasmLines


def investigate(filePe: FilePe, scanner, isolate=False, remove=False, ignoreText=False) -> Tuple[IntervalTree, str]:
    scannerInfos = []
    if remove:
        logging.info("Remove: Ressources, Versioninfo")
        scannerInfos.append('remove-sections')
        filePe.hideSection("Ressources")
        filePe.hideSection("VersionInfo")

    # identify which sections get detected
    detected_sections = []
    if isolate:
        logging.info("Section Detection: Isolating sections (zero all others)")
        scannerInfos.append('isolate-sections')
        detected_sections = findDetectedSectionsIsolate(filePe, scanner)
    else:
        logging.info("Section Detection: Zero section (leave all others intact)")
        scannerInfos.append('zero-sections')
        detected_sections = findDetectedSections(filePe, scanner)
    logging.info(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    for section in detected_sections:
        logging.info(f"  section: {section.name}")

    reducer = Reducer(filePe, scanner)
    matches = []
    if len(detected_sections) == 0:
        logging.info("Section analysis failed. Fall back to non-section-aware reducer")
        scannerInfos.append('flat-scan1')
        match = reducer.scan(
            offsetStart=filePe.sectionsBag.getSectionByName(".text").addr, # start at .code, skip header(s)
            offsetEnd=filePe.Data().getLength())
        matches += match
    else:
        # analyze each detected section
        for section in detected_sections:
            # reducing .text may not work well
            if ignoreText and section.name == '.text':
                continue

            logging.info(f"Launching bytes analysis on section {section.name}")
            match = reducer.scan(
                offsetStart=section.addr, 
                offsetEnd=section.addr+section.size)
            matches += match

        if len(matches) > 0:
            # only append section-scan indicator if it yielded results, see below
            scannerInfos.append('section-scan')
        else:
            # there are instances where the section-based scanning does not yield any result.
            # do it again without it
            logging.info("Section based analysis failed, no matches. Fall back to non-section-aware reducer")
            scannerInfos.append('flat-scan2')
            match = reducer.scan(
                offsetStart=filePe.sectionsBag.getSectionByName(".text").addr, # start at .code, skip header(s)
                offsetEnd=filePe.Data().getLength())
            matches += match

    return sorted(matches), ",".join(scannerInfos)


def findDetectedSectionsIsolate(filePe: FilePe, scanner):
    # isolate individual sections, and see which one gets detected
    detected_sections = []

    for section in filePe.sectionsBag.sections:
        if not section.scan:
            continue
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideAllSectionsExcept(section.name)
        status = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)

        if status:
            detected_sections += [section]

        logging.info(f"Hide all except: {section.name} -> Detected: {status}")

    return detected_sections


def findDetectedSections(filePe: FilePe, scanner):
    # remove stuff until it does not get detected anymore
    detected_sections = []

    for section in filePe.sectionsBag.sections:
        if not section.scan:
            continue
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideSection(section.name)

        status = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)
        if not status:
            detected_sections += [section]

        logging.info(f"Hide: {section.name} -> Detected: {status}")

    return detected_sections

