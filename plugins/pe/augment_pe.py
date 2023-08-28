import logging
from copy import deepcopy
from myutils import *
import r2pipe
from ansi2html import Ansi2HTMLConverter
import json
from intervaltree import Interval, IntervalTree
from typing import List, Tuple

from model.model_data import Match
from model.model_code import AsmInstruction, UiDisasmLine, SectionType
from plugins.pe.file_pe import FilePe
from config import MAX_DISASM_SIZE


# Fix for https://github.com/radareorg/radare2-r2pipe/issues/146
def cmdcmd(r, cmd):
    first = r.cmd(cmd)
    return first if len(first) > 0 else r.cmd("")


def augmentFilePe(filePe: FilePe, matches: List[Match]) -> str:
    """Augments all matches with additional information from filePe"""

    # Augment the matches with R2 decompilation and section information.
    # Returns a FileInfo object with detailed file information too.
    r2 = r2pipe.open(filePe.filepath)

    # check if pdf file exists
    pdbFile = filePe.filepath + ".pdb"
    if os.path.exists(pdbFile):
        logging.info("Loading PDB file: {}".format(pdbFile))
        r2.cmd("idp {}".format(pdbFile))

    r2.cmd("aaa")  # aaaa

    for match in matches:
        matchRva = filePe.offsetToRva(match.start())
        matchBytes: bytes = filePe.Data().getBytesRange(start=match.start(), end=match.end())
        matchHexdump: str = hexdmp(matchBytes, offset=match.start())
        matchDisasmLines: List[UiDisasmLine] = []
        matchAsmInstructions: List[AsmInstruction] = []

        matchSection = filePe.sectionsBag.getSectionByAddr(match.start())
        matchSectionName = '<unknown>'
        if matchSection is not None:
            matchSectionName = matchSection.name

        if matchSection is None: 
            logging.warning("No section found for offset {}".format(match.fileOffset))
        elif matchSection.name == ".text":
            if match.size < MAX_DISASM_SIZE:
                matchAsmInstructions, matchDisasmLines = disassemblePe(
                    r2, filePe, match.start(), match.size)
            match.sectionType = SectionType.CODE
        else:
            if match.size < MAX_DISASM_SIZE:
                matchDisasmLines = dataRefPe(
                    r2, filePe, match.start(), match.size)
            match.sectionType = SectionType.DATA

        match.setRva(matchRva)
        match.setData(matchBytes)
        match.setSection(matchSection)
        match.setDataHexdump(matchHexdump)
        match.setSectionInfo(matchSectionName)
        match.setDisasmLines(matchDisasmLines)
        match.setAsmInstructions(matchAsmInstructions)

    # file structure
    s = ''
    for matchSection in filePe.sectionsBag.sections:
        s += "{0:<16}: File Offset: {1:<7}  Virtual Addr: {2:<6}  size {3:<6}  scan:{4}\n".format(
            matchSection.name, matchSection.addr, matchSection.virtaddr, matchSection.size, matchSection.scan)
    return s


def dataRefPe(r2, filePe: FilePe, fileOffset: int, size: int):
    #virtAddrDisasm = filePe.offsetToRva(fileOffset)
    matchDisasmLines: List[UiDisasmLine] = []
    offset = fileOffset

    # get all strings
    stringsJson = r2.cmd("izj")
    strings = json.loads(stringsJson)
    # convert to intervaltree
    it = IntervalTree()
    for s in strings:
        it.add( Interval(s["paddr"], s["paddr"] + s["size"], s))

    # find all strings which overlap
    its = it.overlap(Interval(offset, offset+size))
    for i in its:
        s = i[2]
        logging.info("Found addr {} in str: {}".format(offset, s["paddr"]))

        # for each string (addr), print its references
        ref = r2.cmd("axt @{}".format(s["vaddr"]))
        logging.info("  Ref: {}".format(ref))

        text = ref
        disasmLine = UiDisasmLine(s["paddr"], s["vaddr"], True, text, text)
        matchDisasmLines.append(disasmLine)

    return matchDisasmLines


conv = Ansi2HTMLConverter()
def disassemblePe(r2, filePe: FilePe, fileOffset: int, sizeDisasm: int, moreUiLines=16):
    virtAddrDisasm = filePe.offsetToRva(fileOffset)

    matchDisasmLines: List[UiDisasmLine] = []
    matchAsmInstructions: List[AsmInstruction] = []

    r2.cmd("e scr.color=2")
    MORE = 32

    # r2: Disassemble by bytes, no color escape codes, more data (like esil, type)
    asm = cmdcmd(r2, "pDj {} @{}".format(sizeDisasm+MORE, virtAddrDisasm-MORE))
    asm = json.loads(asm)
    for a in asm:
        asmVirtAddr = int(a['offset'])
        asmFileOffset = filePe.codeRvaToOffset(asmVirtAddr)

        if (asmFileOffset < fileOffset) or (asmFileOffset > fileOffset + sizeDisasm):
            # we print number of assembly instructions, not bytes,
            # as bytes will possibly garble last decoded asm instruction
            continue

        esil = a.get('esil', '')
        type = a.get('type', '')
        disasm = a.get('disasm', '')
        size = a.get('size', 0)
        rawBytes = bytes.fromhex(a.get('bytes', ''))
    
        asmInstruction = AsmInstruction(
            asmFileOffset,
            asmVirtAddr,
            esil,
            type,
            disasm,
            size,
            rawBytes)
        matchAsmInstructions.append(asmInstruction)

    # surrounding
    # r2: Disassemble by bytes, color
    asmColor = cmdcmd(r2, "pDJ {} @{}".format(
        sizeDisasm+MORE+2*moreUiLines, 
        virtAddrDisasm-MORE-moreUiLines))
    asmColor = json.loads(asmColor)
    # ui disassemly lines
    for a in asmColor:
        asmVirtAddr = int(a['offset'])
        asmFileOffset = filePe.codeRvaToOffset(asmVirtAddr)

        if (asmVirtAddr < (virtAddrDisasm-moreUiLines)) or (asmVirtAddr > (virtAddrDisasm + sizeDisasm + moreUiLines)):
            # we print number of assembly instructions, not bytes,
            # as bytes will possibly garble last decoded asm instruction
            continue

        if asmFileOffset >= fileOffset and asmFileOffset <= fileOffset + sizeDisasm:
            isPart = True
        else: 
            isPart = False
        
        # get disassembly with ANSI color
        text = a['text']
        textHtml = conv.convert(text, full=False)

        disasmLine = UiDisasmLine(
            asmFileOffset, 
            asmVirtAddr,
            isPart,
            text, 
            textHtml, 
        )
        matchDisasmLines.append(disasmLine)

    return matchAsmInstructions, matchDisasmLines
