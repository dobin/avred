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


class DataReferor():
    def __init__(self, r2: r2pipe):
        """Requires a valid open r2 pipe to work on"""
        self.r2 = r2
        self.stringsIt: IntervalTree = IntervalTree()


    def init(self):
        # get all strings
        logging.info("R2: Get all strings")
        stringsJson = self.r2.cmd("izj")
        strings = json.loads(stringsJson)
        stringsIt = IntervalTree()
        for s in strings:
            stringsIt.add( Interval(s["paddr"], s["paddr"] + s["size"], s))
        self.stringsIt = stringsIt


    def query(self, fileOffset: int, size: int) -> List[UiDisasmLine]:
        matchDisasmLines: List[UiDisasmLine] = []
        offset = fileOffset

        # find all strings which we overlap
        its = self.stringsIt.overlap(Interval(offset, offset+size))
        for i in its:
            s = i[2]
            # details of that string
            text = self.r2.cmd("axt @{}".format(s["vaddr"]))
            disasmLine = UiDisasmLine(s["paddr"], s["vaddr"], True, text, text)
            matchDisasmLines.append(disasmLine)

        it = IntervalTree()
        # check if it contains data from IMPORT

        return matchDisasmLines


def augmentFilePe(filePe: FilePe, matches: List[Match]) -> str:
    """Augments all matches with additional information from filePe"""

    logging.info("Augment: File PE")
    # Augment the matches with R2 decompilation and section information.
    # Returns a FileInfo object with detailed file information too.
    r2 = r2pipe.open(filePe.filepath)

    # load PDB file if exists
    pdbFile = filePe.filepath + ".pdb"
    if os.path.exists(pdbFile):
        logging.info("R2: Loading PDB file: {}".format(pdbFile))
        r2.cmd("idp {}".format(pdbFile))

    logging.info("R2: Analyze")
    r2.cmd("aaa")  # aaaa

    dataReferor = DataReferor(r2)
    dataReferor.init()

    logging.info("Augment: Matches")
    for match in matches:
        matchRva = filePe.physOffsetToRva(match.start())
        matchBytes: bytes = filePe.Data().getBytesRange(start=match.start(), end=match.end())
        matchHexdump: str = hexdmp(matchBytes, offset=match.start())
        matchDisasmLines: List[UiDisasmLine] = []
        matchAsmInstructions: List[AsmInstruction] = []

        matchSection = filePe.peSectionsBag.getSectionByPhysAddr(match.start())
        matchSectionName = '<unknown>'
        if matchSection is not None:
            matchSectionName = matchSection.name
        matchDetail = ''

        if matchSection is None: 
            logging.warning("No section found for offset {}".format(match.fileOffset))
        elif matchSection.name == ".text":
            if match.size < MAX_DISASM_SIZE:
                matchAsmInstructions, matchDisasmLines = disassemblePe(
                    r2, filePe, match.start(), match.size)
            match.sectionType = SectionType.CODE
        else:
            if match.size < MAX_DISASM_SIZE:
                matchDisasmLines = dataReferor.query(match.start(), match.size)
            match.sectionType = SectionType.DATA

            region = filePe.regionsBag.getSectionByPhysAddr(match.start())
            if region is not None:
                matchDetail += region.name

        match.setRva(matchRva)
        match.setData(matchBytes)
        match.setSection(matchSection)
        match.setDataHexdump(matchHexdump)
        match.setSectionInfo(matchSectionName)
        match.setSectionDetail(matchDetail)
        match.setDisasmLines(matchDisasmLines)
        match.setAsmInstructions(matchAsmInstructions)

    # file structure
    s = ''
    for matchSection in filePe.peSectionsBag.sections:
        s += "{0:<16}: File Offset: {1:<7}  Virtual Addr: {2:<6}  size {3:<6}  scan:{4}\n".format(
            matchSection.name, matchSection.physaddr, matchSection.virtaddr, matchSection.size, matchSection.scan)
    return s


conv = Ansi2HTMLConverter()
def disassemblePe(r2, filePe: FilePe, fileOffset: int, sizeDisasm: int, moreUiLines=16):
    virtAddrDisasm = filePe.physOffsetToRva(fileOffset)

    matchDisasmLines: List[UiDisasmLine] = []
    matchAsmInstructions: List[AsmInstruction] = []

    r2.cmd("e scr.color=2")
    MORE = 32

    # r2: Disassemble by bytes, no color escape codes, more data (like esil, type)
    asm = cmdcmd(r2, "pDj {} @{}".format(sizeDisasm+MORE, virtAddrDisasm-MORE))
    asm = json.loads(asm)
    for a in asm:
        asmVirtAddr = int(a['offset'])
        asmFileOffset = filePe.codeRvaToPhysOffset(asmVirtAddr)

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
        asmFileOffset = filePe.codeRvaToPhysOffset(asmVirtAddr)

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
