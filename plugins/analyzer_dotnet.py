from intervaltree import Interval, IntervalTree
import logging
from typing import List, Tuple, Set
from model.model import Match, FileInfo, UiDisasmLine, Section, SectionsBag
from model.extensions import Scanner
from plugins.file_pe import FilePe, Section, getDotNetSections
from utils import *

from plugins.dncilparser import DncilParser
from dotnetfile import DotNetPE
from dotnetfile.structures import DOTNET_CLR_HEADER
from dotnetfile.parser import DOTNET_STREAM_HEADER
from dotnetfile.util import BinaryStructureField, FileLocation
from plugins.dncilparser import IlMethod


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> str:
    """Correlates file offsets in matches with the disassembles filePe methods"""
    dotnetSectionsBag = getDotNetSections(filePe)
    if dotnetSectionsBag is None:
        logging.warn("No dotNet sections")
    dncilParser = DncilParser(filePe.filepath)
    
    for match in matches:
        matchDisasmLines: List[UiDisasmLine] = []
        matchBytes: bytes = filePe.Data().getBytesRange(start=match.start(), end=match.end())
        matchHexdump = hexdmp(matchBytes, offset=match.start())
        matchSectionName = filePe.sectionsBag.getSectionNameByAddr(match.fileOffset)

        # set info: PE section name first
        info = matchSectionName + " "

        if dotnetSectionsBag is not None:
            # set info: .NET sections/streams name next if found
            sections = dotnetSectionsBag.getSectionsForRange(match.start(), match.end())
            info += ','.join(s.name for s in sections)

        if matchSectionName == ".text":  # only disassemble in .text
            # set info: precise disassembly info (e.g. function name)
            matchDisasmLines, methodNames = getDotNetDisassemblyMethods(match.start(), match.size, dncilParser)
            more1 = getDotNetDisassemblyHeader(filePe, match.start(), match.size)
            matchDisasmLines += more1

            info += " " + " ".join(methodNames)

        match.setData(matchBytes)
        match.setDataHexdump(matchHexdump)
        match.setSectionInfo(info)
        match.setDisasmLines(matchDisasmLines)

    s = ''
    for section in filePe.sectionsBag.sections:
        s += "{0:<24}: File Offset: {1:<7}  Virtual Addr: {2:<6}  size {3:<6}  scan:{4}\n".format(
            section.name, section.addr, section.virtaddr, section.size, section.scan)
    return s


def getDotNetDisassemblyHeader(filePe: FilePe, offset: int, size: int,) -> List[UiDisasmLine]:
    uiDisasmLines: List[UiDisasmLine] = []  # all diasassmbled IL
    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    # DotNet header / CLI header / CLR header
    clrHeader: DOTNET_CLR_HEADER = dotnet_file.clr_header
    for entry in clrHeader.structure_fields:
        hdrFileOffset = entry.address
        hdrSize = entry.size
        if hdrFileOffset >= offset and hdrFileOffset + hdrSize <= offset + size:
            text = "{:18}  CLR Header: {}: {}".format(
                hexstr(filePe.DataAsBytes(), hdrFileOffset, hdrSize),
                entry.display_name, 
                entry.value)
            uiDisasmLine = UiDisasmLine(
                hdrFileOffset,
                entry.address,
                True,
                text,
                text
            )
            uiDisasmLines.append(uiDisasmLine)

    # metadata header
    entry: BinaryStructureField
    for entry in dotnet_file.dotnet_metadata_header.structure_fields:
        hdrFileOffset = entry.address - addrOffset
        hdrSize = entry.size
        if hdrFileOffset >= offset and hdrFileOffset + hdrSize <= offset + size:
            text = "{:18}  Metadata Header: {}: {}".format(
                hexstr(filePe.DataAsBytes(), hdrFileOffset, hdrSize),
                entry.display_name, 
                entry.value)
            uiDisasmLine = UiDisasmLine(
                hdrFileOffset,
                entry.address,
                True,
                text,
                text
            )
            uiDisasmLines.append(uiDisasmLine)
    
    # all 5 stream headers
    streamHeader: DOTNET_STREAM_HEADER
    for streamHeader in dotnet_file.dotnet_stream_headers:
        hdrFileOffset = streamHeader.address - addrOffset
        hdrSize = streamHeader.size

        for entry in streamHeader.structure_fields:
            entryFileOffset = entry.address - addrOffset
            entrySize = entry.size
            if entryFileOffset >= offset and entryFileOffset + entrySize <= offset + size:
                text = "{:18}  Stream Header: {}: {}".format(
                    hexstr(filePe.DataAsBytes(), entryFileOffset, entrySize),
                    entry.display_name, 
                    entry.value)
                uiDisasmLine = UiDisasmLine(
                    hdrFileOffset,
                    entry.address,
                    True,
                    text,
                    text
                )
                uiDisasmLines.append(uiDisasmLine)
    
    return uiDisasmLines


def getDotNetDisassemblyMethods(offset: int, size: int, dncilParser: DncilParser) -> Tuple[List[UiDisasmLine], Set[str]]:
    """Get section-info & disassembly as UiDisasmLine's with dncilParser for range offset/+size"""
    uiDisasmLines: List[UiDisasmLine] = []  # all diasassmbled IL
    methodNames: Set[str] = set()  # a set with unique function names

    ilMethods = dncilParser.getMethods(offset, offset+size)
    if ilMethods is None or len(ilMethods) == 0:
        #logging.debug("No disassembly found for {:X}", offset)
        return [], ''
    logging.info("Match physical {}/0x{:X}, method disassemblies found: {}".format(
        offset, offset, len(ilMethods)))

    # all relevant instructions
    addrTightStart = offset
    addrTightEnd = offset + size

    # provide some more context
    addrWideStart = addrTightStart - 16
    addrWideEnd = addrTightEnd + 16

    intervalMatch = Interval(offset, offset+size)
    # check each disassembled function if it contains instructions for our offset
    ilMethod: IlMethod
    for ilMethod in sorted(ilMethods):
        intervalMethod = Interval(ilMethod.getOffset(), ilMethod.getOffset() + ilMethod.getSize())
        # check if this method contains part of the data
        if not intervalMatch.overlaps(intervalMethod):
            continue

        # the method contains some of the data. 
        # * add method metadata
        # * add the relevant instructions
        isPart = False
        if ilMethod.getOffset() >= addrTightStart and ilMethod.getOffset() <= addrTightEnd:
            isPart = True
        uiDisasmLine = UiDisasmLine(
            ilMethod.getOffset(), 
            ilMethod.getRva(),
            isPart, 
            "Function: {}".format(ilMethod.getName()),
            "Function: {}".format(ilMethod.getName())
        )
        uiDisasmLines.append(uiDisasmLine)

        #if ilMethod.getHeaderSize() > 1: # should be either 1 or 12
        #    asdf

        #uiDisasmLine = UiDisasmLine(
        #    ilMethod.getOffset(), 
        #    ilMethod.getRva(),
        #    isPart, 
        #    "Header size: {}".format(ilMethod.getHeaderSize()),
        #    "Header size: {}".format(ilMethod.getHeaderSize())
        #)
        #uiDisasmLines.append(uiDisasmLine)

        # find all instructions of method which are part of the match
        for ilInstruction in ilMethod.instructions:
            addrOff = ilInstruction.fileOffset

            if addrOff > addrWideStart and addrOff < addrWideEnd:
                isPart = False
                if addrOff >= addrTightStart and addrOff <= addrTightEnd:
                    isPart = True
                
                uiDisasmLine = UiDisasmLine(
                    ilInstruction.fileOffset,
                    ilInstruction.rva,
                    isPart,
                    ilInstruction.text,
                    ilInstruction.text
                )
                uiDisasmLines.append(uiDisasmLine)

                methodNames.add(ilMethod.getName())

    return uiDisasmLines, methodNames
