from intervaltree import Interval, IntervalTree
import logging
from typing import List, Tuple, Set
from model.model import Match, FileInfo, UiDisasmLine, Section, SectionsBag
from model.extensions import Scanner
from plugins.file_pe import FilePe, Section
from utils import *
from dotnetfile import DotNetPE
from dotnetfile.parser import DOTNET_STREAM_HEADER
from dotnetfile.util import BinaryStructureField, FileLocation
from plugins.dncilparser import DncilParser


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> str:
    """Correlates file offsets in matches with the disassembles filePe methods"""
    dotnetSectionsBag = getDotNetSections(filePe)
    if dotnetSectionsBag is None:
        logging.warn("No dotNet sections")
    dncilParser = DncilParser(filePe.filepath)
    
    for match in matches:
        uiDisasmLines = []
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        sectionName = filePe.sectionsBag.getSectionNameByAddr(match.fileOffset)

        # set info: PE section name first
        info = sectionName + " "

        if dotnetSectionsBag is not None:
            # set info: .NET sections/streams name next if found
            sections = dotnetSectionsBag.getSectionsForRange(match.start(), match.end())
            info += ','.join(s.name for s in sections)

        if sectionName == ".text":  # only disassemble in .text
            # set info: precise disassembly info (e.g. function name)
            uiDisasmLines, methodNames = getDotNetDisassemblyMethods(match.start(), match.size, dncilParser)
            more1 = getDotNetDisassemblyHeader(filePe, match.start(), match.size)
            uiDisasmLines += more1

            info += " " + " ".join(methodNames)

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setSectionInfo(info)
        match.setDisasmLines(uiDisasmLines)

    s = ''
    for section in filePe.sectionsBag.sections:
        s += "{}: File Offset: {}  Virtual Addr: {}  size {}\n".format(
            section.name, section.addr, section.virtaddr, section.size)
    for section in dotnetSectionsBag.sections:
        s += "{}: File Offset: {}  Virtual Addr: {}  size {}\n".format(
            section.name, section.addr, section.virtaddr, section.size)
    return s


def getDotNetDisassemblyHeader(filePe: FilePe, offset: int, size: int,) -> List[UiDisasmLine]:
    uiDisasmLines: List[UiDisasmLine] = []  # all diasassmbled IL
    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    entry: BinaryStructureField
    for entry in dotnet_file.dotnet_metadata_header.structure_fields:
        hdrFileOffset = entry.address - addrOffset
        hdrSize = entry.size
        if hdrFileOffset >= offset and hdrFileOffset + hdrSize <= offset + size:
            
            text = "        {:18}  Metadata Header: {}: {}".format(
                hexstr(filePe.data, hdrFileOffset, hdrSize),
                entry.display_name, 
                entry.value)
            uiDisasmLine = UiDisasmLine(
                hdrFileOffset,
                entry.address,
                True,
                text,
                text
            )
            print("AAA: {}: {}".format(hex(hdrFileOffset), text))
            uiDisasmLines.append(uiDisasmLine)
    
    return uiDisasmLines


def getDotNetDisassemblyMethods(offset: int, size: int, dncilParser: DncilParser) -> Tuple[List[UiDisasmLine], Set[str]]:
    """Get section-info & disassembly as UiDisasmLine's with dncilParser for range offset/+size"""
    uiDisasmLines: List[UiDisasmLine] = []  # all diasassmbled IL
    methodNames: Set[str] = set()  # a set with unique function names

    ilMethods = dncilParser.query(offset, offset+size)
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

        uiDisasmLine = UiDisasmLine(
            ilMethod.getOffset(), 
            ilMethod.getRva(),
            isPart, 
            "Header size: {}".format(ilMethod.getHeaderSize()),
            "Header size: {}".format(ilMethod.getHeaderSize())
        )
        uiDisasmLines.append(uiDisasmLine)

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


def getDotNetSections(filePe) -> SectionsBag:
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sectionsBag = SectionsBag()

    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    # header
    cli_header_addr = textSection.addr
    cli_header_size = dotnet_file.clr_header.HeaderSize.value
    s = Section('DotNet Header', 
        cli_header_addr,   
        cli_header_size, 
        0)
    sectionsBag.addSection(s)

    # metadata header
    metadata_header_addr = dotnet_file.dotnet_metadata_header.address
    metadata_header_size = dotnet_file.dotnet_metadata_header.size
    s = Section('Metadata Header', 
        metadata_header_addr,
        metadata_header_size, 
        0)
    sectionsBag.addSection(s)

    # methods
    methods_addr = cli_header_addr + cli_header_size
    methods_size = metadata_header_addr - methods_addr
    s = Section('methods', 
        methods_addr,    
        methods_size, 
        0)
    sectionsBag.addSection(s)
    
    # metadata directory
    metadata_directory_addr = dotnet_file.clr_header.MetaDataDirectoryAddress.value
    metadata_directory_addr -= addrOffset
    metadata_directory_size = dotnet_file.clr_header.MetaDataDirectorySize.value
    s = Section('Metadata Directory', 
        metadata_directory_addr,
        metadata_directory_size, 
        0)
    sectionsBag.addSection(s)

    # signature
    signature_addr = dotnet_file.clr_header.StrongNameSignatureAddress.value
    signature_size = dotnet_file.clr_header.StrongNameSignatureSize.value    
    if (signature_addr != 0):
        signature_addr -= addrOffset
        s = Section('Signature', 
            signature_addr,
            signature_size, 
            0)
        sectionsBag.addSection(s)

    # All streams
    for stream in dotnet_file.dotnet_stream_headers:
        s = Section(stream.string_representation,
            stream.address - addrOffset, 
            stream.size, 
            0)
        sectionsBag.addSection(s)

    return sectionsBag

