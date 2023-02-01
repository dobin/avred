from intervaltree import Interval, IntervalTree
import logging
from typing import List
from model.model import Match, FileInfo, Scanner, DisasmLine
from plugins.file_pe import FilePe, Section
from utils import *
from dotnetfile import DotNetPE
from plugins.dncilparser import DncilParser


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> FileInfo:
    """Correlates file offsets in matches with the disassembles filePe methods"""
    dotnetSections = getDotNetSections(filePe)
    if dotnetSections is None:
        logging.warn("No dotNet sections")
    dncilParser = DncilParser(filePe.filepath)
    
    for match in matches:
        detail = []
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        sectionName = filePe.findSectionNameFor(match.fileOffset)

        # set info: PE section name first
        info = sectionName + " "

        if dotnetSections is not None:
            # set info: .NET sections/streams name next if found
            sections = list(filter(lambda x: match.start() >= x.addr and match.start() < x.addr + x.size, dotnetSections))
            if len(sections) > 0:
                info += ' '.join(s.name for s in sections)

        if sectionName == ".text":  # only disassemble in .text
            # set info: precise disassembly info (e.g. function name)
            detail, info2 = getDotNetDisassembly(match.start(), match.size, dncilParser)
            info += " " + info2

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(info)
        match.setDetail(detail)


def getDotNetDisassembly(addrBase, size, dncilParser):
    """Get section-info & disassembly in dncilParser for addrBase"""
    detail = []

    ilMethods = dncilParser.query(addrBase, addrBase+size)
    if ilMethods is None or len(ilMethods) == 0:
        logging.debug("No disassembly found for {:X}", addrBase)
        return detail, ''
    logging.info("Match physical {}/0x{:X}, method disassemblies found: {}".format(
        addrBase, addrBase, len(ilMethods)))

    # all relevant instructions
    addrTightStart = addrBase
    addrTightEnd = addrBase + size

    # provide some context
    addrWideStart = addrTightStart - 16
    addrWideEnd = addrTightEnd + 16

    # check each disassembled function if it contains instructions for our offset
    for ilMethod in sorted(ilMethods):
        # find all instructions of method which are part of the match
        for instrOff in sorted(ilMethod.instructions.keys()):
            addrOff = ilMethod.getOffset() + instrOff
            if addrOff > addrWideStart and addrOff < addrWideEnd:
                d = ilMethod.instructions[instrOff]

                isPart = False
                if addrOff > addrTightStart and addrOff < addrTightEnd:
                    isPart = True
                #line = "0x{:X}: {}".format(ilMethod.addr + instrOff - addrOffset, d)
                line = d

                disasmLine = DisasmLine(
                    addrOff, 
                    addrOff,
                    isPart, 
                    line, 
                    line
                )
                detail.append(disasmLine)

    # we take the last method name atm
    info = " {} (@RVA 0x{:X})".format(ilMethod.getName(), ilMethod.getOffset())
    return detail, info


def getDotNetSections(filePe):
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sections = []

    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    cli_header_addr = textSection.addr
    cli_header_size = dotnet_file.clr_header.HeaderSize.value

    metadata_header_addr = dotnet_file.clr_header.MetaDataDirectoryAddress.value
    metadata_header_addr -= addrOffset
    metadata_header_size = dotnet_file.clr_header.MetaDataDirectorySize.value

    methods_addr = cli_header_addr + cli_header_size
    methods_size = metadata_header_addr - methods_addr

    signature_addr = dotnet_file.clr_header.StrongNameSignatureAddress.value
    signature_addr -= addrOffset
    signature_size = dotnet_file.clr_header.StrongNameSignatureSize.value

    s = Section('DotNet Header', 
        cli_header_addr,   
        cli_header_size, 
        0)
    sections.append(s)
    
    s = Section('methods', 
        methods_addr,    
        methods_size, 
        0)
    sections.append(s)

    s = Section('Metadata Header', 
        metadata_header_addr,
        metadata_header_size, 
        0)
    sections.append(s)

    for stream in dotnet_file.dotnet_streams:
        s = Section('Stream: ' + stream.string_representation,
            stream.address - addrOffset, 
            stream.size, 
            0)
        sections.append(s)

    s = Section('Signature', 
        signature_addr,
        signature_size, 
        0)
    sections.append(s)

    return sections
