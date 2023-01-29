from intervaltree import Interval, IntervalTree
import logging
from typing import List
from model.model import Match, FileInfo, Scanner, DisasmLine
from plugins.file_pe import FilePe, Section
from utils import *
from dotnetfile import DotNetPE
from plugins.dncilparser import DncilParser


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> FileInfo:
    # calculate offset for disassembly
    textSection = filePe.getSectionByName('.text')
    if textSection is None:
        logging.error("No text section?")
        return None
    addrOffset = textSection.virtaddr - textSection.addr  # usually 0x1E00
    logging.info("Section Virt: 0x{:X} - Section Phys: 0x{:X} -> Offset: 0x{:X}".format(
        textSection.virtaddr, textSection.addr, addrOffset))

    dotnetSections = getDotNetSections(filePe)
    if dotnetSections is None:
        logging.warn("No dotNet sections")

    dncilParser = DncilParser(filePe.filepath)
    
    for match in matches:
        detail = []
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        sectionName = filePe.findSectionNameFor(match.fileOffset)
        info = sectionName

        if sectionName == ".text":  # only disassemble in .text
            # We have the physical file offset/address given in match
            # What we need is the RVA, as used by ilspy
            addr = match.start() + addrOffset
            detail, info = getDotNetDisassembly(match, addr, dncilParser, addrOffset)

        if dotnetSections is not None:
            sections = list(filter(lambda x: match.start() >= x.addr and match.start() < x.addr + x.size, dotnetSections))
            if len(sections) > 0:
                info = ' '.join(s.name for s in sections)

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(info)
        match.setDetail(detail)


def getDotNetDisassembly(match: Match, addr: int, ilspyParser, addrOffset: int):
    detail = []

    ilMethod = ilspyParser.query(addr, addr+match.size)
    if ilMethod is None:
        print("NONE")
        return detail, '.text'
    logging.info("Match physical {}/0x{:X} (converted to {}/0x{:X}), disassembly found: {}".format(
        match.start(), match.start(), addr, addr, ilMethod))

    # The "method" has RVA addresses
    # But the method's instructions have addresses relative to the method start (in bytes)
    # e.g. addrBase is between 0 - len(method)
    addrBase = addr - ilMethod.addr

    # all relevant instructions
    addrTightStart = addrBase
    addrTightEnd = addrBase + match.size

    # provide some context
    addrWideStart = addrTightStart - 16
    addrWideEnd = addrTightEnd + 16

    # find all instructions of method which are part of the match
    for instrOff in sorted(ilMethod.instructions.keys()):
        if instrOff > addrWideStart and instrOff < addrWideEnd:
            d = ilMethod.instructions[instrOff]

            isPart = False
            if instrOff > addrTightStart and instrOff < addrTightEnd:
                isPart = True
            #line = "0x{:X}: {}".format(ilMethod.addr + instrOff - addrOffset, d)
            line = d

            disasmLine = DisasmLine(
                ilMethod.addr+instrOff-addrOffset,
                ilMethod.addr+instrOff,
                isPart, 
                line, 
                line
            )
            detail.append(disasmLine)

    info = ".text: {} (@RVA 0x{:X})".format(ilMethod.getName(), ilMethod.addr)
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
