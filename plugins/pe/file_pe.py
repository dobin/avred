import logging
import os
import pefile
import inspect

from model.model_code import Section, SectionsBag
from model.file_model import BaseFile

from dotnetfile import DotNetPE
from dotnetfile.util import FileLocation


class FilePe(BaseFile):
    def __init__(self):
        super().__init__()
        self.isDotNet: bool = False
        self.baseAddr: int = 0
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # no container, file is the data

        dataBytes = self.data.getBytes()
        pepe = pefile.PE(data=dataBytes)

        # DotNet or not
        # https://stackoverflow.com/questions/45574925/is-there-a-way-to-check-if-an-exe-is-dot-net-with-python-pefile
        isDotNet = pepe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if isDotNet.VirtualAddress != 0 and isDotNet.Size != 0:
            self.isDotNet = True

        # Baseaddr
        self.baseAddr = pepe.OPTIONAL_HEADER.ImageBase

        # Normal PE sections
        min = len(dataBytes)
        for section in pepe.sections:
            name = ''
            try:
                name = section.Name.decode("UTF-8").rstrip("\x00") # its always padded to 8 bytes with \x00
            except:
                # some binaries have invalid UTF8 in section name
                name = ''.join('0x{:02x} '.format(x) for x in (section.Name))
            physAddr = section.PointerToRawData
            size = section.SizeOfRawData
            virtaddr = section.VirtualAddress

            if physAddr != 0 and size != 0:
                self.peSectionsBag.addSection(Section(name, physAddr, size, virtaddr))
                if physAddr < min:
                    min = physAddr
            else:
                logging.info("Section is invalid, not scanning: {} addr:{} size:{}".format(name, physAddr, size))
        # Header belongs to it too (as its the part of the file not covered by sections)
        self.peSectionsBag.addSection(Section('Header', 0, min, 0, False))

        # Directory "sections"
        for n, entry in enumerate(pepe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if entry.VirtualAddress == 0:
                continue
            
            self.regionsBag.addSection(Section(
                directoryTables[n],
                self.rvaToPhysOffset(entry.VirtualAddress),
                entry.Size,
                entry.VirtualAddress,
                scan=False,
                detected=False
            ))

        # handle dotnet
        if not self.isDotNet:
            return
        dotnetSections = getDotNetSections(self)
        for section in dotnetSections.sections:
            self.peSectionsBag.sections.append(section)
        self.peSectionsBag.getSectionByName(".text").scan = False


    def rvaToPhysOffset(self, rva: int) -> int: 
        section = self.peSectionsBag.getSectionByVirtAddr(rva)
        if section is None:
            logging.error("Could not find section for rva 0x{:x}".format(rva))
        diff = rva - section.virtaddr
        offset = section.physaddr + diff
        return offset


    def codeRvaToPhysOffset(self, rva: int) -> int: 
        baseAddr = self.baseAddr
        textSection = self.peSectionsBag.getSectionByName('.text')
        offsetToBase = rva - textSection.virtaddr
        offset = textSection.physaddr - baseAddr + offsetToBase
        return offset


    def physOffsetToRva(self, fileOffset: int) -> int:
        baseAddr = self.baseAddr
        matchSection = self.peSectionsBag.getSectionByPhysAddr(fileOffset)
        
        # offset: of fileOffset from .text segment file offset
        offset = fileOffset - matchSection.physaddr
        # base=0x400000 + .text=0x1000 + offset=0x123
        addrDisasm = baseAddr + matchSection.virtaddr + offset    

        return addrDisasm
    

    def hideAllSectionsExcept(self, sectionName: str):
        for section in self.peSectionsBag.sections:
            if section.name != sectionName:
                self.Data().hidePart(offset=section.physaddr, size=section.size)


    def hideSection(self, section: Section):
        self.Data().hidePart(offset=section.physaddr, size=section.size)


def getDotNetSections(filePe) -> SectionsBag:
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sectionsBag = SectionsBag()

    dotnet_file = DotNetPE(filePe.filepath)

    textSection: Section = filePe.peSectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.physaddr
    logging.info("Offset: {}".format(addrOffset))

    # header
    cli_header_addr = textSection.physaddr
    cli_header_vaddr = textSection.virtaddr
    cli_header_size = dotnet_file.clr_header.HeaderSize.value
    s = Section('DotNet Header', 
        cli_header_addr,   
        cli_header_size, 
        cli_header_vaddr,
        False)
    sectionsBag.addSection(s)

    # metadata header
    metadata_header_addr = dotnet_file.dotnet_metadata_header.address - addrOffset
    metadata_header_vaddr = dotnet_file.dotnet_metadata_header.address
    metadata_header_size = dotnet_file.dotnet_metadata_header.size
    s = Section('Metadata Header', 
        metadata_header_addr,
        metadata_header_size, 
        metadata_header_vaddr,
        False)
    sectionsBag.addSection(s)

    # methods
    methods_addr = cli_header_addr + cli_header_size
    methods_vaddr = cli_header_vaddr + cli_header_size
    methods_size = metadata_header_addr - methods_addr
    s = Section('methods', 
        methods_addr,    
        methods_size, 
        methods_vaddr)
    sectionsBag.addSection(s)
    
    # metadata directory
    #metadata_directory_addr = dotnet_file.clr_header.MetaDataDirectoryAddress.value
    #metadata_directory_addr -= addrOffset
    #metadata_directory_size = dotnet_file.clr_header.MetaDataDirectorySize.value
    #s = Section('Metadata Directory', 
    #    metadata_directory_addr,
    #    metadata_directory_size, 
    #    0)
    #sectionsBag.addSection(s)

    # signature
    signature_addr = dotnet_file.clr_header.StrongNameSignatureAddress.value
    signature_size = dotnet_file.clr_header.StrongNameSignatureSize.value    
    if (signature_addr != 0):
        signature_addr -= addrOffset
        s = Section('Signature', 
            signature_addr,
            signature_size, 
            0,
            False)
        sectionsBag.addSection(s)

    # All stream headers
    for streamHeader in dotnet_file.dotnet_stream_headers:
        s = Section(streamHeader.string_representation,
            streamHeader.address - addrOffset, 
            streamHeader.size,
            streamHeader.address,
            False)
        sectionsBag.addSection(s)

    # All streams
    stream: FileLocation
    for stream in dotnet_file.dotnet_streams:
        s = Section(stream.string_representation,
            stream.address - addrOffset, 
            stream.size, 
            stream.address)
        sectionsBag.addSection(s)

    return sectionsBag


# Name correspond to their index
directoryTables = [
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
]