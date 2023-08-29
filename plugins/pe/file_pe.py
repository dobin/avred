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
        self.sectionsBag: SectionsBag = SectionsBag()
        self.isDotNet: bool = False
        self.baseAddr: int = 0
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # no container, file is the data

        dataBytes = self.data.getBytes()
        pepe = pefile.PE(data=dataBytes)

        # https://stackoverflow.com/questions/45574925/is-there-a-way-to-check-if-an-exe-is-dot-net-with-python-pefile
        isDotNet = pepe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if isDotNet.VirtualAddress != 0 and isDotNet.Size != 0:
            self.isDotNet = True

        self.baseAddr = pepe.OPTIONAL_HEADER.ImageBase

        # Normal sections
        min = len(dataBytes)
        for section in pepe.sections:
            name = ''
            try:
                name = section.Name.decode("UTF-8").rstrip("\x00") # its always padded to 8 bytes with \x00
            except:
                # some binaries have invalid UTF8 in section name
                name = ''.join('0x{:02x} '.format(x) for x in (section.Name))
            addr = section.PointerToRawData
            size = section.SizeOfRawData
            virtaddr = section.VirtualAddress

            if addr != 0 and size != 0:
                self.sectionsBag.addSection(Section(name, addr, size, virtaddr))
                if addr < min:
                    min = addr
            else:
                logging.warning("Section is invalid, not scanning: {} {} {}".format(name, addr, size))

        self.sectionsBag.addSection(Section('Header', 0, min, 0, False))

        # handle dotnet
        if not self.isDotNet:
            return
        dotnetSections = getDotNetSections(self)
        for section in dotnetSections.sections:
            self.sectionsBag.sections.append(section)
        self.sectionsBag.getSectionByName(".text").scan = False


    def codeRvaToOffset(self, rva: int) -> int: 
        baseAddr = self.baseAddr
        textSection = self.sectionsBag.getSectionByName('.text')
        offsetToBase = rva - textSection.virtaddr
        offset = textSection.addr - baseAddr + offsetToBase
        return offset


    def offsetToRva(self, fileOffset: int) -> int:
        baseAddr = self.baseAddr
        matchSection = self.sectionsBag.getSectionByAddr(fileOffset)
        
        # offset: of fileOffset from .text segment file offset
        offset = fileOffset - matchSection.addr
        # base=0x400000 + .text=0x1000 + offset=0x123
        addrDisasm = baseAddr + matchSection.virtaddr + offset    

        return addrDisasm


    def hideAllSectionsExcept(self, sectionName: str):
        for section in self.sectionsBag.sections:
            if section.name != sectionName:
                self.Data().hidePart(offset=section.addr, size=section.size)


    def hideSection(self, section: Section):
        self.Data().hidePart(offset=section.addr, size=section.size)


def getDotNetSections(filePe) -> SectionsBag:
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sectionsBag = SectionsBag()

    dotnet_file = DotNetPE(filePe.filepath)

    textSection: Section = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr
    logging.info("Offset: {}".format(addrOffset))

    # header
    cli_header_addr = textSection.addr
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

