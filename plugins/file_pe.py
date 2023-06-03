import logging
import os
import pefile
import inspect

from model.extensions import PluginFileFormat
from model.model import Section, SectionsBag

from dotnetfile import DotNetPE
from dotnetfile.structures import DOTNET_CLR_HEADER
from dotnetfile.parser import DOTNET_STREAM_HEADER
from dotnetfile.util import BinaryStructureField, FileLocation


class FilePe(PluginFileFormat):
    def __init__(self):
        super().__init__()
        self.sectionsBag: SectionsBag = SectionsBag()
        self.isDotNet: bool = False
        self.baseAddr: int = 0
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # no container, file is the data

        pepe = pefile.PE(data=self.data)

        # https://stackoverflow.com/questions/45574925/is-there-a-way-to-check-if-an-exe-is-dot-net-with-python-pefile
        isDotNet = pepe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if isDotNet.VirtualAddress != 0 and isDotNet.Size != 0:
            self.isDotNet = True

        self.baseAddr = pepe.OPTIONAL_HEADER.ImageBase

        # Normal sections
        min = len(self.data)
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
                logging.warn("Section is invalid, not scanning: {} {} {}".format(name, addr, size))

        self.sectionsBag.addSection(Section('Header', 0, min, 0, False))

        # handle dotnet
        if not self.isDotNet:
            return
        dotnetSections = getDotNetSections(self)
        for section in dotnetSections.sections:
            self.sectionsBag.sections.append(section)
        self.sectionsBag.getSectionByName(".text").scan = False

        if False:
            # (not necessary?) version information
            if hasattr(pepe, "VS_VERSIONINFO"):
                vi = pepe.VS_VERSIONINFO
                if len(vi) != 0:
                    vim = vi[0] # TODO what if more?
                    base = vim.get_file_offset()
                    size = vim.Length
                    self.sections.append(
                        Section("VersionInfo", base, size, virtaddr)
                    )

            # (not necessary?) resources
            d = None
            for directory in pepe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if (directory.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE"):
                    d = directory
            if d is not None:
                base = d.VirtualAddress
                size = d.Size
                self.sections.append(
                    Section("Ressources", base, size, virtaddr)
                )


    def hideSection(self, sectionName: str):
        section = self.sectionsBag.getSectionByName(sectionName)
        if section is None:
            logging.warn(f"Section {sectionName} does not exist. Cant hide.")
            return

        logging.debug(f"Hide section: {section.name} at {hex(section.addr)} {section.size}")
        self.hidePart(section.addr, section.size)


    def hideAllSectionsExcept(self, sectionName: str):
        for section in self.sectionsBag.sections:
            if section.name != sectionName:
                self.hidePart(section.addr, section.size)


def getDotNetSections(filePe) -> SectionsBag:
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sectionsBag = SectionsBag()

    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr
    logging.info("Offset: {}".format(addrOffset))

    # header
    cli_header_addr = textSection.addr
    cli_header_size = dotnet_file.clr_header.HeaderSize.value
    s = Section('DotNet Header', 
        cli_header_addr,   
        cli_header_size, 
        0,
        False)
    sectionsBag.addSection(s)

    # metadata header
    metadata_header_addr = dotnet_file.dotnet_metadata_header.address - addrOffset
    metadata_header_size = dotnet_file.dotnet_metadata_header.size
    s = Section('Metadata Header', 
        metadata_header_addr,
        metadata_header_size, 
        0,
        False)
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
            0,
            False)
        sectionsBag.addSection(s)

    # All streams
    stream: FileLocation
    for stream in dotnet_file.dotnet_streams:
        s = Section(stream.string_representation,
            stream.address - addrOffset, 
            stream.size, 
            0)
        sectionsBag.addSection(s)

    return sectionsBag

