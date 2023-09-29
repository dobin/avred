import logging

from model.model_code import Section, SectionsBag
from dotnetfile import DotNetPE
from dotnetfile.util import FileLocation
from plugins.pe.file_pe import FilePe


class FilePeDotNet(FilePe):
    def __init__(self):
        super().__init__()
        self.dotnetSectionsBag: SectionsBag = SectionsBag()  # for DotNet "sections"


    def parseFile(self) -> bool:
        # parse PE sections
        super().parseFile()

        if not self.checkIsDotNet():
            raise Exception("FileDotNet used, but file is not a dotnet file?")

        # self.dotnetSectionsBag
        self.parseDotNetSections()

        # added DotNet specific sections in .text, so disable scanning of .text
        self.peSectionsBag.getSectionByName(".text").scan = False


    def getScanSections(self):
        sections = []
        for section in self.peSectionsBag.sections:
            if section.scan:
                sections.append(section)
        for section in self.dotnetSectionsBag.sections:
            if section.scan:
                sections.append(section)
        return sections
    

    def getSections(self):
        sections = []
        for section in self.peSectionsBag.sections:
            sections.append(section)
        for section in self.dotnetSectionsBag.sections:
            sections.append(section)
        return sections
    
    
    def checkIsDotNet(self):
        # DotNet or not
        # https://stackoverflow.com/questions/45574925/is-there-a-way-to-check-if-an-exe-is-dot-net-with-python-pefile
        isDotNet = self.pepe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if isDotNet.VirtualAddress != 0 and isDotNet.Size != 0:
            return True
        return False
    

    def parseDotNetSections(self):
        logging.info("FilePe: Parse DotNet Sections")
        # Get more details about .net executable (e.g. streams)
        # as most of it is just in PE .text
        dotnet_file = DotNetPE(self.filepath)
        textSection: Section = self.peSectionsBag.getSectionByName('.text')
        addrOffset = textSection.virtaddr - textSection.physaddr

        # header
        cli_header_addr = textSection.physaddr
        cli_header_vaddr = textSection.virtaddr
        cli_header_size = dotnet_file.clr_header.HeaderSize.value
        s = Section('DotNet Header', 
            cli_header_addr,   
            cli_header_size, 
            cli_header_vaddr,
            False)
        self.dotnetSectionsBag.addSection(s)

        # metadata header
        metadata_header_addr = dotnet_file.dotnet_metadata_header.address - addrOffset
        metadata_header_vaddr = dotnet_file.dotnet_metadata_header.address
        metadata_header_size = dotnet_file.dotnet_metadata_header.size
        s = Section('Metadata Header', 
            metadata_header_addr,
            metadata_header_size, 
            metadata_header_vaddr,
            False)
        self.dotnetSectionsBag.addSection(s)

        # All stream headers
        for streamHeader in dotnet_file.dotnet_stream_headers:
            s = Section(streamHeader.string_representation,
                streamHeader.address - addrOffset, 
                streamHeader.size,
                streamHeader.address,
                False)
            self.dotnetSectionsBag.addSection(s)

        # methods
        methods_addr = cli_header_addr + cli_header_size
        methods_vaddr = cli_header_vaddr + cli_header_size
        methods_size = metadata_header_addr - methods_addr
        s = Section('methods', 
            methods_addr,    
            methods_size, 
            methods_vaddr)
        self.dotnetSectionsBag.addSection(s)
        
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
            self.dotnetSectionsBag.addSection(s)

        # All streams
        stream: FileLocation
        for stream in dotnet_file.dotnet_streams:
            s = Section(stream.string_representation,
                stream.address - addrOffset, 
                stream.size, 
                stream.address)
            self.dotnetSectionsBag.addSection(s)
