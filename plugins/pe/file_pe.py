import logging
import pefile

from model.model_code import Section, SectionsBag
from model.file_model import BaseFile
from dotnetfile import DotNetPE
from dotnetfile.util import FileLocation


class FilePe(BaseFile):
    def __init__(self):
        super().__init__()
        self.baseAddr: int = 0
        self.pepe = None
        

    def parseFile(self) -> bool:
        """Parses PE file for sections and regions"""
        logging.info("FilePe: Parse File")
        self.data = self.fileData  # no container, file is the data

        dataBytes = self.data.getBytes()
        self.pepe = pefile.PE(data=dataBytes)

        # Baseaddr
        self.baseAddr = self.pepe.OPTIONAL_HEADER.ImageBase

        # self.peSectionsBag
        self.parsePeSections(self.pepe, self.data.getLength())
        # self.regionsBag
        self.parsePeRegions(self.pepe)


    def getScanSections(self):
        sections = []
        for section in self.peSectionsBag.sections:
            if section.scan:
                sections.append(section)
        return sections
    

    def getSections(self):
        sections = []
        for section in self.peSectionsBag.sections:
            sections.append(section)
        return sections


    def parsePeSections(self, pepe, fileLength):
        logging.info("FilePe: Parse PE Sections")
        min = fileLength
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


    def parsePeRegions(self, pepe):
        logging.info("FilePe: Parse PE Regions")
        # Directory "sections"
        for n, entry in enumerate(pepe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if entry.VirtualAddress == 0:
                logging.warn("Data Directory Section {} has address 0, skipping".format(n))
                continue
            if entry.Size == 0:
                logging.warn("Data Directory Section {} has length 0, skipping".format(n))
                continue

            self.regionsBag.addSection(Section(
                directoryTables[n],
                self.rvaToPhysOffset(entry.VirtualAddress),
                entry.Size,
                entry.VirtualAddress,
                scan=False,
                detected=False
            ))


    def rvaToPhysOffset(self, rva: int) -> int: 
        section = self.peSectionsBag.getSectionByVirtAddr(rva)
        if section is None:
            logging.warn("Could not find section for rva 0x{:x}".format(rva))
            return 0

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
        if matchSection is None:
            logging.warn("Could not find matching section for offset {}".format(fileOffset))
            return 0
        
        # offset: of fileOffset from .text segment file offset
        offset = fileOffset - matchSection.physaddr
        # base=0x400000 + .text=0x1000 + offset=0x123
        addrDisasm = baseAddr + matchSection.virtaddr + offset    

        return addrDisasm
    

    def hideSection(self, section: Section):
        self.Data().hidePart(offset=section.physaddr, size=section.size)


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