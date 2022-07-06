import logging
import pefile
import os
from dataclasses import dataclass
import copy 

from utils import patchData, FillType


@dataclass
class Section:
    name: str
    addr: int
    size: int


class FilePe():
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        
        self.data = b""
        self.sections = []
        

    def load(self):
        with open(self.filepath, "rb") as f:
            self.data = f.read()

        self._parseSections()


    def _parseSections(self):
        pepe = pefile.PE(data=self.data)

        # Normal sections
        for section in pepe.sections:
            name = section.Name.decode("ascii").rstrip("\x00") # its always padded to 8 bytes with \x00
            addr = section.PointerToRawData
            size = section.SizeOfRawData

            if addr != 0 and size != 0:
                self.sections += [
                    Section(name, addr, size)
                ]

        # (not necessary?) version information
        if hasattr(pepe, "VS_VERSIONINFO"):
            vi = pepe.VS_VERSIONINFO
            if len(vi) != 0:
                vim = vi[0] # TODO what if more?
                base = vim.get_file_offset()
                size = vim.Length
                self.sections.append(
                    Section("VersionInfo", base, size)
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
                Section("Ressources", base, size)
            )


    def hideSection(self, sectionName: str):
        section = next((sec for sec in self.sections if sectionName in sec.name ), None)

        if section is None:
            logging.warn(f"Section {sectionName} does not exist.")
            return

        logging.debug(f"Hide: {hex(section.addr)} {section.size}")
        self.hidePart(section.addr, section.size)


    def hideAllSectionsExcept(self, sectionName: str):
        for section in self.sections:
            if section.name != sectionName:
                self.hidePart(section.addr, section.size)


    def hidePart(self, base: int, size: int, fillType: FillType=FillType.null):
        self.data = patchData(self.data, base, size, fillType)


    def findSectionNameFor(self, address: int):
        for section in self.sections:
            if address >= section.addr and address <= section.addr + section.size:
                return section.name

        return ""

    def printSections(self):
        for section in self.sections:
            print(f"Section {section.name}\t  addr: {hex(section.addr)}   size: {section.size} ")
            logging.info(f"Section {section.name}\t  addr: {hex(section.addr)}   size: {section.size} ") 