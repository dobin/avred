import logging
import os
import pefile

from model.extensions import PluginFileFormat
from model.model import Section, SectionsBag


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

        self.sectionsBag.addSection(Section('Header', 0, min, 0))

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
