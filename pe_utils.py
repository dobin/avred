import logging
import pefile
import os
from dataclasses import dataclass

from utils import patchData, FillType


@dataclass
class Section:
    name: str
    addr: int
    size: int


@dataclass
class PE:
    filename = ""
    filepath = ""
    sections = []
    data = b""


def parse_pe(path, showInfo=False):
    pe = PE()

    with open(path, "rb") as f:
        pe.data = f.read()

    pe.filename = os.path.basename(path)
    pe.filepath = path
    pe.sections = get_sections(pe)

    if showInfo:
        for section in pe.sections:
            print(f"Section {section.name}\t  addr: {hex(section.addr)}   size: {section.size} ")
            logging.info(f"Section {section.name}\t  addr: {hex(section.addr)}   size: {section.size} ")
    return pe


def get_sections(pe):
    pepe = pefile.PE(data=pe.data)

    # Normal sections
    for section in pepe.sections:
        name = section.Name.decode("ascii").rstrip("\x00") # its always padded to 8 bytes with \x00
        addr = section.PointerToRawData
        size = section.SizeOfRawData

        if addr != 0 and size != 0:
            pe.sections += [
                Section(name, addr, size)
            ]

    # (not necessary?) version information
    if hasattr(pepe, "VS_VERSIONINFO"):
        vi = pepe.VS_VERSIONINFO
        if len(vi) != 0:
            vim = vi[0] # TODO what if more?
            base = vim.get_file_offset()
            size = vim.Length
            pe.sections.append(
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
        pe.sections.append(
            Section("Ressources", base, size)
        )

    return pe.sections


def hide_section(pe, section_name):
    #section = next((sec for sec in pe.sections if sec.name == section_name), None)
    section = next((sec for sec in pe.sections if section_name in sec.name ), None)

    if section is None:
        logging.warn(f"Section {section_name} does not exist.")
        return

    logging.debug(f"Hide: {hex(section.addr)} {section.size}")
    hidePart(pe, section.addr, section.size)


def hidePart(pe, base, size, fillType=FillType.null):
    pe.data = patchData(pe.data, base, size, fillType)


def hide_all_sections_except(pe, exception):
    for section in pe.sections:
        if section.name != exception:
            hidePart(pe, section.addr, section.size)
