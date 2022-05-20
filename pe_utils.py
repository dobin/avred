import logging
from dataclasses import dataclass
import pefile

@dataclass
class Section:
    name: str
    addr: int
    size: int
    #detected: bool = False


@dataclass
class PE:
    filename = ""
    sections = []
    strings = []
    data = b""
    patches = []


def parse_pe(path, showInfo=False):
    pe = PE()

    with open(path, "rb") as f:
        pe.data = f.read()

    pe.filename = path
    pe.sections = get_sections(pe)

    if showInfo:
        for section in pe.sections:
            print(f"Section {section.name}  addr: {section.addr}   size: {section.size} ")

    return pe


def get_sections(pe):
    pepe = pefile.PE(data=pe.data)

    # Normal sections
    for section in pepe.sections:
        name = section.Name.decode("utf-8")
        addr = section.PointerToRawData
        size = section.SizeOfRawData

        if addr != 0 and size != 0:
            pe.sections += [
                Section(name, addr, size)
            ]

    # version information
    if hasattr(pepe, "VS_VERSIONINFO"):
        vi = pepe.VS_VERSIONINFO
        if len(vi) != 0:
            vim = vi[0] # TODO what if more?
            base = vim.get_file_offset()
            size = vim.Length
            pe.sections.append(
                Section("VersionInfo", base, size)
            )

    # resources
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
    section = next((sec for sec in pe.sections if sec.name == section_name), None)
    hidePart(pe, section.addr, section.size)
    

def hidePart(pe, base, size):
    d = bytearray(pe.data)
    d[base:base+size] = b" " * size
    pe.data = bytes(d)


def hide_all_sections_except(pe, exception):
    logging.info(f"Hide all except: {exception}")
    for section in pe.sections:
        if section.name != exception:
            hidePart(pe, section.addr, section.size)
