import logging
from dataclasses import dataclass

import r2pipe

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)


@dataclass
class Section:
    name: str
    size: int
    vsize: int
    addr: int
    vaddr: int
    detected: bool = False


@dataclass
class PE:
    filename = ""
    sections = []
    strings = []
    data = b""
    patches = []


def get_sections(pe):
    section_size = 0
    section_addr = 0

    pipe = r2pipe.open(pe.filename)

    # get the sections
    sections = pipe.cmdj("iSj")

    for section in sections:
        if section.get("size") != 0 and section.get("addr") != 0:
            pe.sections += [
                Section(section.get("name"), section.get("size"), section.get("vsize"), section.get("paddr"),
                        section.get("vaddr"))]
            #logging.debug(f"Found section: {pe.sections[-1]}")

    return pe.sections


def hide_section(pe, section_name):
    section = next((sec for sec in pe.sections if sec.name == section_name), None)
    logging.debug(f"Hiding section {section.name}")

    d = bytearray(pe.data)
    d[section.addr:section.addr+section.size] = b" " * section.size

    pe.data = bytes(d)


def hide_all_sections_except(pe, exception=".text"):
    for section in pe.sections:
        if section.name != exception:
            hide_section(pe, section.name)
