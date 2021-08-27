import base64
import logging
import random
import re
import string
import hashlib
from copy import deepcopy
import shutil
from tempfile import NamedTemporaryFile


from dataclasses import dataclass

import r2pipe

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)

@dataclass
class Section:

    name:str
    size:int
    addr:int
    detected:bool = False

@dataclass
class PE:

    filename = ""
    sections = []
    strings = []
    md5 = ""

@dataclass
class StringRef:
    index      : int = 0  # index of the string
    paddr      : int = 0  # offset from the beginning of the file
    vaddr      : int = 0  # virtual address in the binary
    length     : int = 0  # number of characters of the string
    size       : int = 0  # size of the memory taken by the string
    section    : str = ""  # segment where the string is located
    encoding   : str = ""  # encoding of the string (utf-8, utf-16, utf-32, etc)
    content    : str = ""  # actual string
    is_replaced: bool = False  # has this string already been patched?
    is_bad     : bool = False  # does this string has a significant impact on the AV's verdict?
    should_mask: bool = True


def spwn_dbg():

    import sys
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

def md5(file):


    with open(file, 'rb') as f:
        data = f.read()

        return hashlib.md5(data).hexdigest()


def backup_pe(pe):

    # copy the binary
    new_name = NamedTemporaryFile().name
    shutil.copyfile(pe.filename, new_name)

    # hide the byzes
    new_pe = deepcopy(pe)
    new_pe.filename = new_name

    return new_pe

"""
    gets sections information about a PE
"""
def get_sections(pe):

    section_size = 0
    section_addr = 0

    pipe = r2pipe.open(pe.filename)

    # get the sections
    sections = pipe.cmdj("iSj")

    for section in sections:

        if section.get("size") != 0 and section.get("addr") != 0:
            pe.sections += [Section(section.get("name"), section.get("size"), section.get("paddr"))]
            logging.debug(f"Found section: {pe.sections[-1]}")

    return pe.sections

def hide_section(pe, section_name):

    section = next((sec for sec in pe.sections if sec.name == section_name), None)
    logging.debug(f"Hiding section {section.name}")
    hide_bytes(pe, section.addr, section.size)


"""
Hide all sections but the one specified
"""
def hide_all_sections_except(pe, exception=".text"):

    for section in pe.sections:
        if section.name != exception:
            hide_section(pe, section.name)



def hide_bytes(pe, start, length):


    logging.debug(f"Hiding {length} bytes @ {start}")
    """
    pipe = r2pipe.open(pe.filename, flags=["-w"])
    replacement = ''.join(random.choice(string.ascii_letters) for i in range(length))
    replacement = base64.b64encode(bytes(replacement, "ascii")).decode()
    pipe.cmd(f"w6d {replacement} @ {start}")
    """
    # for some reasons the code above is buggy with my radare2 version
    with open(pe.filename, 'r+b') as f:
        f.seek(start)
        f.write(bytes(''.join(random.choice(string.ascii_letters) for i in range(length)), encoding='ascii'))




"""
    converts rabin2 encoding to python3
    @param encoding the requested encoding (string)
    @return the correct encoding as string
"""
def convert_encoding(encoding):

    table = {
        "ascii": "ascii",
        "utf16le": "utf_16_le",
        "utf32le": "utf_32_le",
        "utf8": "utf8"
    }

    assert(table.get(encoding) is not None)
    return table.get(encoding)


"""
    Used to process the raw output of rabin2.
    Populates a collection of StringRefs objects from the collected data.
    TODO: parse output of -zz
    @param strings_data: the raw output of rabin2
    @return: a collection of StringRefs
"""
def parse_strings_old(strings_data):
    # columns: Num, Paddr, Vaddr, Len, Size, Section, Type, String
    string_refs = []

    for string in strings_data.split('\n'):
        data = re.split(r'(\s+)', string)  # to preserve some whitespaces
        if len(data) >= 7 and data[0].isnumeric():
            str_ref = StringRef()
            str_ref.index = int(data[0])
            str_ref.paddr = int(data[2], 16)
            str_ref.vaddr = int(data[4], 16)
            str_ref.length = int(data[6])
            str_ref.size = int(data[8])
            str_ref.section = data[10]
            str_ref.encoding = data[12]
            new_encoding = convert_encoding(str_ref.encoding)
            to_parse_len = str_ref.length+len("\x00".encode(new_encoding))
            # skip first whitespace
            content = "".join(data[13:])[1:to_parse_len]
            str_ref.content = content
            string_refs += [str_ref]

    return string_refs

def parse_strings(filename, all_sections=False, min_length=5):

    pipe = r2pipe.open(filename)
    #pipe.cmd("aaa")
    strings = pipe.cmdj("izzj")

    string_refs = []

    for string in strings:

        if string.get("size") < min_length:
            continue

        str_ref = StringRef()
        str_ref.index = string["ordinal"]
        str_ref.paddr = string.get("paddr")
        str_ref.vaddr = string.get("vaddr")
        str_ref.length = string.get("length")
        str_ref.size = string.get("size")
        str_ref.section = string.get("section")
        str_ref.encoding = string.get("type")
        new_encoding = convert_encoding(str_ref.encoding)
        #to_parse_len = str_ref.length + len("\x00".encode(new_encoding))
        # skip first whitespace
        content = string.get("string").replace("\\\\", "\\")
        str_ref.content = content#.encode(convert_encoding(str_ref.encoding))
        string_refs += [str_ref]
    return string_refs


def patch_binary_mass(filename, str_refs, pipe=None, unmask_only=False):

    if pipe is None:
        pipe = r2pipe.open(filename, flags=["-w"])

    for str_ref in str_refs:
        patch_string(filename, str_ref, pipe, unmask_only=unmask_only)


def patch_string(filename, str_ref, pipe=None, unmask_only=False):

    if pipe is None:
        pipe = r2pipe.open(filename, flags=["-w"])

    if not str_ref.should_mask:
        replacement = str_ref.content
    elif not unmask_only:
        replacement = ''.join(random.choice(string.ascii_letters) for _ in range(str_ref.length))
        replacement = replacement + '\0'
    else:
        return

    #replacement = base64.b64encode(bytes(replacement, convert_encoding(str_ref.encoding))).decode()
    #pipe.cmd(f"w6d {replacement} @ {str_ref.paddr}")
    logging.debug(f"Patching {str_ref.content} @ {str_ref.paddr} ({filename})")
    with open(filename, 'r+b') as f:
        f.seek(str_ref.paddr)
        f.write(bytes(replacement, encoding=convert_encoding(str_ref.encoding)))



