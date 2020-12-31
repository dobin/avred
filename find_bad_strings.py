#!/usr/bin/python3
import sys
import string
import os
import subprocess
import dataclasses
import re
import logging
import r2pipe
import base64
import shutil

import string
import random
import tempfile
from tqdm import tqdm
from itertools import islice

from scanner import WindowsDefender, DockerWindowsDefender

logging.basicConfig(level=logging.DEBUG)

BINARY                 = "/home/vladimir/dev/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
ORIGINAL_BINARY        = ""

g_scanner = None

class UnknownDetectionException(Exception):
    pass

class ShouldNotGetHereException(Exception):
    pass

@dataclasses.dataclass
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


"""
    Loads an entire binary to memory.
    Warning: don't use on huge files.
"""
def get_binary(path):

    data = []

    with open(path, "rb") as f:
        data = f.read()

    return data



"""
    Hides an entire section of a binary
    rabin2 output:
        [Sections]
        Nm Paddr       Size Vaddr      Memsz Perms Name
        00 0x00000400 619008 0x180001000 622592 -r-x .text
"""
def hide_section(section_name, filepath):

    section_size = 0
    section_addr = 0

    pipe = r2pipe.open(filepath)

    sections = pipe.cmdj("iSj")

    for section in sections:

        if section.get("name") == section_name:
            logging.debug(f"Found {section_name} section, hiding it...")
            section_size = section.get("size")
            section_addr = section.get("paddr")
            break

    assert(section_size > 0)
    assert(section_addr > 0)

    """
    patch = bytes('\x41' * section_size, 'ascii')
    new_bin = binary[:section_addr] + patch + binary[section_addr+section_size:]

    # binary's size is not expected to change.
    assert(len(new_bin) == len(binary))

    return new_bin
    """
    pipe = r2pipe.open(filepath, flags=["-w"])
    replacement = ''.join(random.choice(string.ascii_letters) for i in range(section_size))
    replacement = base64.b64encode(bytes(replacement, "ascii")).decode()
    pipe.cmd(f"w6d {replacement} @ {section_addr}")

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

def parse_strings(filename):

    pipe = r2pipe.open(filename)
    #pipe.cmd("aaa")
    strings = pipe.cmdj("izj")

    string_refs = []

    for string in strings:
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
    replacement = base64.b64encode(bytes(replacement, convert_encoding(str_ref.encoding))).decode()
    pipe.cmd(f"w6d {replacement} @ {str_ref.vaddr}")


"""
    returns true if all string_refs are in the blacklist
    tested: true
    @param string_refs a collection of StringRef objects
    @param blacklist a collection of indexes that are known to the AV engine
"""
def is_all_blacklisted(string_refs, blacklist):
    return all(s.index in blacklist for s in string_refs)


"""
    merges two lists without duplicates
    @param list1 some collection of type 'list'
    @param list2 somme collection of type 'list'
    return list1 and list2 merged together (type: list)
"""
def merge_unique(list1, list2):
    list3 = list1 + list2
    unique_set = set(list3)
    return list(unique_set)


"""
    returns true if both lists are equal and order doesn't matter
    @param list1 some list
    @param list2 some list
"""
def is_equal_unordered(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    return set1 == set2


"""
    Takes the original binary, patches the strings whose
    indexes are in "blacklist" and re-scan with the AV.
"""
def validate_results(sample_file, blacklist, all_strings):

    blacklisted = []
    for b in blacklist:
        string = next(filter(lambda x: x.index == b, all_strings))
        string.should_mask = True
        logging.debug(f"Removing bad string {repr(string)}")
        blacklisted += [string]

    temp = tempfile.NamedTemporaryFile()
    shutil.copyfile(sample_file, temp.name)
    pipe = r2pipe.open(temp.name, flags=["-w"])
    patch_binary_mass(temp.name, blacklisted, pipe)

    detection = scan(temp.name)
    temp.close()

    return detection


def prepare_sample(filename, str_refs, unmask_only=False):

    pipe = r2pipe.open(filename, flags=["-w"])

    for ref in str_refs:
        patch_string(filename, ref, pipe, unmask_only=unmask_only)

"""
    TODO: update the progress bar.
    TODO: use a threadpool.
    @param binary binary blob currently edited, all strings hidden
    @param string_refs list of StringRefs objects.
    @param blacklist list of strings' index to never unmask.
"""
def rec_bissect(sample_file, string_refs, blacklist):

    if type(string_refs) is list and len(string_refs) < 2:
        if len(string_refs) > 0:
            i = string_refs[0]
            i.is_bad = True
            logging.debug(f"Found it: {repr(i)}")
            blacklist.append(i.index)
        else:
            raise ShouldNotGetHereException
        return blacklist

    elif type(string_refs) is StringRef:
        string_refs.is_bad = True
        logging.debug(f"Found it: f{repr(string_refs)}")
        blacklist.append(string_refs.index)
        return blacklist

    half_nb_strings = len(string_refs) // 2

    str_ref_blacklisted = list(filter(lambda x: x.index in blacklist, string_refs))
    for str_ref in str_ref_blacklisted:
        str_ref.should_mask = True

    half1 = string_refs[:half_nb_strings]# + str_ref_blacklisted
    half2 = string_refs[half_nb_strings:]# + str_ref_blacklisted

    # unmask all the strings in half1 except those that are blacklisted
    for item in half1:
        item.should_mask = item.index in blacklist

    # unmask all the strings in half2 except those that are blacklisted
    for item in half2:
        item.should_mask = item.index in blacklist

    dump_path1 = tempfile.NamedTemporaryFile()
    dump_path2 = tempfile.NamedTemporaryFile()

    shutil.copyfile(sample_file, dump_path1.name)
    shutil.copyfile(sample_file, dump_path2.name)

    prepare_sample(dump_path1.name, half1 + str_ref_blacklisted, unmask_only=True)
    prepare_sample(dump_path2.name, half2 + str_ref_blacklisted, unmask_only=True)

    detection_result1 = scan(dump_path1.name)
    detection_result2 = scan(dump_path2.name)

    dump_path1.close()
    dump_path2.close()

    res = detection_result1 or detection_result2

    # the upper half triggers the detection
    if detection_result1:
        logging.debug(f"Signature between half1 {half1[0].index} and {half1[-1].index}")
        blacklist1 = rec_bissect(sample_file, half1, blacklist)
        blacklist = merge_unique(blacklist, blacklist1)

    if detection_result2:
        logging.debug(f"Signature between half2 {half2[0].index} and {half2[-1].index}")
        blacklist2 = rec_bissect(sample_file, half2, blacklist)
        blacklist = merge_unique(blacklist, blacklist2)

    if not res:
        logging.debug("Both halves are not detected")
        if len(blacklist) > 0 and len(blacklist) <= 200:
            logging.debug("Here is the blacklist's content:")

            logging.info(f"Found {len(blacklist)} signatures")
            all_strings = parse_strings(ORIGINAL_BINARY)
            if not validate_results(ORIGINAL_BINARY, blacklist, all_strings):
                logging.info("Validation is ok !")


        # TODO: rather hazardous, but works for mimikatz. In case of failures, fix this.
        half1 = string_refs[:len(string_refs)//4]
        half2 = string_refs[len(string_refs)//4]
        blacklist = merge_unique(
            blacklist, rec_bissect(sample_file, half1, blacklist))
        blacklist = merge_unique(
            blacklist, rec_bissect(sample_file, half2, blacklist))

    return blacklist

"""
    Amorce function for the bissection algorithm.
    Expects a path to a binary detected by the AV engine.
    Returns a list of signatures or crashes.
"""
def bissect(sample_file, blacklist = []):

    # no point in continuing if the binary is not detected as malicious already.
    #assert(scan(sample_file) is True)

    str_refs = parse_strings(sample_file)

    logging.debug(f"Got {len(str_refs)} string objects")

    # mask all strings
    logging.debug("Patching all the strings in the binary")

    # patch the binary (mask the string)
    for str_ref in str_refs:
        str_ref.should_mask = True

    collection = random.sample(str_refs, 10)
    print([(x.content) for x in collection])

    pipe = r2pipe.open(sample_file, flags=["-w"])
    patch_binary_mass(sample_file, str_refs, pipe)

    logging.debug("Binary patched")
    detection_result = scan(sample_file)

    # sometimes there are signatures in the .txt sections
    if detection_result is True:
        raise UnknownDetectionException

    logging.debug("Good, masking all the strings has an impact on the AV's verdict")
    #progress = tqdm(total=len(str_refs), leave=False)

    blacklist = rec_bissect(sample_file, str_refs, blacklist)

    if len(blacklist) > 0:
        logging.info(f"Found {len(blacklist)} signatures")

        if not validate_results(ORIGINAL_BINARY, blacklist, str_refs):
            logging.info("Validation is ok !")
        else:
            logging.error("Patched binary is still detected, retrying.")
            bissect(BINARY, blacklist)
    else:
        logging.debug("No signatures found...")
    return blacklist


def scan(path):

    return g_scanner.scan(path)


if __name__ == "__main__":

    #g_scanner = WindowsDefender()
    g_scanner = DockerWindowsDefender()

    if not len(sys.argv) > 1:
        print(f"Usage: {sys.argv[0]} path/to/file/to/analyse")
        exit(-1)

    ORIGINAL_BINARY = os.path.abspath(sys.argv[1])
    temp = tempfile.NamedTemporaryFile()
    shutil.copyfile(ORIGINAL_BINARY, temp.name)
    BINARY = temp.name
    print(BINARY)
    try:
        # explore(sample_file)

        bissect(BINARY)
        logging.debug("[*] Done ! Press any to exit...")

    except KeyboardInterrupt:
        logging.debug("[*] Not done, but here is what I've found so far:")
    except UnknownDetectionException:
        logging.debug("Hiding all the strings doesn't seem to impact the AV's verdict.\
             Retrying after masking the .text section")
        hide_section(".text", BINARY)
        bissect(BINARY)
        exit(0)
    except ShouldNotGetHereException:
        print("WTF")
