#!/usr/bin/python3
import sys
import string
import os
import subprocess
import dataclasses
import re
import random
import tempfile
from tqdm import tqdm
from itertools import islice
from scanner import WindowsDefender, DockerWindowsDefender, VMWareKaspersky
import logging

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)

BINARY                 = "/home/vladimir/dev/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
ORIGINAL_BINARY        = ""
WDEFENDER_INSTALL_PATH = '/home/vladimir/tools/new_loadlibrary/loadlibrary/'
DEBUG_LEVEL            = 2  # setting supporting levels 0-3, incrementing the verbosity of log msgs
LVL_ALL_DETAILS        = 3  # everything
LVL_DETAILS            = 2  # only    important  details
LVL_RES_ONLY           = 1  # only    results
LVL_SILENT             = 0  # quiet
g_scanner = None

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
    is_bad     : bool = False  # does this string has a signifcant impact on the AV's verdict?


"""
    Wrapper to print text to stdout, either for concurrent access to
    the file descriptor, or because we need to enrich the text before.
"""
def print_dbg(msg, level=3, decorate=True):

    toprint = msg

    if decorate:
        toprint = "[*] " + toprint

    if level <= DEBUG_LEVEL:
        tqdm.write(toprint)

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
    Executes rabin2 to get all the strings from a binary.
    @param filepath: the path to the file to be analyzed.
    @return: the raw output from rabin2
"""
def get_all_strings(file_path, extensive=False):

    command = ['rabin2', "-z", file_path]
    if extensive:
        command = ['rabin2', "-zz", file_path]

    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    rout = ""
    iterations = 0
    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out = p.stdout.readline().decode('utf-8')
        iterations += 1
        rout += out
        if(retcode is not None):
            break

    return rout


"""
    Executes rabin2 to enumerate the binary's sections information
    @param filepath: the path to the file to be analyzed.
    @return: the raw output from rabin2
"""
def get_sections(file_path):

    command = ['rabin2', "-S", file_path]

    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    rout = ""
    iterations = 0
    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out = p.stdout.readline().decode('utf-8')
        iterations += 1
        rout += out
        if(retcode is not None):
            break

    return rout


"""
    Hides an entire section of a binary
    rabin2 output:
        [Sections]
        Nm Paddr       Size Vaddr      Memsz Perms Name
        00 0x00000400 619008 0x180001000 622592 -r-x .text
"""
def hide_section(section, filepath, binary):

    section_size = 0
    section_addr = 0

    strings_data = get_sections(filepath)

    for string in strings_data.split('\n'):

        # to preserve some whitespaces
        data = string.split()

        if len(data) >= 4 and data[0].isnumeric():

            if data[6] == section:
                print_dbg(f"Found {section} section, hiding it...", LVL_DETAILS, True)
                section_size = int(data[2],16)
                section_addr = int(data[1],16)
                break

    assert(section_size > 0)
    assert(section_addr > 0)

    patch = bytes('\x41' * section_size, 'ascii')
    new_bin = binary[:section_addr] + patch + binary[section_addr+section_size:]

    # binary's size is not expected to change.
    assert(len(new_bin) == len(binary))

    return new_bin

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
def parse_strings(strings_data):
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


"""
    Scans a file with Windows Defender and returns True if the file
    is detected as a threat.
"""
def scan(path):

    return g_scanner.scan(path)



"""
    @description patch a binary blob at the location pointed by "str_ref"
    @param binary binary blob of data
    @param str_ref StringRef object, must hold size, length and content.
    @param filepath if non empty, the function will write the resulting binary to the specified location on disk.
    @param mask if true, patches with junk data, or else path with str_ref.content (revert to original content)
"""
def patch_binary(binary, str_ref, filepath, mask=True):

    encoding = convert_encoding(str_ref.encoding)
    patch = bytes('\x00' * str_ref.size, 'ascii')

    # tricky part, the original string must be put back in the binary.
    # however, several encodings and null bytes make that a pain to realize.
    # In case of failures, the original binary is used instead of str_ref.content
    if not mask:
        cnt = str_ref.content + '\x00'  # why already ??
        cnt = str_ref.content.replace("\\n", '\x0a')
        cnt = cnt.replace("\\t", '\x09')
        patch = bytes(cnt+chr(0), encoding)

        if len(patch) != str_ref.size or "\\" in str_ref.content:
            print_dbg(
                "Oops, parsing error, will recover bytes from the original file...", LVL_ALL_DETAILS)
            with open(BINARY, "rb") as tmp_fd:
                tmp_fd.seek(str_ref.paddr)
                patch = tmp_fd.read(str_ref.size)

    new_bin = binary[:str_ref.paddr] + patch + \
        binary[str_ref.paddr+str_ref.size:]

    # binary's size is not expected to change.
    assert(len(new_bin) == len(binary))

    # write the patched binary to disk
    if len(filepath) > 0:
        with open(filepath, "wb") as f:
            f.write(new_bin)

    return new_bin


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
def validate_results(sample_file, tmpfile, blacklist, all_strings):


    # read the binary.
    binary = get_binary(sample_file)

    for b in blacklist:
        string = next(filter(lambda x: x.index == b, all_strings))
        print_dbg(f"Removing bad string {repr(string)}", LVL_DETAILS, True)
        binary = patch_binary(binary, string, "", True)

    with open(tmpfile, "wb") as fd:
        fd.write(binary)

    detection = scan(tmpfile)

    return detection


"""
    TODO: update the progress bar.
    TODO: use a threadpool.
    @param binary binary blob currently edited, all strings hidden
    @param string_refs list of StringRefs objects.
    @param blacklist list of strings' index to never unmask.
"""
def rec_bissect(binary, string_refs, blacklist):

    if type(string_refs) is list and len(string_refs) < 2:
        if len(string_refs) > 0:
            i = string_refs[0]
            print_dbg(f"Found it: {repr(i)}", LVL_RES_ONLY, False)
            blacklist.append(i.index)
        return blacklist

    elif type(string_refs) is StringRef:
        print_dbg(f"Found it: f{repr(string_refs)}", LVL_RES_ONLY, False)
        blacklist.append(string_refs.index)
        return blacklist


    half_nb_strings = len(string_refs) // 2
    half1 = string_refs[:half_nb_strings]
    half2 = string_refs[half_nb_strings:]
    binary1 = binary
    binary2 = binary

    for string in half1:

        # hide all upper half of binary2
        binary2 = patch_binary(binary2, string, "", mask=True)

        if string.index in blacklist:
            # hide the blacklisted string
            binary1 = patch_binary(binary1, string, "", mask=True)
            binary2 = patch_binary(binary2, string, "", mask=True)

        else:
            # put the string back
            binary1 = patch_binary(binary1, string, "", mask=False)

    for string in half2:

        #hide all lower half of binary1
        binary1 = patch_binary(binary1, string, "", mask=True)

        if string.index in blacklist:
            # hide blacklisted strings in both halves
            binary1 = patch_binary(binary1, string, "", mask=True)
            binary2 = patch_binary(binary2, string, "", mask=True)
        else:
            # unhide all lower half of binary2
            binary2 = patch_binary(binary2, string, "", mask=False)
            pass

    dump_path1 = tempfile.NamedTemporaryFile()
    dump_path2 = tempfile.NamedTemporaryFile()

    with open(dump_path1.name, "wb") as f:
        f.write(binary1)

    with open(dump_path2.name, "wb") as fd:
        fd.write(binary2)

    detection_result1 = scan(dump_path1.name)
    detection_result2 = scan(dump_path2.name)

    dump_path1.close()
    dump_path2.close()

    res = detection_result1 or detection_result2

    # the upper half triggers the detection
    if detection_result1:
        print_dbg(f"Signature between half1 {half1[0].index} and {half1[-1].index}", LVL_DETAILS)
        blacklist1 = rec_bissect(binary1, half1, blacklist)
        blacklist = merge_unique(blacklist, blacklist1)

    if detection_result2:
        print_dbg(f"Signature between half2 {half2[0].index} and {half2[-1].index}", LVL_DETAILS)
        blacklist2 = rec_bissect(binary2, half2, blacklist)
        blacklist = merge_unique(blacklist, blacklist2)

    if not res:
        print_dbg("Both halves are not detected", LVL_DETAILS)

        # TODO: rather hazardous, but works for mimikatz. In case of failures, fix this.
        half1 = string_refs[:len(string_refs)//4]
        half2 = string_refs[len(string_refs)//4]
        blacklist = merge_unique(
            blacklist, rec_bissect(binary, half1, blacklist))
        blacklist = merge_unique(
            blacklist, rec_bissect(binary, half2, blacklist))

    return blacklist

"""
    Amorce function for the bissection algorithm.
    Expects a path to a binary detected by the AV engine.
    Returns a list of signatures or crashes.
"""
def bissect(sample_file, blacklist = []):

    global g_scanner
    global BINARY

    BINARY = sample_file
    if g_scanner is None:
        #g_scanner = DockerWindowsDefender()
        g_scanner = VMWareKaspersky()
    # no point in continuing if the binary is not detected as malicious already.
    assert(scan(sample_file) is True)

    # use rabin2 from radare2 to extract all the strings from the binary
    strings_data = get_all_strings(sample_file)

    # parse rabin2 output
    str_refs = parse_strings(strings_data)

    print_dbg(f"Got {len(str_refs)} string objects", LVL_DETAILS, True)

    # read the binary.
    binary = get_binary(sample_file)
    binary1 = binary
    # mask all strings
    for string in str_refs:
        # patch the binary (mask the string)
        binary = patch_binary(binary, string, "", True)

    dump_path = tempfile.NamedTemporaryFile()

    with open(dump_path.name, "wb") as f:
        f.write(binary)

    detection_result = scan(dump_path.name)
    dump_path.close()

    # sometimes there are signatures in the .txt sections
    if detection_result is True:
        print_dbg("Hiding all the strings doesn't seem to impact the AV's verdict.\
             Retrying after masking the .text section", LVL_DETAILS, True)
        binary = hide_section(".text", sample_file, binary1)
        tmp = tempfile.NamedTemporaryFile()
        with open("/tmp/toto", "wb") as f:
            f.write(binary)
        bissect("/tmp/toto")
        exit(0)


    print_dbg("Good, masking all the strings has an impact on the AV's verdict", 0)
    #progress = tqdm(total=len(str_refs), leave=False)

    blacklist = rec_bissect(binary1, str_refs, blacklist)

    if len(blacklist) > 0:
        print_dbg(f"Found {len(blacklist)} signatures", LVL_DETAILS, True)
        print(blacklist)
        tmpfile = "/tmp/newbin"
        if not validate_results(ORIGINAL_BINARY, tmpfile, blacklist, str_refs):
            print_dbg("Validation is ok !", LVL_DETAILS, True)
        else:
            print_dbg("Patched binary is still detected, retrying.", LVL_DETAILS, True)
            bissect("/tmp/newbin", blacklist)
    else:
        print_dbg("No signatures found...", LVL_DETAILS, True)
    return blacklist


if __name__ == "__main__":

    g_scanner = DockerWindowsDefender()


    sample_file = BINARY

    if len(sys.argv) > 1:
        sample_file = sys.argv[1]
        BINARY = sample_file

    ORIGINAL_BINARY = BINARY

    try:
        # explore(sample_file)
        bissect(sample_file)
        print_dbg("[*] Done ! Press any to exit...", 0)

    except KeyboardInterrupt:
        print_dbg("[*] Not done, but here is what I've found so far:", 0)
