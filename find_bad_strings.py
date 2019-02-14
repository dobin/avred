#!/usr/bin/python3
import sys
import string
import os
import subprocess
import dataclasses
import re
from tqdm import tqdm

BINARY = "/home/vladimir/dev/research/find_detected_strings/ext_server_kiwi.x64.dll"
WDEFENDER_INSTALL_PATH = '/home/vladimir/tools/loadlibrary/'
DEBUG_LEVEL = 3

@dataclasses.dataclass
class StringRef:
    index: int = 0  # index of the string
    paddr: int = 0  # offset from the beginning of the file
    vaddr: int = 0  # virtual address in the binary
    length: int = 0  # number of characters of the string
    size: int = 0  # size of the memory taken by the string
    section: str = ""  # segment where the string is located
    encoding: str = ""  # encoding of the string (utf-8, utf-16, utf-32, etc)
    content: str = ""  # actual string
    is_replaced: bool = False  # has this string already been patched?
    is_bad: bool = False  # does this string has a signifcant impact on the AV's verdict?

def print_dbg(msg, level=3):

    if level <= DEBUG_LEVEL:
        tqdm.write(msg)

"""
    todo deleteme
    get strings from binary blob
"""
def strings(binary, min=4):
    result = ""
    for c in binary:
        c = chr(c)

        if c in string.printable[:-5]:
            result += c
            continue

        if c == '\x00':
            continue
        #print(hex(int(c)))
        if len(result) >= min:
            yield result

        result = ""

    if len(result) >= min:  # catch result at EOF
        yield result 

def get_binary(path):

    data = []

    with open(path, "rb") as f:
        data = f.read()

    return data

# todo deleteme
def handle_string(data, offset, length):

    blob = data[0xa0210:0xa0210+120]

    print_dbg("[*] Strings:",1)
    for s in strings(blob):
        print_dbg(f"> {s}",1)

def get_all_strings(file_path):

    command = ['rabin2', "-z", file_path]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rout = ""
    iterations = 0
    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out = p.stdout.readline().decode('utf-8')
        iterations +=1
        rout += out
        if(retcode is not None):
                break

    return rout 

def parse_strings(strings_data):
    #columns: Num, Paddr, Vaddr, Len, Size, Section, Type, String
    string_refs = []

    for string in strings_data.split('\n'):
        data = string.split()

        if len(data) >= 7 and data[0] != "Num":
            content = " ".join(data[7:])
            str_ref = StringRef()
            str_ref.index = int(data[0])
            str_ref.paddr = int(data[1],16)
            str_ref.vaddr = int(data[2], 16)
            str_ref.length = int(data[3])
            str_ref.size = int(data[4])
            str_ref.section = data[5]
            str_ref.encoding = data[6]
            str_ref.content = content
            
            if "Kerberos name" in content:
                print(str_ref)
            string_refs += [str_ref]

    return string_refs

"""
    Scans a file with Windows Defender and returns True if the file
    is detected as a threat.
"""
def scan(file_path):
    command = ['/home/vladimir/tools/loadlibrary/mpclient', file_path]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out = p.stdout.readline().decode('utf-8')
        m = re.search('Threat', out)

        if m:
            print_dbg("[!] Threat found\n",2)
            return True
       
        if(retcode is not None):
                break

    return False 


def patch_binary(binary, str_ref, filepath, mask=True):
    
    patch = bytes(chr(0)* str_ref.size,'ascii')
    
    if not mask:
        encoding = 'ascii'
        requested_encoding = str_ref.encoding
        if requested_encoding == "utf16le":
            encoding = 'utf_16_le'
        elif requested_encoding == "utf32le":
            encoding = 'utf_32_le'
        elif requested_encoding == "utf8":
            encoding = 'utf8'
        else:
            assert(requested_encoding == 'ascii')

        patch = bytes(str_ref.content, encoding)

    new_bin = binary[:str_ref.paddr] + patch + binary[str_ref.paddr+str_ref.size:]    
    #binary[str_ref.paddr:str_ref.paddr+str_ref.size] = new_bytes

    # write the patched binary to disk
    if len(filepath) > 0:
        with open(filepath, "wb") as f:
            f.write(new_bin)

    return new_bin

def explore(sample_file):

    """
    ALGORITHM:
    assert that the AV detects the binary or else abort
    replaces all strings with 'AAAA...'
    assert that the AV doesn't flag the binary anymore or else abort
    unmask a string, scan
    if detected:
        string is bad, re-mask it, continue
    else
        continue to un-mask

    corner cases:
        what if a lot of low score strings trigger detection and we miss the more
        important strings ?

        --> i don't know!
    """
    os.chdir(WDEFENDER_INSTALL_PATH)
    assert(scan(sample_file) is True)

    # use rabin2 from radare2 to extract all the strings from the binary
    strings_data = get_all_strings(sample_file)

    # parse rabin2 output
    str_refs = parse_strings(strings_data)

    print(f"We got {len(str_refs)} string objects")

    binary = get_binary(sample_file)

    # mask all strings
    for string in str_refs:
        string.is_replaced = True

        # patch the binary (mask the string)
        binary = patch_binary(binary, string, "", True)

    dump_path = "/tmp/goat_0.bin"
    with open(dump_path, "wb") as f:
        f.write(binary)
        
    detection_result = scan(dump_path)

    assert(detection_result is False)

    print_dbg("Good, masking all the strings has an impact on the AV's verdict", 0)
    progress = tqdm(total=len(str_refs), leave=False)
    for string in str_refs:
        string.is_replaced = False
        dump_path = f"/tmp/goat_{string.index}.bin"
        binary = patch_binary(binary, string, dump_path, False)
        detection_result = scan(dump_path)
        
        if detection_result:
            print_dbg("Found a bad string, re-masking it", 1)
            print_dbg(string.content)
            string.is_replaced = True
            string.is_bad = True
            binary = patch_binary(binary, string, "", True)
        else:
            os.remove(dump_path)
            
        progress.update(1)

    progress.clear()
    progress.close()

    # done, now print results
    bad_strings = list(filter(lambda x: x.is_bad, str_refs))
    print(bad_strings)




if __name__ == "__main__":

    sample_file = BINARY

    if len(sys.argv) > 1:
        sample_file = sys.argv[1]

    try:
        explore(sample_file)
        print_dbg("[*] Done ! Press any to exit...", 0)

    except KeyboardInterrupt:
        print_dbg("[*] Not done, but here is what I've found so far:", 0)

