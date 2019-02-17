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

BINARY                 = "/home/vladimir/dev/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
WDEFENDER_INSTALL_PATH = '/home/vladimir/tools/loadlibrary/'
DEBUG_LEVEL            = 2  # setting supporting levels 0-3, incrementing the verbosity of log msgs
LVL_ALL_DETAILS        = 3  # everything
LVL_DETAILS            = 2  # only    important  details
LVL_RES_ONLY           = 1  # only    results
LVL_SILENT             = 0  # quiet


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
    TODO deleteme
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

        if len(result) >= min:
            yield result

        result = ""

    if len(result) >= min:  # catch result at EOF
        yield result


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
    TODO: delete.
    Extracts strings from a binary blob.
"""
def handle_string(data, offset, length):

    blob = data[0xa0210:0xa0210+120]

    print_dbg("[*] Strings:", 1)
    for s in strings(blob):
        print_dbg(f"> {s}", 1)


"""
    Executes rabin2 to get all the strings from a binary.
    @param filepath: the path to the file to be analyzed.
    @return: the raw output from rabin2
"""
def get_all_strings(file_path):

    command = ['rabin2', "-z", file_path]
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
def scan(file_path):
    command = ['/home/vladimir/tools/loadlibrary/mpclient', file_path]
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out = p.stdout.readline().decode('utf-8')
        m = re.search('Threat', out)

        if m:
            print_dbg("Threat found\n", LVL_ALL_DETAILS)
            return True

        if(retcode is not None):
            break

    return False


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

        if len(patch) != str_ref.size or True: # TODO remove this
            print_dbg(
                "Oops, parsing error, will recover bytes from the original file...", LVL_ALL_DETAILS)
            with open(BINARY, "rb") as tmp_fd:
                tmp_fd.seek(str_ref.paddr)
                patch = tmp_fd.read(str_ref.size)

    new_bin = binary[:str_ref.paddr] + patch + \
        binary[str_ref.paddr+str_ref.size:]

    # binary's size is expected to change.
    assert(len(new_bin) == len(binary))

    # write the patched binary to disk
    if len(filepath) > 0:
        with open(filepath, "wb") as f:
            f.write(new_bin)

    return new_bin


"""
    Find signatures in the string tables by repeatedly querying WD's engine.
    --> too slow
    --> gets stuck halfway through
    ALGORITHM:
    assert that the AV detects the binary or else abort
    replaces all strings with 'AAAA...'
    assert that the AV doesn't flag the binary anymore or else abort
    unmask a string, scan
    if detected:
        string is bad, re-mask it, continue
    else
        continue to un-mask
"""
def explore(sample_file):

    known_strings = ["Pass-the-ccache [NT6]",
                     "ERROR kuhl_m_crypto_l_certificates ; CryptAcquireCertificatePrivateKey (0x%08x)",
                     "ERROR kuhl_m_crypto_l_certificates ; CertGetCertificateContextProperty (0x%08x)",
                     "ERROR kuhl_m_crypto_l_certificates ; CertGetNameString (0x%08x)",
                     "lsasrv.dll",
                     "ERROR kuhl_m_lsadump_sam ; CreateFile (SYSTEM hive) (0x%08x)",
                     "SamIFree_SAMPR_USER_INFO_BUFFER",
                     "KiwiAndRegistryTools",
                     "wdigest.dll",
                     "multirdp",
                     "logonPasswords",
                     "credman",
                     "[%x;%x]-%1u-%u-%08x-%wZ@%wZ-%wZ.%s",
                     "n.e. (KIWI_MSV1_0_CREDENTIALS KO)",
                     "\\\\.\\mimidrv"]

    # mpengine looks for signatures definitions in the current directory.
    os.chdir(WDEFENDER_INSTALL_PATH)

    # no point in continuing if the binary is not detected as malicious already.
    assert(scan(sample_file) is True)

    # use rabin2 from radare2 to extract all the strings from the binary
    strings_data = get_all_strings(sample_file)

    # parse rabin2 output
    str_refs = parse_strings(strings_data)

    print(f"We got {len(str_refs)} string objects")

    # read the binary.
    binary = get_binary(sample_file)

    # mask all strings
    for string in str_refs:
        string.is_replaced = True

        # patch the binary (mask the string)
        binary = patch_binary(binary, string, "", True)

    dump_path = "/tmp/goat_0.bin"
    os.remove(dump_path)
    with open(dump_path, "wb") as f:
        f.write(binary)

    detection_result = scan(dump_path)

    # no point in continuing if Windows Defender detects something else than strings.
    assert(detection_result is False)

    print_dbg("Good, masking all the strings has an impact on the AV's verdict", 0)
    progress = tqdm(total=len(str_refs), leave=False)

    for string in str_refs:

        if string.index < 1500:
            progress.update(1)
            continue

        string.is_replaced = False
        dump_path = f"/tmp/goat_{string.index}.bin"

        banned_words = ["mimi", "password", "Kerb", "Ticket",
            "LsaCallAuthenticationPackage", "ntlm", "hash"]
        if string.index < 2936:
            if string.content in known_strings or any(word in string.content for word in banned_words):
                print("Skipped string " + string.content)
                with open("current_state.txt", 'a+') as d:
                    d.write(repr(string))
                progress.update(1)
                continue

        binary = patch_binary(binary, string, dump_path, False)

        if string.index < 2936:
            progress.update(1)
            os.remove(dump_path)
            continue

        detection_result = scan(dump_path)

        if detection_result:
            print_dbg("Found a bad string, re-masking it", 1)

            with open("current_state.txt", 'a+') as d:
                d.write(repr(string))

            print_dbg(repr(string), 2, False)
            string.is_replaced = True
            string.is_bad = True
            binary = patch_binary(binary, string, dump_path, True)
        else:
            os.remove(dump_path)

        progress.update(1)

    progress.clear()
    progress.close()

    # done, now print results
    bad_strings = list(filter(lambda x: x.is_bad, str_refs))
    print(bad_strings)


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


def chunk(it, size):
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

"""
    TODO: update the progress bar.
    TODO: use a threadpool.
    @param binary binary blob currently edited, all strings hidden
    @param string_refs list of StringRefs objects.
    @param blacklist list of strings' index to never unmask.
"""
def rec_bissect(binary, string_refs, blacklist):

    if type(string_refs) is list and len(string_refs) < 2:
        i = string_refs[0]
        print_dbg(repr(i), LVL_RES_ONLY, False)
        blacklist.append(i.index)
        print("-----> Here is the blacklist")
        print(blacklist)
        return blacklist
    elif type(string_refs) is StringRef:
        print_dbg(repr(string_refs), LVL_RES_ONLY, False)
        blacklist.append(string_refs.index)
        print("-----> Here is the blacklist")
        print(blacklist)
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
            
        else:
            # put the string back
            binary1 = patch_binary(binary1, string, "", mask=False)

    for string in half2:

        #hide all lower half of binary1
        binary1 = patch_binary(binary1, string, "", mask=True)

        if string.index in blacklist:
            # hide blacklisted strings in lower half
            binary2 = patch_binary(binary2, string, "", mask=True)
        else:
            # unhide all lower half of binary2
            binary2 = patch_binary(binary2, string, "", mask=False)
            pass

    dump_path1 = f"/tmp/goat_{half1[0].index}_{str(random.randint(10000,20000))}.bin"
    dump_path2 = f"/tmp/goat_{half2[0].index}_{str(random.randint(10000,20000))}.bin"

    with open(dump_path1, "wb") as f:
        f.write(binary1)

    with open(dump_path2, "wb") as fd:
        fd.write(binary2)

    detection_result1 = scan(dump_path1)
    detection_result2 = scan(dump_path2)
    
    res = detection_result1 or detection_result2

    # the upper half triggers the detection
    if detection_result1:
        print_dbg(f"Signature between half1 {half1[0].index} and {half1[-1].index}", LVL_DETAILS)
        blacklist1 = rec_bissect(binary1, half1, blacklist)
        blacklist = merge_unique(blacklist, blacklist1)

    else:
        print_dbg("Half 1 is not detected", LVL_ALL_DETAILS)

    if detection_result2:
        print_dbg(f"Signature between half2 {half2[0].index} and {half2[-1].index}", LVL_DETAILS)
        blacklist2 = rec_bissect(binary2, half2, blacklist)
        blacklist = merge_unique(blacklist, blacklist2)
    else:
        print_dbg("Half 2 is not detected", LVL_ALL_DETAILS)

    if not res:
        print("Both halves are not detected, len = " + str(len(string_refs)))
        """chunks = chunk(string_refs, 4)
        for i in chunks:
            merge_unique(blacklist, rec_bissect(binary, i, blacklist))"""
        half1 = string_refs[:len(string_refs)//4]
        half2 = string_refs[len(string_refs)//4]
        blacklist = merge_unique(
            blacklist, rec_bissect(binary, half1, blacklist))
        blacklist = merge_unique(
            blacklist, rec_bissect(binary, half2, blacklist))

    return blacklist


def validate_results(sample_file, blacklist, all_strings):

   # mpengine looks for signatures definitions in the current directory.
    os.chdir(WDEFENDER_INSTALL_PATH)

    # read the binary.
    binary = get_binary(sample_file)

    for b in blacklist:
        string = next(filter(lambda x : x.index == b, all_strings))
        print_dbg(f"Removing bad string {repr(string)}", LVL_DETAILS, True)
        binary = patch_binary(binary, string, "", True)

    tmp = tempfile.NamedTemporaryFile()

    with open(tmp.name, "wb") as fd:
        fd.write(binary)

    detection = scan(tmp.name)

    assert(detection is False)
    print_dbg("Validation is ok !", LVL_DETAILS, True)
    


def bissect(sample_file):
    # mpengine looks for signatures definitions in the current directory.
    os.chdir(WDEFENDER_INSTALL_PATH)

    # no point in continuing if the binary is not detected as malicious already.
    assert(scan(sample_file) is True)

    # use rabin2 from radare2 to extract all the strings from the binary
    strings_data = get_all_strings(sample_file)

    # parse rabin2 output
    str_refs = parse_strings(strings_data)

    print(f"We got {len(str_refs)} string objects")

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
    # no point in continuing if Windows Defender detects something else than strings.
    assert(detection_result is False)

    print_dbg("Good, masking all the strings has an impact on the AV's verdict", 0)
    #progress = tqdm(total=len(str_refs), leave=False)

    blacklist = []
    blacklist = rec_bissect(binary1, str_refs, blacklist)

    if len(blacklist) > 0:
        print_dbg(f"Found {len(blacklist)} signatures", LVL_DETAILS, True)
        validate_results(sample_file, blacklist, str_refs)
    else:
        print_dbg("No signatures found...", LVL_DETAILS, True)
    return blacklist


if __name__ == "__main__":

    sample_file = BINARY

    if len(sys.argv) > 1:
        sample_file = sys.argv[1]

    try:
        # explore(sample_file)
        bissect(sample_file)
        print_dbg("[*] Done ! Press any to exit...", 0)

    except KeyboardInterrupt:
        print_dbg("[*] Not done, but here is what I've found so far:", 0)
