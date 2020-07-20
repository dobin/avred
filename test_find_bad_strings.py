#!/usr/bin/python3

import pytest
import unittest.mock
import tempfile
import find_bad_strings as fbs
import hashlib
import os
import shutil
import random

def test_is_all_blacklisted():
    strings_refs = []

    for i in range(100):
        tmp = fbs.StringRef()
        tmp.index = i
        strings_refs += [tmp]

    available_idx = [str_ref.index for str_ref in strings_refs]

    rnd_blacklist = random.choices(available_idx, k=random.randint(0,len(available_idx)//2))

    assert not (fbs.is_all_blacklisted(strings_refs, rnd_blacklist))

    assert fbs.is_all_blacklisted(strings_refs, available_idx)

def test_parse_strings():
    data_blob = """[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x00099640 0x18009a240  13  14 (.rdata) ascii kiwi_exec_cmd
001 0x00099650 0x18009a250   4   5 (.rdata) ascii kiwi
002 0x00099658 0x18009a258  27  56 (.rdata) utf16le \nmimikatz(powershell) # %s\n
003 0x00099690 0x18009a290   5  12 (.rdata) utf16le hello
004 0x000996a0 0x18009a2a0  50 102 (.rdata) utf16le ERROR mimikatz_initOrClean ; CoInitializeEx: %08x\n
005 0x00099708 0x18009a308   4  10 (.rdata) utf16le INIT
006 0x00099718 0x18009a318   5  12 (.rdata) utf16le CLEAN
007 0x00099730 0x18009a330  36  74 (.rdata) utf16le >>> %s of '%s' module failed : %08x\n"""
    strings_refs = fbs.parse_strings(data_blob)

    assert len(strings_refs) == 8
    assert strings_refs[-1].index == 7
    assert strings_refs[0].index == 0
    assert strings_refs[7].length == 36

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def test_patch_binary():
    string = "3122 0x000cef20 0x1800cfb20 23  48   .rdata  utf16le \\pipe\\protected_storage"
    string_ref = fbs.StringRef(3122, 0x000cef20, 0x1800cfb20, 23, 48, ".rdata", "utf16le", "\pipe\protected_storage")
    string_ref.should_mask = True
    index = int(string.split()[0])
    assert string_ref.index == index
    assert string_ref.content == "\pipe\protected_storage"
    md5_before = md5("test_cases/ext_server_kiwi.x64.dll")
    tmp_bin = tempfile.NamedTemporaryFile()
    shutil.copyfile("test_cases/ext_server_kiwi.x64.dll", tmp_bin.name)
    print("tmp file name = " + tmp_bin.name)
    filename = tmp_bin.name
    all_strings_ref = fbs.parse_strings(filename)
    len_strings_before = len(all_strings_ref)

    # replace the string with something else
    fbs.patch_string(filename, string_ref, unmask_only=False)
    all_strings_ref2 = fbs.parse_strings(filename)

    assert(len(all_strings_ref2) == len_strings_before)
    # check that the replacement worked
    assert all_strings_ref2[index].content != string_ref.content
    print(f"Replaced by : {all_strings_ref2[index].content}")

    # check that no other string contains this value (in case offsets are wrong)
    assert not(any(string_ref.content in string.content for string in all_strings_ref2))

    # re-set the string
    string_ref.should_mask = False
    all_strings_ref[index].should_mask = False
    #fbs.patch_string(filename, string_ref, unmask_only=False)
    fbs.patch_string(filename, all_strings_ref[index], unmask_only=False)
    all_strings_ref = fbs.parse_strings(filename)

    # check that the original string was put back
    string = all_strings_ref[index].content
    assert all_strings_ref[index].content == string_ref.content
    new_md5 = md5(filename)

    # check files are the same
    assert md5_before == new_md5
    tmp_bin.close()
    pass


"""
    replace the actual scan with Windows Defender by a
    fake one, so as to check if the bissection algorithm works
    as expected.
"""
def mock_scan(filepath):
    #return True
    all_strings_ref = fbs.parse_strings(filepath)
    known_strings = ['Ask a privilege by its id', 'RUUU', 'CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID', 'text', 'LocalAlloc', 'viewstack', '0000//...-', 'CERT_SUBJECT_NAME_MD5_HASH_PROP_ID', 'HeapReAlloc', 'Preshutdown service']


    ##return any(s.content in known_strings for s in all_strings_ref)
    for i in all_strings_ref:
        if i.content in known_strings:
            print(f"---> Found bad string {i.content} at index {i.index}, address = {i.paddr}")
            return True
    return False

@unittest.mock.patch("find_bad_strings.scan", side_effect=mock_scan)
@unittest.mock.patch("find_bad_strings.os.chdir")
#@unittest.mock.patch("find_bad_strings.validate_results")
def test_bissection(mock_scan, mock_chdir):
    """known_strings = ["Pass-the-ccache [NT6]",
            "ERROR kuhl_m_crypto_l_certificates ; CryptAcquireCertificatePrivateKey (0x%08x)\\n",
            "ERROR kuhl_m_crypto_l_certificates ; CertGetCertificateContextProperty (0x%08x)\\n",
            "ERROR kuhl_m_crypto_l_certificates ; CertGetNameString (0x%08x)\\n",
            "lsasrv.dll",
            "ERROR kuhl_m_lsadump_sam ; CreateFile (SYSTEM hive) (0x%08x)\\n",
            "SamIFree_SAMPR_USER_INFO_BUFFER",
            "KiwiAndRegistryTools",
            "wdigest.dll",
            "multirdp",
            "logonPasswords",
            "credman",
            "[%x;%x]-%1u-%u-%08x-%wZ@%wZ-%wZ.%s",
            "n.e. (KIWI_MSV1_0_CREDENTIALS KO)"]
    """

    known_strings = ['Ask a privilege by its id', 'RUUU', 'CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID', 'text', 'LocalAlloc', 'viewstack', '0000//...-', 'CERT_SUBJECT_NAME_MD5_HASH_PROP_ID', 'HeapReAlloc', 'Preshutdown service']

    tmp = tempfile.NamedTemporaryFile()
    shutil.copyfile("test_cases/ext_server_kiwi.x64.dll", tmp.name)

    fbs.ORIGINAL_BINARY = "test_cases/ext_server_kiwi.x64.dll"
    blacklist = fbs.bissect(tmp.name)
    assert len(blacklist) > 0
    all_strings_ref = fbs.parse_strings("test_cases/ext_server_kiwi.x64.dll")

    try:
        for i in blacklist:
            assert all_strings_ref[i].index == i
            assert all_strings_ref[i].content in known_strings

        for str in known_strings:
            assert any(str in x.content for x in all_strings_ref)
        #assert len(blacklist) == len(known_strings)

    except AssertionError:
        print(blacklist)
        for i in blacklist:
            print(list(filter(lambda x: x.index == i, all_strings_ref)))
        raise AssertionError


@pytest.mark.parametrize('list1,list2,output', [
    ([], [1], [1]),
    ([1], [1], [1]),
    ([2,3], [4], [2,3,4]),
    ([2,3,34,3], [1,0,3,1,1,1], [0,1,2,3,34])])
def test_merge_unique(list1, list2, output):
    assert fbs.merge_unique(list1, list2) == output

def test_merge_unique_param_return():
    toto = [1,2,3,4,5,6]
    res = []
    for i in toto:
        res = fbs.merge_unique(res, [i])
    assert res == toto


@pytest.mark.parametrize('list1,list2,output', [
    ([], [1], False),
    ([1], [1], True),
    ([2, 3], [4], False),
    ([2, 3, 34, 3], [1, 0, 3, 1, 1, 1], False),
    ([4,3,2], [2,3,4], True)])
def test_is_equal_unordered(list1, list2, output):
    assert fbs.is_equal_unordered(list1, list2) == output

def test_validate_results():
    all_strings = fbs.get_all_strings("test_cases/ext_server_kiwi.x64.dll")
    all_strings_ref = fbs.parse_strings(all_strings)

    blacklist = [x.index for x in all_strings_ref]

    fbs.validate_results(fbs.BINARY, blacklist, all_strings_ref)

def test_hide_section():
    filepath = os.path.abspath("test_cases/ext_server_kiwi.x64.dll")

    binary = fbs.get_binary(filepath)
    fbs.hide_section(".text", filepath, binary)
