#!/usr/bin/python3

import pytest
import unittest.mock
import tempfile
import find_bad_strings as fbs
import hashlib

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
    string = "000 0x00099640 0x18009a240  13  14 (.rdata) ascii kiwi_exec_cmd"
    string_ref = fbs.parse_strings(string)
    assert string_ref[0].index == 0
    assert string_ref[0].content == "kiwi_exec_cmd"
    binary = fbs.get_binary("test_cases/ext_server_kiwi.x64.dll")
    md5_before = md5("test_cases/ext_server_kiwi.x64.dll")
    tmp_bin = tempfile.NamedTemporaryFile()
    print("tmp file name = " + tmp_bin.name)
    filename = tmp_bin.name
    new_binary = fbs.patch_binary(binary, string_ref[0], filename, True)
    all_strings = fbs.get_all_strings(filename)
    all_strings_ref = fbs.parse_strings(all_strings)
    assert all_strings_ref[0].content != string_ref[0].content
    print(f"Replaced by : {all_strings_ref[0].content}")
    assert not(any(string_ref[0].content in string.content for string in all_strings_ref))
    
    fbs.patch_binary(binary, string_ref[0], filename, False)
    all_strings = fbs.get_all_strings(filename)
    all_strings_ref = fbs.parse_strings(all_strings)
    assert all_strings_ref[0].content == string_ref[0].content
    new_md5 = md5(filename)
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
    all_strings = fbs.get_all_strings(filepath)
    all_strings_ref = fbs.parse_strings(all_strings)
    known_strings = ["Pass-the-ccache [NT6]",
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

    ##return any(s.content in known_strings for s in all_strings_ref)
    for i in all_strings_ref:
        if i.content in known_strings:
            print(f"---> Found bad string {i.content} at index {i.index}, address = {i.paddr}")
            return True
        elif "kuhl_m_crypto_l_certificates" in i.content:
            print(f"Look found it: {repr(i)}")
    return False

@unittest.mock.patch("find_bad_strings.scan", side_effect=mock_scan)
@unittest.mock.patch("find_bad_strings.os.chdir")
def test_bissection(mock_scan, mock_chdir):
    known_strings = ["Pass-the-ccache [NT6]",
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
    blacklist = fbs.bissect("test_cases/ext_server_kiwi.x64.dll")
    assert len(blacklist) > 0
    all_strings = fbs.get_all_strings("test_cases/ext_server_kiwi.x64.dll")
    all_strings_ref = fbs.parse_strings(all_strings)

    try:
        for i in blacklist:
            assert all_strings_ref[i].index == i
            assert all_strings_ref[i].content in known_strings

        assert len(blacklist) == len(known_strings)
    
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