#!/usr/bin/python3

import pytest
import tempfile
from find_bad_strings import is_all_blacklisted, StringRef, parse_strings, BINARY, get_binary, patch_binary, get_all_strings

import random

def test_is_all_blacklisted():
    strings_refs = []

    for i in range(100):
        tmp = StringRef()
        tmp.index = i
        strings_refs += [tmp]
    
    available_idx = [str_ref.index for str_ref in strings_refs]

    rnd_blacklist = random.choices(available_idx, k=random.randint(0,len(available_idx)//2))

    assert not (is_all_blacklisted(strings_refs, rnd_blacklist))

    assert is_all_blacklisted(strings_refs, available_idx)

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
    strings_refs = parse_strings(data_blob)

    assert len(strings_refs) == 8
    assert strings_refs[-1].index == 7
    assert strings_refs[0].index == 0
    assert strings_refs[7].length == 36

def test_patch_binary():
    string = "000 0x00099640 0x18009a240  13  14 (.rdata) ascii kiwi_exec_cmd"    
    string_ref = parse_strings(string)
    assert string_ref[0].index == 0
    assert string_ref[0].content == "kiwi_exec_cmd"
    binary = get_binary("test_cases/ext_server_kiwi.x64.dll")
    tmp_bin = tempfile.NamedTemporaryFile()
    new_binary = patch_binary(binary, string_ref[0], tmp_bin.name, True)
    all_strings = get_all_strings(tmp_bin.name)
    all_strings_ref = parse_strings(all_strings)
    assert all_strings_ref[0].content != string_ref[0].content
    assert not(any(string_ref[0].content in string.content for string in all_strings_ref))
    
    patch_binary(binary, string_ref[0], tmp_bin.name, False)
    all_strings = get_all_strings(tmp_bin.name)
    all_strings_ref = parse_strings(all_strings)
    tmp_bin.close()
    assert all_strings_ref[0].content == string_ref[0].content
