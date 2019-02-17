# Description

Windows Defender relies on strings, function exports and huge integers to recognize malware.
This project aims at automatically inferring these signatures.

# Project status

Tested and actually working.

# Setup and usage

## Dependencies (Python 3)
python-tqdm
python-hexdump
pytest

## Dependencies (other)
* loadlibrary: Windows Defender scanner ported to Linux by taviso (3 minutes setup, instructions at https://github.com/taviso/loadlibrary)

## Usage

```
python3 find_bad_strings.py ext_server_kiwi.x64.dll
```

# Example output

```
% pytest
========================================== test session starts ==========================================
platform linux -- Python 3.7.2, pytest-4.2.1, py-1.7.0, pluggy-0.8.1
rootdir: /home/vladimir/dev/av-signatures-finder, inifile:
collected 15 items                                                                                      

test_find_bad_strings.py ...............                                                          [100%]

====================================== 15 passed in 23.45 seconds =======================================
pytest  14.52s user 9.36s system 100% cpu 23.741 total

% python3 find_bad_strings.py    
[*] Got 5080 string objects
[*] Good, masking all the strings has an impact on the AV's verdict
[*] Both halves are not detected
[*] Signature between half2 635 and 1269
[*] Signature between half2 952 and 1269
[*] Signature between half1 952 and 1110
[*] Signature between half1 952 and 1030
[*] Signature between half1 952 and 990
[*] Signature between half2 971 and 990
[*] Signature between half1 971 and 980
[*] Signature between half2 976 and 980
[*] Signature between half1 976 and 977
[*] Signature between half2 977 and 977
Found it: StringRef(index=977, paddr=693936, vaddr=6443147952, length=52, size=106, section='(.rdata)', encoding='utf16le', content='Ask a server to set a new password/ntlm for one user', is_replaced=False, is_bad=False)
[*] Signature between half2 1031 and 1110
[*] Signature between half1 1031 and 1070
[*] Signature between half1 1031 and 1050
[*] Signature between half1 1031 and 1040
[*] Signature between half1 1031 and 1035
[*] Signature between half2 1033 and 1035
[*] Signature between half2 1034 and 1035
[*] Signature between half1 1034 and 1034
Found it: StringRef(index=1034, paddr=696000, vaddr=6443150016, length=108, size=218, section='(.rdata)', encoding='utf16le', content='ERROR kuhl_m_lsadump_secretsOrCache ; ntlm hash length must be 32 (16 bytes) - will use default password...\\n', is_replaced=False, is_bad=False)
[*] Signature between half2 1035 and 1035
Found it: StringRef(index=1035, paddr=696224, vaddr=6443150240, length=18, size=38, section='(.rdata)', encoding='utf16le', content='  * password : %s\\n', is_replaced=False, is_bad=False)
Found it: fStringRef(index=1270, paddr=712240, vaddr=6443166256, length=65, size=132, section='(.rdata)', encoding='utf16le', content='ERROR kuhl_m_lsadump_changentlm ; Bad old NTLM hash or password!\\n', is_replaced=False, is_bad=False)
[*] Found 4 signatures
[*] Removing bad string StringRef(index=977, paddr=693936, vaddr=6443147952, length=52, size=106, section='(.rdata)', encoding='utf16le', content='Ask a server to set a new password/ntlm for one user', is_replaced=False, is_bad=False)
[*] Removing bad string StringRef(index=1034, paddr=696000, vaddr=6443150016, length=108, size=218, section='(.rdata)', encoding='utf16le', content='ERROR kuhl_m_lsadump_secretsOrCache ; ntlm hash length must be 32 (16 bytes) - will use default password...\\n', is_replaced=False, is_bad=False)
[*] Removing bad string StringRef(index=1035, paddr=696224, vaddr=6443150240, length=18, size=38, section='(.rdata)', encoding='utf16le', content='  * password : %s\\n', is_replaced=False, is_bad=False)
[*] Removing bad string StringRef(index=1270, paddr=712240, vaddr=6443166256, length=65, size=132, section='(.rdata)', encoding='utf16le', content='ERROR kuhl_m_lsadump_changentlm ; Bad old NTLM hash or password!\\n', is_replaced=False, is_bad=False)
[*] Validation is ok !
[*] [*] Done ! Press any to exit...
python3 find_bad_strings.py  79.02s user 10.75s system 97% cpu 1:32.01 total
```

# How does it work ?

Basically, this is a divide-and-conquer algorithm:
* Assert that the binary is detected by the AV, or else abort.
* Mask all the strings and assert that the AV doesn't flag it anymore, or else abort.
* Unveil half the strings from the start of the file and check if the AV now flags it, if yes, then some bad strings are in this part.
* Repeat for other half.
* Recursively perform the above steps.

