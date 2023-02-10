#!/usr/bin/env python

import unittest
from utils import *
from plugins.file_pe import FilePe
from utils import getFileInfo

class UtilsTest(unittest.TestCase):
    def test_magic(self):
        filename = "tests/data/dotnet-test.dll"
        type = GetFileType(filename) 
        self.assertEqual(type, FileType.EXE) # DOTNET

        filename = "tests/data/P5-5h3ll.docm"
        type = GetFileType(filename) 
        self.assertEqual(type, FileType.OFFICE)

        filename = "tests/data/test.exe"
        type = GetFileType(filename) 
        self.assertEqual(type, FileType.EXE)


    def test_fileInfo(self):
        file = FilePe()
        file.loadFromFile('tests/data/test.exe')

        fileInfo = getFileInfo(file, FileType.EXE, '')

        self.assertEqual(fileInfo.name, 'test.exe')
        self.assertEqual(fileInfo.size, 89062)
        self.assertEqual(fileInfo.hash, b'\xcai\xed\x146.\xfe\x01\xb0|\x9a\xd4uv\x07\xd1')
