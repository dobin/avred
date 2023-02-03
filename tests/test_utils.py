#!/usr/bin/env python

import unittest
from utils import *


class DotnetDisasmTest(unittest.TestCase):
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