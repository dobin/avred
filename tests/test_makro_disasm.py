#!/usr/bin/env python

import unittest
import pcodedmp.pcodedmp as pcodedmp
from plugins.analyzer_office import augmentFileWord
from intervaltree import Interval, IntervalTree
from plugins.file_office import FileOffice, VbaAddressConverter
import olefile

class DisasmMakroTest(unittest.TestCase):
    def test_addressConverter(self):
        # Only the VbaAddressConverter
        file = 'tests/data/test.docm.vbaProject.bin'
        ole = olefile.OleFileIO(file)

        ac = VbaAddressConverter(ole)

        self.assertEqual(ac.physicalAddressFor("VBA/NewMacros", 0), 4224)

        # VBA/NewMacros: virt:1092 phys:5316 line:7 
        #    0020 Ld msg 
        #    0041 ArgsCall MsgBox 0x0001 
        # 
        # % hexdump -s 5316 -n 16 -C test.docm.vbaProject.bin
        # 000014c4  20 00 36 02 41 40 34 02  01 00 00 00 78 00 00 00  | .6.A@4.....x...|
        self.assertEqual(ac.physicalAddressFor("VBA/NewMacros", 1092), 5316)


    def test_disasm(self):
        # Only the Pcodedmp dumping, docm
        results = pcodedmp.processFile("tests/data/test.docm")

        itemSet = results[0].at(1004)
        self.assertTrue(len(itemSet) == 1)
        item = next(iter(itemSet))
        self.assertEqual(item.begin, 1004)
        self.assertEqual(item.end, 1010)
        self.assertEqual(item.data.lineNr, 0)
        self.assertTrue("FuncDefn (Sub Auto_Open())" in item.data.text)


    def test_augment(self):
        # pcodedmp with VbaAddressConverter
        filename = "tests/data/test.docm"
        fileOffice = FileOffice()
        fileOffice.loadFromFile(filename)

        # 7 5316 5326: 
        #	0020 Ld msg 
        #	0041 ArgsCall MsgBox 0x0001 

        it = IntervalTree()
        it.add(Interval(5316, 5316+16))
        matches = augmentFileWord(fileOffice, it)

        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertTrue("Ld msg" in match.detail)
        self.assertTrue("ArgsCall MsgBox 0x0001" in match.detail)
