#!/usr/bin/env python

import unittest
import pcodedmp.pcodedmp as pcodedmp
from plugins.office.augment_office import augmentFileWord
from plugins.office.file_office import FileOffice, OleStructurizer, VbaAddressConverter
import olefile
from model.model import Match


class DisasmMakroTest(unittest.TestCase):
    def test_VbaAddressConverterMiniStream(self):
        # Only the VbaAddressConverter
        file = 'tests/data/test.docm.vbaProject.bin'
        with olefile.OleFileIO(file) as ole:
            ac = VbaAddressConverter(ole)
            self.assertEqual(ac.physicalAddressFor("VBA/NewMacros", 0), 4224)
            # VBA/NewMacros: virt:1092 phys:5316 line:7 
            #    0020 Ld msg 
            #    0041 ArgsCall MsgBox 0x0001 
            # 
            # % hexdump -s 5316 -n 16 -C test.docm.vbaProject.bin
            # 000014c4  20 00 36 02 41 40 34 02  01 00 00 00 78 00 00 00  | .6.A@4.....x...|
            self.assertEqual(ac.physicalAddressFor("VBA/NewMacros", 1092), 5316)


    def test_VbaAddressConverterStream(self):
        # Only the VbaAddressConverter
        file = 'tests/data/word.docm.vbaProject.bin'
        with olefile.OleFileIO(file) as ole:
            ac = VbaAddressConverter(ole)
            self.assertEqual(ac.physicalAddressFor("VBA/ThisDocument", 0), 6144)
            self.assertEqual(ac.physicalAddressFor("VBA/ThisDocument", 1024), 7168)
            self.assertEqual(ac.physicalAddressFor("VBA/ThisDocument", 1024+1), 7168+1)

            self.assertEqual(ac.physicalAddressFor("VBA/ThisDocument", 4093), 10237)
            self.assertEqual(ac.physicalAddressFor("VBA/ThisDocument", 4125), 10269)


    def test_AddressConverterGetSection(self):
        file = 'tests/data/test.docm.vbaProject.bin'
        with olefile.OleFileIO(file) as ole:
            ac = OleStructurizer(ole)
            self.assertEqual(ac.getSectionForAddr(0), "Header")
            self.assertEqual(ac.getSectionForAddr(1), "Header")
            self.assertEqual(ac.getSectionForAddr(512), "FAT Sector")
            self.assertEqual(ac.getSectionForAddr(513), "FAT Sector")
            self.assertEqual(ac.getSectionForAddr(3072), "ThisDocument")
            self.assertEqual(ac.getSectionForAddr(3572), "__SRP_2")


    def test_AddressConverterGetSections(self):
        file = 'tests/data/test.docm.vbaProject.bin'
        with olefile.OleFileIO(file) as ole:
            ac = OleStructurizer(ole)
            
            sections = ac.getSectionsForAddr(3584, 1024)
            print(str(sections))
            self.assertEqual(len(sections), 3)
            self.assertTrue('Directory' in sections)
            self.assertTrue('__SRP_3' in sections)
            self.assertTrue('NewMacros' in sections)


    def test_disasm_pcodedmp(self):
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

        # VBA/NewMacros: 1092 1102 7 
        #   Ld msg 
        #   ArgsCall MsgBox 0x0001 
        # -> 5316

        matches = []
        match = Match(0, 5316, 16)
        matches.append(match)
        augmentFileWord(fileOffice, matches)

        self.assertEqual(len(matches), 1)
        match = matches[0]
        detail = match.getDisasmLines()[0].textHtml
        self.assertTrue("Ld msg" in detail)
        self.assertTrue("ArgsCall MsgBox 0x0001" in detail)
