#!/usr/bin/env python

import unittest
from webbrowser import get
from plugins.analyzer_pe import analyzeFileExe
from tests.helpers import TestDetection
from plugins.file_pe import FilePe
from plugins.analyzer_pe import augmentFilePe, disassemble
from plugins.outflank_pe import outflankPe
from tests.scanners import *
from model.model import Match, OutflankPatch
from model.testverify import MatchConclusion, VerifyStatus
from utils import hexdmp, hexstr, removeAnsi
import r2pipe


class PeTest(unittest.TestCase):
    def test_pe0(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(29824, b"Unknown error") )
        scanner = ScannerTest(detections)
        
        matches, _ = analyzeFileExe(filePe, scanner)
        # A: [Interval(29808, 29864)]
        self.assertTrue(len(matches) == 1)


    def test_pe1(self):
        # simple, merge 2-OR
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []
        
        # TODO PROBLEM with this one
        detections.append( TestDetection(30810, b"\xff\xff\x10\xb1\xff\xff\xc2\xb2\xff\xff") )
        # WORKS
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
        scanner = ScannerTest(detections)
        
        matches, _ = analyzeFileExe(filePe, scanner)
        # A: [Interval(30809, 30844)]
        self.assertTrue(len(matches) == 1)


    def test_pe2(self):
        # 2 sections OR
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []
        # .rodata
        detections.append( TestDetection(29824, b"Unknown error") )
        # .text
        detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
        scanner = ScannerTest(detections)

        matches, _ = analyzeFileExe(filePe, scanner)
        # A: [Interval(1644, 1698), Interval(29808, 29864)]
        self.assertTrue(len(matches) == 2)


    def test_pe3(self):
        # two in one section OR
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []
        # .rodata
        detections.append( TestDetection(29824, b"Unknown error") )
        detections.append( TestDetection(31850, b" 10.2.0") )
        # .text
        #detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
        scanner = ScannerTest(detections)

        matches, _ = analyzeFileExe(filePe, scanner)
        # A: [Interval(29808, 29864), Interval(31824, 31880)]
        self.assertTrue(len(matches) == 2)


    def test_pe4(self):
        # weighted (at least half)
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []
        # .rodata
        detections.append( TestDetection(29824, b"Unknown error") )
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
        detections.append( TestDetection(31850, b" 10.2.0") )
        detections.append( TestDetection(33150, b"\x00\x00\x47\x43\x43\x3a\x20") )

        scanner = ScannerTestWeighted(detections)

        matches, _ = analyzeFileExe(filePe, scanner)
        # A: [Interval(29808, 29864), Interval(30816, 30844), Interval(31824, 31880), Interval(33140, 33168)]
        self.assertTrue(len(matches) == 4)


    def test_disasm(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        # 0x004014e0
        start = 2807  # AF7
        size = 8
        matchAsmInstructions, matchDisasmLines = disassemble(
            r2, filePe, start, size, moreUiLines=0)

        #for a in matchDisasmLines:
        #    print(a)
        
        self.assertEqual(start, matchDisasmLines[0].offset)
        self.assertEqual(0x004014f7, matchDisasmLines[0].rva)
        self.assertTrue('nop' in removeAnsi(matchDisasmLines[0].text))
        self.assertTrue('add rsp, 0x28' in removeAnsi(matchDisasmLines[1].text))
        self.assertTrue('ret' in removeAnsi(matchDisasmLines[2].text))
        
        self.assertEqual(start, matchAsmInstructions[0].offset)
        self.assertEqual(0x004014f7, matchAsmInstructions[0].rva)
        self.assertEqual('nop', matchAsmInstructions[0].disasm)
        self.assertEqual('add rsp, 0x28', matchAsmInstructions[1].disasm)
        self.assertEqual('ret', matchAsmInstructions[2].disasm)
        

    def test_disasm_swap(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        self.assertEqual(0x004014f7, filePe.offsetToRva(2807))
        self.assertEqual(2807, filePe.codeRvaToOffset(0x004014f7))

        # 0x004014e0
        start = 2807  # AF7
        size = 8
        matchAsmInstructions, matchDisasmLines = disassemble(
            r2, filePe, start, size, moreUiLines=0)
        
        # 0x004014f7      90             nop
        # 0x004014f8      4883c428       add rsp, 0x28
        # 0x004014fc      c3             ret
        self.assertTrue('nop' in removeAnsi(matchDisasmLines[0].text))
        self.assertTrue('add rsp, 0x28' in removeAnsi(matchDisasmLines[1].text))
        self.assertTrue('ret' in removeAnsi(matchDisasmLines[2].text))

        filePe.data.swapData(2807, 1, 2807+1, 4)

        self.assertEqual(filePe.data.getBytesRange(2807, 2807+4), b"\x48\x83\xc4\x28")
        self.assertEqual(filePe.data.getBytesRange(2807+4, 2807+4+1), b"\x90")
        #matchAsmInstructions, matchDisasmLines = disassemble(
        #    r2, filePe, start, size, moreUiLines=0)
        #self.assertEqual('nop', matchAsmInstructions[1].disasm)
        #self.assertEqual('add rsp, 0x28', matchAsmInstructions[0].disasm)
        #self.assertEqual('ret', matchAsmInstructions[2].disasm)


    def test_disasm_outflank(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        fileOffset = filePe.codeRvaToOffset(0x0040154e)
        matchAsmInstructions, _ = disassemble(
            r2, filePe, fileOffset, 5, moreUiLines=0)
        
        # 0x0040154e      48894dd0       mov qword [var_30h], rcx    ; format
        # 0x00401552      488955d8       mov qword [var_28h], rdx    ; arg2
        # 0x00401556      4c8945e0       mov qword [var_20h], r8     ; arg3
        # 0x0040155a      4c894de8       mov qword [var_18h], r9     ; arg4
        #for entry in matchDisasmLines:
        #    print(entry)

        self.assertEqual(len(matchAsmInstructions), 5)

        #for entry in matchAsmInstructions:
        #    print(entry)

        matches = []
        match = Match(0, fileOffset, 8)
        matches.append(match)
        verifyStatus = [ VerifyStatus.GOOD ]
        matchConclusion = MatchConclusion(verifyStatus)
        augmentFilePe(filePe, matches)
        patches = outflankPe(filePe, matches, matchConclusion)
        #for patch in patches:
        #    print(patch)

        self.assertEqual(patches[0].offset, 2894)
        self.assertEqual(patches[1].offset, 2902)
        self.assertEqual(patches[2].offset, 2914)
