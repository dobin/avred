#!/usr/bin/env python

import unittest
from webbrowser import get
from plugins.analyzer_pe import analyzeFileExe
from tests.helpers import TestDetection
from plugins.file_pe import FilePe
from tests.scanners import *


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
