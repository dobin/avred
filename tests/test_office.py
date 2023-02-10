#!/usr/bin/env python

import unittest
from plugins.analyzer_office import analyzeFileWord
from model.extensions import Scanner
from tests.helpers import TestDetection
from pprint import pprint
from plugins.file_office import FileOffice
from scanner import ScannerRest


class OfficeTest(unittest.TestCase):
    def testDocx(self):
        fileOffice = FileOffice()
        fileOffice.loadFromFile("tests/data/test.docm")
        detections = []
        detections.append( TestDetection(10656, b"e VB_Nam\x00e = ") )

        scanner = ScannerTestDocx(detections)
        matches = analyzeFileWord(fileOffice, scanner)
        # [Interval(0, 13312)]
        self.assertTrue(len(matches) == 1)


class ScannerTestDocx(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)


    def scan(self, data, filename):
        # unpack office file
        fileOffice = FileOffice()
        fileOffice.loadFromMem(data)

        for detection in self.detections:
            data = fileOffice.data[detection.refPos:detection.refPos+len(detection.refData)] 
            if data != detection.refData:
                return False

        return True

