#!/usr/bin/env python

import unittest
from pprint import pprint

from plugins.office.analyzer_office import analyzeFileWord
from plugins.office.file_office import FileOffice
from model.model_base import Scanner
from tests.helpers import TestDetection
from reducer import Reducer


class OfficeTest(unittest.TestCase):
    def testDocx(self):
        fileOffice = FileOffice()
        fileOffice.loadFromFile("tests/data/test.docm")
        detections = []
        detections.append( TestDetection(10656, b"e VB_Nam\x00e = ") )

        scanner = ScannerTestDocx(detections)
        reducer = Reducer(fileOffice, scanner)
        matches, _ = analyzeFileWord(fileOffice, scanner, reducer)
        # [Interval(0, 13312)]
        self.assertTrue(len(matches) == 1)


class ScannerTestDocx(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)


    def scannerDetectsBytes(self, data, filename):
        # unpack office file
        fileOffice = FileOffice()
        fileOffice.loadFromMem(data)

        for detection in self.detections:
            data = fileOffice.Data().getBytesRange(detection.refPos, detection.refPos+len(detection.refData))
            if data != detection.refData:
                return False

        return True

