#!/usr/bin/env python

import unittest
import pcodedmp.pcodedmp as pcodedmp
import argparse
import pickle
from analyzer_office import augmentMatches
from intervaltree import Interval, IntervalTree
from file_office import FileOffice
from utils import printMatches

class OfficeTest(unittest.TestCase):
    def test_disasm(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-n', '--norecurse', action='store_true',
                            help="Don't recurse into directories")
        parser.add_argument('-d', '--disasmonly', dest='disasmOnly', action='store_true',
                            help='Only disassemble, no stream dumps')
        parser.add_argument('-b', '--verbose', action='store_true',
                            help='Dump the stream contents')
        parser.add_argument('-o', '--output', dest='outputfile', default=None,
                            help='Output file name')
        args = parser.parse_args()

        results = pcodedmp.processFile("tests/data/test.docm", args)

        itemSet = results[0].at(1004)
        self.assertTrue(len(itemSet) == 1)
        item = next(iter(itemSet))
        self.assertEqual(item.begin, 1004)
        self.assertEqual(item.end, 1010)
        self.assertEqual(item.data.lineNr, 0)
        self.assertTrue("FuncDefn (Sub Auto_Open())" in item.data.text)


    def test_augment(self):
        base = "tests/data/P5-5h3ll.docm"

        fileOffice = FileOffice()
        fileOffice.loadFromFile(base)
        
        it = IntervalTree()
        it.add(Interval(1824, 1976))

        matches = augmentMatches(fileOffice, it)

        self.assertEqual(len(matches), 1)
        match = matches[0]
        print(str(match))

        self.assertTrue("Ld jypii" in match.detail)