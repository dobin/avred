#!/usr/bin/env python

import unittest
import pcodedmp.pcodedmp as pcodedmp
import argparse
import pickle
from analyzer_office import augmentFileWord
from intervaltree import Interval, IntervalTree
from file_office import FileOffice
from utils import printMatches


class OfficeTest(unittest.TestCase):
    def test_disasm(self):
        results = pcodedmp.processFile("tests/data/test.docm")

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
        matches = augmentFileWord(fileOffice, it)

        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertTrue("Ld jypii" in match.detail)
