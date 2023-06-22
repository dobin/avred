import unittest
from plugins.office.analyzer_office import analyzeFileWord
from model.model import Scanner
from tests.helpers import TestDetection
from pprint import pprint
from plugins.office.file_office import FileOffice
from scanner import ScannerRest
from model.model import Data
from plugins.model import BaseFile


class ModelTest(unittest.TestCase):
    def testFile(self):
        file = BaseFile()
        orig = b'AAAABBBBCCCCDDDD'
        new = b'AA\x00\x00\x00\x00BBCCCCDDDD'

        file.loadFromMem(orig, "test.bin")
        file.Data().hidePart(offset=2, size=4)

        patched = file.DataAsBytes()
        self.assertEqual(patched, new)
