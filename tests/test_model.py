import unittest
from plugins.analyzer_office import analyzeFileWord
from model.extensions import Scanner
from tests.helpers import TestDetection
from pprint import pprint
from plugins.file_office import FileOffice
from scanner import ScannerRest
from model.model import Data
from model.extensions import PluginFileFormat


class ModelTest(unittest.TestCase):
    def testFile(self):
        file = PluginFileFormat()
        orig = b'AAAABBBBCCCCDDDD'
        new = b'AA\x00\x00\x00\x00BBCCCCDDDD'

        file.loadFromMem(orig, "test.bin")
        file.Data().hidePart(offset=2, size=4)

        patched = file.DataAsBytes()
        self.assertEqual(patched, new)
