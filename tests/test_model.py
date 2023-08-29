import unittest
from model.file_model import BaseFile


class ModelTest(unittest.TestCase):
    def testFile(self):
        file = BaseFile()
        orig = b'AAAABBBBCCCCDDDD'
        new = b'AA\x00\x00\x00\x00BBCCCCDDDD'

        file.loadFromMem(orig, "test.bin")
        file.Data().hidePart(offset=2, size=4)

        patched = file.DataAsBytes()
        self.assertEqual(patched, new)
