import unittest
from model.model import *
from plugins.file_pe import FilePe
from tests.scanners import *
from tests.helpers import TestDetection
from plugins.analyzer_pe import analyzeFileExe
from verifier import verify
from verifyconclusion import verificationAnalyzer


class VerifierTest(unittest.TestCase):
    def test_verifyresults(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
        detections.append( TestDetection(29824, b"Unknown error") )
        scanner = ScannerTest(detections)
        
        matchesIt = analyzeFileExe(filePe, scanner)
        matches = convertMatchesIt(matchesIt)
        self.assertTrue(len(matches) == 2)

        verifications = verify(filePe, matches, scanner)
        verifyConclusion = verificationAnalyzer(verifications)

        # 0 MIDDLE8 ISOLATED  False  False
        # 1 FULL ISOLATED  False  False
        # 2 MIDDLE8 INCREMENTAL  False  False
        # 3 FULL INCREMENTAL  False  False
        # 4 FULL DECREMENTAL  False  False
        self.assertEqual(verifyConclusion.verifyStatus[0], VerifyStatus.GOOD)
        self.assertEqual(verifyConclusion.verifyStatus[1], VerifyStatus.GOOD)


    def test_verifyresults_or(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
        detections.append( TestDetection(29824, b"Unknown error") )
        scanner = ScannerTestOr(detections)
        
        matchesIt = analyzeFileExe(filePe, scanner)
        matches = convertMatchesIt(matchesIt)

        self.assertTrue(len(matches) == 2)
        for match in matches: 
            print(str(match))

        verifications = verify(filePe, matches, scanner)
        for ver in verifications:
            print(str(ver))

        verifyConclusion = verificationAnalyzer(verifications)
        for verRes in verifyConclusion.verifyStatus:
            print(str(verRes))

        # 0 MIDDLE8 ISOLATED    True  True
        # 1 FULL ISOLATED       True  True
        # 2 MIDDLE8 INCREMENTAL True  False
        # 3 FULL INCREMENTAL    True  False
        # 4 FULL DECREMENTAL    False  True
        self.assertEqual(verifyConclusion.verifyStatus[0], VerifyStatus.BAD)
        self.assertEqual(verifyConclusion.verifyStatus[1], VerifyStatus.BAD)
