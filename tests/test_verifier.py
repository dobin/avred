import unittest
from model.testverify import *
from plugins.file_pe import FilePe
from tests.scanners import *
from tests.helpers import TestDetection
from plugins.analyzer_pe import analyzeFileExe
from verifier import verify, verificationAnalyzer, getMatchTestsFor
from utils import convertMatchesIt


class VerifierTest(unittest.TestCase):
    def test_verifyresults(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff\xff\x68\xb1\xff\xff\x10\xb1\xff") )
        detections.append( TestDetection(29824, b"Unknown error\x00\x00\x00") )
        scanner = ScannerTest(detections)
        
        matchesIt, _ = analyzeFileExe(filePe, scanner)
        matches = convertMatchesIt(matchesIt)
        self.assertEqual(len(matches), 2)

        verification = verify(filePe, matches, scanner)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.INCREMENTAL, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.INCREMENTAL, TestMatchModify.FULL)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)

        self.assertEqual(verification.matchConclusions.verifyStatus[0], VerifyStatus.DOMINANT)
        self.assertEqual(verification.matchConclusions.verifyStatus[1], VerifyStatus.DOMINANT)


    def test_verifyresults_or(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff\xff\x68\xb1\xff\xff\x10\xb1\xff") )
        detections.append( TestDetection(29824, b"Unknown error\x00\x00\x00") )
        scanner = ScannerTestOr(detections)
        
        matchesIt, _ = analyzeFileExe(filePe, scanner)
        matches = convertMatchesIt(matchesIt)

        self.assertTrue(len(matches) == 2)
        for match in matches: 
            print(str(match))

        verification = verify(filePe, matches, scanner)
        print(verification)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.DETECTED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.INCREMENTAL, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.DECREMENTAL, TestMatchModify.FULL)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.DETECTED)

        self.assertEqual(verification.matchConclusions.verifyStatus[0], VerifyStatus.ROBUST)
        self.assertEqual(verification.matchConclusions.verifyStatus[1], VerifyStatus.ROBUST)
