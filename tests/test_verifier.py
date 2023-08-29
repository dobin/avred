import unittest
from model.model_verification import *
from plugins.pe.file_pe import FilePe
from tests.scanners import *
from tests.helpers import TestDetection
from plugins.pe.analyzer_pe import analyzeFilePe
from verifier import verify, getMatchTestsFor
from reducer import Reducer


class VerifierTest(unittest.TestCase):
    def test_verifyresults(self):
        # simple, 1
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")
        detections = []

        # one string in .rodata
        detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff\xff\x68\xb1\xff\xff\x10\xb1\xff") )  # 16 bytes
        detections.append( TestDetection(29824, b"Unknown error\x00\x00\x00") )  # 16 bytes
        scanner = ScannerTest(detections)
        reducer = Reducer(filePe, scanner)
        
        matches, _ = analyzeFilePe(filePe, scanner, reducer)
        self.assertEqual(len(matches), 2)

        verification = verify(filePe, matches, scanner)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)  # 15 bytes
        #self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_SCANNED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.INCREMENTAL, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)  # 15 bytes
        #self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_SCANNED)

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
        reducer = Reducer(filePe, scanner)

        matches, _ = analyzeFilePe(filePe, scanner, reducer)

        for match in matches:
            print(match)

        self.assertTrue(len(matches) == 2)
        for match in matches: 
            print(str(match))

        verification = verify(filePe, matches, scanner)
        print(verification)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.DETECTED)  # 15 bytes
        #self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_SCANNED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.INCREMENTAL, TestMatchModify.MIDDLE8)
        self.assertTrue(matchTests[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_DETECTED)  # 15 bytes
        #self.assertTrue(matchTests[1].scanResult == ScanResult.NOT_SCANNED)

        matchTests = getMatchTestsFor(verification.verifications, TestMatchOrder.DECREMENTAL, TestMatchModify.FULL)
        self.assertTrue(matchTests[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(matchTests[1].scanResult == ScanResult.DETECTED)

        self.assertEqual(verification.matchConclusions.verifyStatus[0], VerifyStatus.ROBUST)
        self.assertEqual(verification.matchConclusions.verifyStatus[1], VerifyStatus.ROBUST)
