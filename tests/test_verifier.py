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

        self.assertTrue(verifications[0].testEntries[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(verifications[0].testEntries[1].scanResult == ScanResult.NOT_DETECTED)

        self.assertTrue(verifications[2].testEntries[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(verifications[2].testEntries[1].scanResult == ScanResult.NOT_DETECTED)

        self.assertTrue(verifications[3].testEntries[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(verifications[3].testEntries[1].scanResult == ScanResult.NOT_DETECTED)

        verifyConclusion = verificationAnalyzer(verifications)
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

        self.assertTrue(verifications[0].testEntries[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(verifications[0].testEntries[1].scanResult == ScanResult.DETECTED)

        self.assertTrue(verifications[2].testEntries[0].scanResult == ScanResult.DETECTED)
        self.assertTrue(verifications[2].testEntries[1].scanResult == ScanResult.NOT_DETECTED)

        self.assertTrue(verifications[4].testEntries[0].scanResult == ScanResult.NOT_DETECTED)
        self.assertTrue(verifications[4].testEntries[1].scanResult == ScanResult.DETECTED)


        verifyConclusion = verificationAnalyzer(verifications)
        self.assertEqual(verifyConclusion.verifyStatus[0], VerifyStatus.OK)
        self.assertEqual(verifyConclusion.verifyStatus[1], VerifyStatus.OK)
