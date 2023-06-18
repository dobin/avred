from copy import deepcopy
from utils import FillType
import logging
from typing import List

from model.model import *
from model.extensions import PluginFileFormat


def toTestEntry(scanIndex, result):
    scanResult = ScanResult.NOT_SCANNED
    if not result:
        scanResult = ScanResult.NOT_DETECTED
    else: 
        scanResult = ScanResult.DETECTED

    testEntry = MatchTest(scanIndex, scanResult)
    return testEntry


def getMatchTestsFor(verifications: List[VerificationEntry], matchOrder: TestMatchOrder, matchModify: TestMatchModify):
        for verification in verifications:
            if verification.info == matchOrder and verification.type == matchModify:
                return verification.matchTests
        return None


def verify(file: PluginFileFormat, matches: List[Match], scanner) -> Verification:
    """Verify matches in file with scanner, and return the result"""
    verifications = runVerifications(file, matches, scanner)
    matchConclusions = verificationAnalyzer(verifications)
    verify = Verification(verifications, matchConclusions)
    return verify


def verificationAnalyzer(verifications: List[VerificationEntry]) -> MatchConclusion:
    """Do some analysis on the verifications, and return the result"""
    verifyResults = []
    if len(verifications) == 0:
        matchConclusions = MatchConclusion(verifyResults)
        return matchConclusions

    matchCount = len(verifications[0].matchTests)
    idx = 0
    while idx < matchCount:
        result = getMatchTestsFor(verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)[idx].scanResult
        if result is ScanResult.NOT_DETECTED or result is ScanResult.NOT_SCANNED:
            middle8 = True
        else:
            middle8 = False
        
        result = getMatchTestsFor(verifications, TestMatchOrder.ISOLATED, TestMatchModify.THIRDS8)[idx].scanResult
        if result is ScanResult.NOT_DETECTED or result is ScanResult.NOT_SCANNED:
            thirds8 = True
        else:
            thirds8 = False

        result = getMatchTestsFor(verifications, TestMatchOrder.ISOLATED, TestMatchModify.FULL)[idx].scanResult
        if result is ScanResult.NOT_DETECTED or result is ScanResult.NOT_SCANNED:
            full = True
        else:
            full = False

        if middle8 or thirds8:
            res = VerifyStatus.GOOD
        elif full:
            res = VerifyStatus.OK
        else:
            res = VerifyStatus.BAD

        verifyResults.append(res)
        idx += 1

    matchConclusions = MatchConclusion(verifyResults)
    return matchConclusions


def runVerifications(file: PluginFileFormat, matches: List[Match], scanner) -> List[VerificationEntry]: 
    """Perform modifications on file from matches, scan with scanner and return those results"""
    verificationRuns: List[VerificationEntry] = []
    if len(matches) == 0:
        return verificationRuns

    logging.info(f"Verify {len(matches)} matches")

    # Independant, Middle
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.MIDDLE8)
    for match in matches:
        if match.size < (2*8):
            verificationRun.matchTests.append(MatchTest('', ScanResult.NOT_SCANNED))
            continue
        fileCopy = deepcopy(file)
        offset = match.fileOffset + int((match.size) // 2) - 4
        fileCopy.Data().hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    logging.info("Verification run: {}".format(verificationRun))
    verificationRuns.append(verificationRun)

    # Independant, Thirds
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.THIRDS8)
    for match in matches:
        if match.size < (3*8):
            verificationRun.matchTests.append(MatchTest('', ScanResult.NOT_SCANNED))
            continue
        fileCopy = deepcopy(file)
        offset1 = match.fileOffset + int( (match.size // 3) * 1) - 4
        offset2 = match.fileOffset + int( (match.size // 3) * 2) - 4
        fileCopy.Data().hidePart(offset1, 8, fillType=FillType.lowentropy)
        fileCopy.Data().hidePart(offset2, 8, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # Independant, Full
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.FULL
    )
    for match in matches:
        fileCopy = deepcopy(file)
        fileCopy.Data().hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # Independant, Full B
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.FULLB
    )
    for match in matches:
        fileCopy = deepcopy(file)
        fileCopy.Data().hidePart(match.fileOffset, match.size, fillType=FillType.highentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    if len(matches) == 1:
        return verificationRuns

    # Incremental, Middle
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.INCREMENTAL,
        matchModify=TestMatchModify.MIDDLE8, 
    )
    fileCopy = deepcopy(file)
    for match in matches:
        if match.size < (2*8):
            verificationRun.matchTests.append(MatchTest('', ScanResult.NOT_SCANNED))
            continue
        offset = match.fileOffset + int((match.size) // 2) - 4
        fileCopy.Data().hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # Incremental, Full
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.INCREMENTAL,
        matchModify=TestMatchModify.FULL)
    fileCopy = deepcopy(file)
    for match in matches:
        fileCopy.Data().hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # Decremental, Full
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.DECREMENTAL,
        matchModify=TestMatchModify.FULL)
    fileCopy = deepcopy(file)
    n = 0
    for match in reversed(matches):
        fileCopy.Data().hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
        verificationRun.matchTests.append(toTestEntry(n, result))
        n += 1
    verificationRun.matchTests = list(reversed(verificationRun.matchTests))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # All, Middle
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ALL,
        matchModify=TestMatchModify.MIDDLE8)
    fileCopy = deepcopy(file)
    for match in matches:
        offset = match.fileOffset + int((match.size) // 2) - 4
        fileCopy.Data().hidePart(offset, 8, fillType=FillType.lowentropy)
    result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
    for match in matches:
        verificationRun.matchTests.append(toTestEntry(0, result))
    verificationRun.matchTests = list(reversed(verificationRun.matchTests))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # All, Thirds
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ALL,
        matchModify=TestMatchModify.THIRDS8)
    fileCopy = deepcopy(file)
    for match in matches:
        offset1 = match.fileOffset + int( (match.size // 3) * 1) - 4
        offset2 = match.fileOffset + int( (match.size // 3) * 2) - 4
        fileCopy.Data().hidePart(offset1, 8, fillType=FillType.lowentropy)
        fileCopy.Data().hidePart(offset2, 8, fillType=FillType.lowentropy)
    result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
    for match in matches:
        verificationRun.matchTests.append(toTestEntry(0, result))
    verificationRun.matchTests = list(reversed(verificationRun.matchTests))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    # All, Full
    verificationRun = VerificationEntry(
        index=len(verificationRuns), 
        matchOrder=TestMatchOrder.ALL,
        matchModify=TestMatchModify.FULL)
    fileCopy = deepcopy(file)
    for match in matches:
        fileCopy.Data().hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
    result = scanner.scannerDetectsBytes(fileCopy.DataAsBytes(), file.filename)
    for match in matches:
        verificationRun.matchTests.append(toTestEntry(0, result))
    verificationRun.matchTests = list(reversed(verificationRun.matchTests))
    verificationRuns.append(verificationRun)
    logging.info("Verification run: {}".format(verificationRun))

    return verificationRuns