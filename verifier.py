from copy import deepcopy
from utils import FillType
import logging
from typing import List

from model.model import *


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


def verify(file, matches: List[Match], scanner) -> Verification:
    verifications = runVerifications(file, matches, scanner)
    matchConclusions = verificationAnalyzer(verifications)
    verify = Verification(verifications, matchConclusions)
    return verify


def verificationAnalyzer(verifications: List[VerificationEntry]) -> VerifyConclusion:
    verifyResults = []
    res = VerifyStatus.BAD

    for idx, val in enumerate(verifications[0].matchTests):
        # best: Partial modification of an isolated match
        if getMatchTestsFor(verifications, TestMatchOrder.ISOLATED, TestMatchModify.MIDDLE8)[idx].scanResult is ScanResult.NOT_DETECTED:
            res = VerifyStatus.GOOD

        # ok: Full modification of an isolated match
        elif getMatchTestsFor(verifications, TestMatchOrder.ISOLATED, TestMatchModify.FULL)[idx].scanResult is ScanResult.NOT_DETECTED:
            res = VerifyStatus.OK

        # ok: 
        else:
            if len(verifications) >= 5:
                if idx == 0 or idx == 1:
                    # check FIRST_TWO (first two entries have same result)
                    if getMatchTestsFor(verifications, TestMatchOrder.FIRST_TWO, TestMatchModify.FULL)[idx].scanResult is ScanResult.NOT_DETECTED:
                        res = VerifyStatus.OK

                if idx == len(verifications) or idx == len(verifications) - 1:
                    # check LAST_TWO (last two entries have same result)
                    if getMatchTestsFor(verifications, TestMatchOrder.LAST_TWO, TestMatchModify.FULL).matchTests[idx].scanResult is ScanResult.NOT_DETECTED:
                        res = VerifyStatus.OK
        
        verifyResults.append(res)

    verifyConclusion = VerifyConclusion(verifyResults)
    return verifyConclusion


def runVerifications(file, matches: List[Match], scanner):
    verificationRuns = []
    logging.info(f"Verify {len(matches)} matches")

    # Independant, Middle
    verificationRun = VerificationEntry(
        index=0, 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.MIDDLE8)
    logging.info("Verification run: {}".format(verificationRun))
    for match in matches:
        fileCopy = deepcopy(file)
        offset = match.fileOffset + int((match.size) // 2)
        fileCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)

    # Independant, Full
    verificationRun = VerificationEntry(
        index=1, 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.FULL
    )
    logging.info("Verification run: {}".format(verificationRun))
    for match in matches:
        fileCopy = deepcopy(file)
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)

    # Incremental, Middle
    verificationRun = VerificationEntry(
        index=2, 
        matchOrder=TestMatchOrder.INCREMENTAL,
        matchModify=TestMatchModify.MIDDLE8, 
    )
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    for match in matches:
        offset = match.fileOffset + int((match.size) // 2)
        fileCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)

    # Incremental, Full
    verificationRun = VerificationEntry(
        index=3, 
        matchOrder=TestMatchOrder.INCREMENTAL,
        matchModify=TestMatchModify.FULL)
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    for match in matches:
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)

    # Decremental, Full
    verificationRun = VerificationEntry(
        index=4, 
        matchOrder=TestMatchOrder.DECREMENTAL,
        matchModify=TestMatchModify.FULL)
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    n = 0
    for match in reversed(matches):
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry(n, result))
        n += 1
    verificationRun.matchTests = list(reversed(verificationRun.matchTests))
    verificationRuns.append(verificationRun)

    if len(matches) >= 2:
        # First Two
        verificationRun = VerificationEntry(
            index=5, 
            matchOrder=TestMatchOrder.FIRST_TWO,
            matchModify=TestMatchModify.FULL)
        logging.info("Verification run: {}".format(verificationRun))
        fileCopy = deepcopy(file)
        fileCopy.hidePart(matches[0].fileOffset, matches[0].size, fillType=FillType.lowentropy)
        fileCopy.hidePart(matches[1].fileOffset, matches[1].size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        verificationRun.matchTests.append(toTestEntry(0, result))
        verificationRun.matchTests.append(toTestEntry(0, result))
        n = 2
        while n < len(matches):
            verificationRun.matchTests.append(MatchTest('', ScanResult.NOT_SCANNED))
            n += 1
        verificationRuns.append(verificationRun)

        # Last two
        verificationRun = VerificationEntry(
            index=6, 
            matchOrder=TestMatchOrder.LAST_TWO,
            matchModify=TestMatchModify.FULL)
        logging.info("Verification run: {}".format(verificationRun))
        fileCopy = deepcopy(file)
        fileCopy.hidePart(matches[-1].fileOffset, matches[-1].size, fillType=FillType.lowentropy)
        fileCopy.hidePart(matches[-2].fileOffset, matches[-2].size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        n = 0
        while n < len(matches) - 2:
            verificationRun.matchTests.append(MatchTest('', ScanResult.NOT_SCANNED))
            n += 1
        verificationRun.matchTests.append(toTestEntry(0, result))
        verificationRun.matchTests.append(toTestEntry(0, result))
        verificationRuns.append(verificationRun)

    return verificationRuns