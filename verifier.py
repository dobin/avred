from copy import deepcopy
from model.model import TestMatchModify, TestMatchOrder, Verification, Match, ScanResult, TestEntry
from utils import FillType
import logging
from typing import List


def toTestEntry(scanIndex, result):
    scanResult = ScanResult.NOT_SCANNED
    if not result:
        scanResult = ScanResult.NOT_DETECTED
    else: 
        scanResult = ScanResult.DETECTED

    testEntry = TestEntry(scanIndex, scanResult)
    return testEntry


def verify(file, matches: List[Match], scanner):
    verificationRuns = []
    logging.info(f"Verify {len(matches)} matches")

    # Independant, Middle
    verificationRun = Verification(
        index=0, 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.MIDDLE8)
    logging.info("Verification run: {}".format(verificationRun))
    for match in matches:
        fileCopy = deepcopy(file)
        offset = match.fileOffset + int((match.size) // 2)
        fileCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)

    # Independant, Full
    verificationRun = Verification(
        index=1, 
        matchOrder=TestMatchOrder.ISOLATED,
        matchModify=TestMatchModify.FULL
    )
    logging.info("Verification run: {}".format(verificationRun))
    for match in matches:
        fileCopy = deepcopy(file)
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(toTestEntry('', result))
    verificationRuns.append(verificationRun)

    # Incremental, Middle
    verificationRun = Verification(
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
        #logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)

    # Incremental, Full
    verificationRun = Verification(
        index=3, 
        matchOrder=TestMatchOrder.INCREMENTAL,
        matchModify=TestMatchModify.FULL)
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    for match in matches:
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(toTestEntry(match.idx, result))
    verificationRuns.append(verificationRun)

    # Decremental, Full
    verificationRun = Verification(
        index=4, 
        matchOrder=TestMatchOrder.DECREMENTAL,
        matchModify=TestMatchModify.FULL)
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    n = 0
    for match in reversed(matches):
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(toTestEntry(n, result))
        n += 1
    verificationRun.testEntries = list(reversed(verificationRun.testEntries))
    verificationRuns.append(verificationRun)

    if len(matches) >= 2:
        # First Two
        verificationRun = Verification(
            index=5, 
            matchOrder=TestMatchOrder.FIRST_TWO,
            matchModify=TestMatchModify.FULL)
        logging.info("Verification run: {}".format(verificationRun))
        fileCopy = deepcopy(file)

        fileCopy.hidePart(matches[0].fileOffset, matches[0].size, fillType=FillType.lowentropy)
        fileCopy.hidePart(matches[1].fileOffset, matches[1].size, fillType=FillType.lowentropy)

        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(toTestEntry(0, result))
        verificationRun.testEntries.append(toTestEntry(0, result))
        n = 2
        while n < len(matches):
            verificationRun.testEntries.append(TestEntry('', ScanResult.NOT_SCANNED))
            n += 1
        verificationRuns.append(verificationRun)

        # Last two
        verificationRun = Verification(
            index=6, 
            matchOrder=TestMatchOrder.LAST_TWO,
            matchModify=TestMatchModify.FULL)
        logging.info("Verification run: {}".format(verificationRun))
        fileCopy = deepcopy(file)

        fileCopy.hidePart(matches[-1].fileOffset, matches[-1].size, fillType=FillType.lowentropy)
        fileCopy.hidePart(matches[-2].fileOffset, matches[-2].size, fillType=FillType.lowentropy)

        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")

        n = 0
        while n < len(matches) - 2:
            verificationRun.testEntries.append(TestEntry('', ScanResult.NOT_SCANNED))
            n += 1
        verificationRun.testEntries.append(toTestEntry(0, result))
        verificationRun.testEntries.append(toTestEntry(0, result))
            
        verificationRuns.append(verificationRun)

    return verificationRuns