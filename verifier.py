from copy import deepcopy
from model.model import TestMatchModify, TestMatchOrder, Verification, Match
from utils import FillType
import logging
from typing import List


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
        verificationRun.testEntries.append(result)
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
        verificationRun.testEntries.append(result)
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
        verificationRun.testEntries.append(result)
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
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    # Decremental, Full
    verificationRun = Verification(
        index=4, 
        matchOrder=TestMatchOrder.DECREMENTAL,
        matchModify=TestMatchModify.FULL)
    logging.info("Verification run: {}".format(verificationRun))
    fileCopy = deepcopy(file)
    for match in reversed(matches):
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        #logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRun.testEntries = list(reversed(verificationRun.testEntries))
    verificationRuns.append(verificationRun)

    return verificationRuns