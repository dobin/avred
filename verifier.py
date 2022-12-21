from copy import deepcopy
from model.model import TestType, Verification
from utils import FillType
import logging

def verify(file, matches, scanner):
    verificationRuns = []
    logging.info(f"Verify {len(matches)} matches")

    verificationRun = Verification(index=0, type=TestType.FULL, 
        info="One match after another, additive")
    logging.info("One match after another, additive")
    fileCopy = deepcopy(file)
    for match in matches:
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=1, type=TestType.FULL, 
        info="Each individually")
    logging.info("Each individually")
    for match in matches:
        fileCopy = deepcopy(file)
        fileCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=2, type=TestType.MIDDLE, 
        info="One match after another, additive")
    logging.info("One match after another, additive")
    fileCopy = deepcopy(file)
    for match in matches:
        offset = match.fileOffset + int((match.size) // 2)
        fileCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=3, type=TestType.MIDDLE, 
        info="Each individually")
    logging.info("Each individually: MIDDLE")
    for match in matches:
        fileCopy = deepcopy(file)
        offset = match.fileOffset + int((match.size) // 2)
        fileCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileCopy.data, file.filename)
        logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    return verificationRuns