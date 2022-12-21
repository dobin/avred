from copy import deepcopy
from model.model import TestType, Verification
from utils import FillType
import logging

def verify(fileData, matches, scanner):
    verificationRuns = []
    logging.info(f"Verify {len(matches)} matches")

    verificationRun = Verification(index=0, type=TestType.FULL, 
        info="One match after another, additive")
    logging.info("One match after another, additive")
    fileDataCopy = deepcopy(fileData)
    for match in matches:
        fileDataCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileDataCopy.data, fileData.filename)
        logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=1, type=TestType.FULL, 
        info="Each individually")
    logging.info("Each individually")
    for match in matches:
        fileDataCopy = deepcopy(fileData)
        fileDataCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(fileDataCopy.data, fileData.filename)
        logging.info(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=2, type=TestType.MIDDLE, 
        info="One match after another, additive")
    logging.info("One match after another, additive")
    fileDataCopy = deepcopy(fileData)
    for match in matches:
        offset = match.fileOffset + int((match.size) // 2)
        fileDataCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileDataCopy.data, fileData.filename)
        logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=3, type=TestType.MIDDLE, 
        info="Each individually")
    logging.info("Each individually: MIDDLE")
    for match in matches:
        fileDataCopy = deepcopy(fileData)
        offset = match.fileOffset + int((match.size) // 2)
        fileDataCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(fileDataCopy.data, fileData.filename)
        logging.info(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    return verificationRuns