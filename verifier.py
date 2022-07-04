from copy import deepcopy
from file_pe import FilePe
from model import TestType, VerificationRun
from utils import FillType

def verify(scanner, filePe, matches):
    verificationRuns = []

    verificationRun = VerificationRun(index=0, type=TestType.FULL, 
        info="One match after another, additive")
    peCopy = deepcopy(filePe)
    for match in matches:
        size = match.end - match.start
        peCopy.hidePart(match.start, size, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {match.start}-{match.end} size {size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = VerificationRun(index=1, type=TestType.FULL, 
        info="Each individually")
    for match in matches:
        peCopy = deepcopy(filePe)
        size = match.end - match.start
        peCopy.hidePart(match.start, size, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {match.start}-{match.end} size {size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = VerificationRun(index=2, type=TestType.MIDDLE, 
        info="One match after another, additive")
    peCopy = deepcopy(filePe)
    for match in matches:
        offset = int((match.end - match.start) // 2)
        peCopy.hidePart(match.start + offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = VerificationRun(index=3, type=TestType.MIDDLE, 
        info="Each individually")
    for match in matches:
        peCopy = deepcopy(filePe)
        offset = int((match.end - match.start) // 2)
        peCopy.hidePart(match.start + offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    return verificationRuns