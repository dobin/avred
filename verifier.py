from copy import deepcopy
from file_pe import FilePe
from model import TestType, Verification
from utils import FillType

def verify(filePe, matches, scanner):
    verificationRuns = []

    verificationRun = Verification(index=0, type=TestType.FULL, 
        info="One match after another, additive")
    print("One match after another, additive")
    peCopy = deepcopy(filePe)
    for match in matches:
        peCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=1, type=TestType.FULL, 
        info="Each individually")
    print("Each individually")
    for match in matches:
        peCopy = deepcopy(filePe)
        peCopy.hidePart(match.fileOffset, match.size, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {match.fileOffset} size {match.size}  Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=2, type=TestType.MIDDLE, 
        info="One match after another, additive")
    peCopy = deepcopy(filePe)
    for match in matches:
        offset = match.fileOffset + int((match.size) // 2)
        peCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    verificationRun = Verification(index=3, type=TestType.MIDDLE, 
        info="Each individually")
    for match in matches:
        peCopy = deepcopy(filePe)
        offset = match.fileOffset + int((match.size) // 2)
        peCopy.hidePart(offset, 8, fillType=FillType.lowentropy)
        result = scanner.scan(peCopy.data, filePe.filename)
        print(f"Patching: {offset} size 8 Detected: {result}")
        verificationRun.testEntries.append(result)
    verificationRuns.append(verificationRun)

    return verificationRuns