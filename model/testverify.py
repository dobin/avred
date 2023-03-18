from enum import Enum
from typing import List


class FillType(Enum):
    """What kind of data to take to overwrite parts of a file/match"""
    null = 1
    space = 2
    highentropy = 3
    lowentropy = 4


class TestMatchOrder(Enum):
    """Order of the match-tests performed for a Verification"""
    ISOLATED = 1
    INCREMENTAL = 2
    DECREMENTAL = 3
    LAST_TWO = 4
    FIRST_TWO = 5
    

class TestMatchModify(Enum):
    """How much and where the match was modified for a Verification"""
    FULL = 1
    
    MIDDLE8 = 2
    MIDDLE_32 = 3
    BEGIN = 4
    END = 5
    THIRDS8 = 6

    FULLB = 7


class VerifyStatus(Enum):
    """Conclusion of verification scans for VerifyConclusion"""
    UNKNOWN = 0
    GOOD = 1
    OK = 2
    BAD = 3


class ScanResult(Enum):
    """Result of a verification scan for a TestEntry"""
    NOT_SCANNED = 0
    DETECTED = 1
    NOT_DETECTED = 2
    

class MatchTest():
    """Data about a performed Test for Verification"""
    def __init__(self, scanIndex: int, scanResult: ScanResult):
        self.scanIndex = scanIndex
        self.scanResult = scanResult

    def __str__(self):
        s = ''
        if self.scanIndex != '':
            s += "Idx: {}  result: {}".format(self.scanIndex, self.scanResult)
        else: 
            s += "result: {}".format(self.scanResult)
        return s


class MatchConclusion():
    """Object to hold all information about the verification conclusion"""
    def __init__(self, verifyStatus: List[VerifyStatus]):
        self.verifyStatus = verifyStatus


    def getCount(self, verifyStatus: VerifyStatus) -> int:
        n = 0
        for vs in self.verifyStatus:
            if vs is verifyStatus:
                n += 1
        return n

    def __str__(self):
        s = ''
        for idx, entry in enumerate(self.verifyStatus):
            s += "{} {}\n".format(idx, entry.name)
        return s


class VerificationEntry():
    """Object to hold all data of a verification run"""
    def __init__(self, index: int, matchOrder: TestMatchOrder, matchModify: TestMatchModify, fillType=FillType.lowentropy):
        self.index = index
        self.info = matchOrder
        self.type = matchModify
        self.fillType = fillType
        self.matchTests: List[MatchTest] = []  # same order as Matches

    def __str__(self):
        s = ""
        s += "{} {} {}\n".format(self.index, self.type.name, self.info.name)

        if self.matchTests is not None:
            for entry in self.matchTests:
                s += "  {}\n".format(entry)
        return s
    

class Verification():
    def __init__(self, verifications: List[VerificationEntry], matchConclusions: MatchConclusion):
        self.verifications = verifications
        self.matchConclusions = matchConclusions

    def __str__(self):
        s = ''
        for verification in self.verifications:
            s += "{}\n".format(verification)
        s += 'Conclusion:\n'
        s += str(self.matchConclusions)
        return s
