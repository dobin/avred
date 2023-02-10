from enum import Enum
from typing import List, Set, Dict, Tuple, Optional


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
    

class TestEntry():
    """Data about a performed Test for Verification"""
    def __init__(self, scanIndex: int, scanResult: ScanResult):
        self.scanIndex = scanIndex
        self.scanResult = scanResult

    def __str__(self):
        s = ''
        s += "Idx: {}  result: {}".format(self.scanIndex, self.scanResult)
        return s


class VerifyConclusion():
    """Object to hold all information about the verification conclusion"""
    def __init__(self, verifyStatus: List[VerifyStatus]):
        self.verifyStatus = verifyStatus

    def __str__(self):
        s = ''
        for entry in self.verifyStatus:
            s += entry


class Verification():
    """Object to hold all data of a verification run"""
    def __init__(self, index, matchOrder, matchModify, fillType=FillType.lowentropy):
        self.index: int = index
        self.info: TestMatchOrder = matchOrder
        self.type: TestMatchModify = matchModify
        self.fillType = fillType
        self.testEntries: List[TestEntry] = []

    def __str__(self):
        s = ""
        s += "{} {} {}".format(self.index, self.type.name, self.info.name)

        if self.testEntries is not None:
            for entry in self.testEntries:
                s += "  {}".format(entry)
        return s
    