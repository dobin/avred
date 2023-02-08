from dataclasses import dataclass
from re import S
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum
from intervaltree import Interval, IntervalTree
import os
from utils import patchData, FillType


@dataclass
class Scanner:
    scanner_path: str = ""
    scanner_name: str = ""

    def scan(self, data, filename):
        pass


class UiDisasmLine():
    def __init__(self, fileOffset, rva, isPart, text, textHtml):
        self.offset = str(hex(fileOffset))  # offset in file
        self.rva = rva  # relative offset (usually created by external disasm tool)
        self.isPart = isPart  # is this part of the data, or supplemental?
        self.text = text  # the actual disassembled data
        self.textHtml = textHtml  # the actual disassembled data, colored

    def __str__(self):
        s = "Offset: {}  RVA: {}  isPart: {}  Text: {}".format(
            self.offset,
            self.rva,
            self.isPart,
            self.text
        )
        return s
    

class Match():
    def __init__(self, idx: int, fileOffset:int , size: int):
        self.idx: int = idx
        self.fileOffset: int = fileOffset
        self.size: int = size
        
        self.data: bytes = None
        self.dataHexdump: str = None
        self.sectionInfo: str = None
        self.disasmLines: List[UiDisasmLine] = []

    def start(self):
        return self.fileOffset

    def end(self):
        return self.fileOffset + self.size

    def setData(self, data):
        self.data = data

    def setDataHexdump(self, dataHexdump):
        self.dataHexdump = dataHexdump

    def setSectionInfo(self, info):
        self.sectionInfo = info

    def getSectionInfo(self):
        return self.sectionInfo

    def setDisasmLines(self, disasmLines):
        self.disasmLines = disasmLines

    def getDisasmLines(self):
        return self.disasmLines

    def __str__(self):
        s = ""
        s += "id:{}  offset:{:X}  len:{}\n".format(self.idx, self.fileOffset, self.size)
        if self.sectionInfo is not None:
            s += "  Section: {}\n".format(self.sectionInfo)
        if self.disasmLines is not None:
            s += "  DisasmLines: {}\n".format(self.disasmLines)
        if self.dataHexdump is not None:
            s += "  Hexdump: {}\n".format(self.dataHexdump)
        return s


class TestMatchOrder(Enum):
    ISOLATED = 1
    INCREMENTAL = 2
    DECREMENTAL = 3
    LAST_TWO = 4
    FIRST_TWO = 5
    

class TestMatchModify(Enum):
    FULL = 1
    MIDDLE8 = 2
    MIDDLE_32 = 3
    BEGIN = 4
    END = 5


class ScanResult(Enum):
    NOT_SCANNED = 0
    DETECTED = 1
    NOT_DETECTED = 2
    

class TestEntry():
    def __init__(self, scanIndex, scanResult):
        self.scanIndex = scanIndex
        self.scanResult = scanResult

    def __str__(self):
        s = ''
        s += "Idx: {}  result: {}".format(self.scanIndex, self.scanResult)
        return s


class Verification():
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
    

class FileInfo():
    def __init__(self, name, size, fileStructure):
        self.name = name
        self.size = size
        self.fileStructure = fileStructure
        self.type = ''
        self.date = ''


class PluginFileFormat():
    def __init__(self):
        self.filepath = None
        self.filename = None
        self.fileData = b""  # The content of the file
        self.data = b""      # The data we work on
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # Default: File is Data


    def getData(self):
        return self.data


    def getFileWithNewData(self, data):
        return data  # Default: Data is the File. No need to modify.


    def loadFromFile(self, filepath: str) -> bool:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(self.filepath, "rb") as f:
            self.fileData = f.read()

        return self.parseFile()


    def hidePart(self, base: int, size: int, fillType: FillType=FillType.null):
        self.data = patchData(self.data, base, size, fillType)


class VerifyStatus(Enum): 
    UNKNOWN = 0
    GOOD = 1
    OK = 2
    BAD = 3


class VerifyConclusion():
    def __init__(self, verifyStatus: List[VerifyStatus]):
        self.verifyStatus = verifyStatus

    def __str__(self):
        s = ''
        for entry in self.verifyStatus:
            s += entry


def convertMatchesIt(matchesIt):
    matches = []
    idx = 0
    for m in matchesIt:
        match = Match(idx, m.begin, m.end-m.begin)
        matches.append(match)
        idx += 1
    return matches


class Outcome():
    def __init__(self, fileInfo, matches, verifications, matchesIt=None, verifyConclusion=None):
        self.fileInfo: FileInfo = fileInfo
        self.matches: List[Match] = matches
        self.verifications: List[Verification] = verifications
        self.matchesIt: IntervalTree = matchesIt
        self.verifyConclusion: VerifyConclusion = verifyConclusion


    def __str__(self):
        s = ''
        if self.fileInfo is not None:
            if self.fileInfo.fileStructure is not None:
                s += 'FileInfo: \n'
                s += self.fileInfo.fileStructure
        s += "Matches: \n"
        for match in self.matches:
            s += str(match)
        s += "\nVerification: \n"
        for v in self.verifications:
            s += str(v)
        s += "\VerifyConclusion: \n"
        print(str(self.verifyConclusion))
        s += "\n"    
        return s