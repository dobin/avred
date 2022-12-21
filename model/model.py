from dataclasses import dataclass
from re import S
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum
from intervaltree import Interval, IntervalTree
import os
from utils import patchData, FillType


@dataclass
class Packer:
    data: bytes = None

    def pack(self, data) -> bytes:
        pass


@dataclass
class Scanner:
    scanner_path: str = ""
    scanner_name: str = ""
    packer: Packer = None

    def scan(self, data, filename):
        return False

    def setPacker(self, packer):
        self.packer = packer



class Match():
    def __init__(self, idx, fileOffset, size):
        self.idx = idx
        self.fileOffset = fileOffset
        self.size = size
        
        self.data = None
        self.dataHexdump = None
        self.info = None
        self.detail = None

    def start(self):
        return self.fileOffset

    def end(self):
        return self.fileOffset + self.size

    def setData(self, data):
        self.data = data

    def setDataHexdump(self, dataHexdump):
        self.dataHexdump = dataHexdump

    def setInfo(self, info):
        self.info = info

    def setDetail(self, detail):
        self.detail = detail

    def __str__(self):
        s = ""
        s += "id:{}  offset:{}  len:{}\n".format(self.idx, self.fileOffset, self.size)
        if self.info is not None:
            s += "  {}\n".format(self.info)
        if self.detail is not None:
            s += "  {}\n".format(self.detail)
        return s


class TestType(Enum):
    FULL = 1
    MIDDLE = 2


class Verification():
    def __init__(self, index, type, info):
        self.index: int = index
        self.type: TestType = type
        self.info: str = info
        self.testEntries: List[bool] = []

    def __str__(self):
        s = ""
        s += "{} {} {}\n".format(self.index, self.type, self.info)
        for entry in self.testEntries:
            s += "  {}".format(entry)
        s += "\n"
        return s
    

class FileData():
    def __init__(self, matches, verifications, matchesIt=None):
        self.matches: List[Match] = matches
        self.verifications: List[Verification] = verifications
        self.matchesIt: IntervalTree = matchesIt

    def __str__(self):
        s = "Matches: \n"
        for match in self.matches:
            s += str(match)

        s += "Verification: \n"
        for v in self.verifications:
            s += str(v)        

        return s


class FileFormat():
    def __init__(self):
        self.filepath = None
        self.filename = None
        self.fileData = b""  # The content of the file
        self.data = b""      # The data we work on
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # Default: File is Data


    def getData(self):
        return self.data


    def getFileWithExternalData(self, data):
        return data  # Default: Data is the File. No need to modify.


    def getFileWithInternalData(self):
        return self.data  # Default: Data is the File. No need to modify.


    def loadFromFile(self, filepath: str) -> bool:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(self.filepath, "rb") as f:
            self.fileData = f.read()

        return self.parseFile()


    def hidePart(self, base: int, size: int, fillType: FillType=FillType.null):
        self.data = patchData(self.data, base, size, fillType)
