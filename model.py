from dataclasses import dataclass
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum


class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

    def __str__(self):
        return f"{self.refPos} {self.refData}"
    def __repr__(self):
        return f"{self.refPos} {self.refData}"


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
    def __init__(self, idx, data, dataHexdump, fileOffset, size, info, detail):
        self.idx = idx
        self.data = data
        self.dataHexdump = dataHexdump
        self.fileOffset = fileOffset
        self.size = size
        self.info = info
        self.detail = detail


class TestType(Enum):
    FULL = 1
    MIDDLE = 2


class Verification():
    def __init__(self, index, type, info):
        self.index: int = index
        self.type: TestType = type
        self.info: str = info
        self.testEntries: List[bool] = []
    

class FileData():
    def __init__(self, matches, verifications):
        self.matches: List[Match] = matches
        self.verifications: List[Verification] = verifications
