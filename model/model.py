from dataclasses import dataclass
from re import S
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum
from intervaltree import Interval, IntervalTree
import logging
import pickle

from model.testverify import *


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


class FileType(Enum):
    EXE = 1
    OFFICE = 3
    PLAIN = 4
    

class Match():
    def __init__(self, idx: int, fileOffset:int , size: int):
        self.idx: int = idx
        self.fileOffset: int = fileOffset
        self.size: int = size
        
        self.data: bytes = b''
        self.dataHexdump: str = ''
        self.sectionInfo: str = ''
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
        #if self.disasmLines is not None:
        #    s += "  DisasmLines: {}\n".format(self.disasmLines)
        if self.dataHexdump is not None:
            s += "  Hexdump: \n{}\n".format(self.dataHexdump)
        s += '\n'
        return s


class FileInfo():
    def __init__(self, name, size, hash, time, ident):
        self.name = name
        self.size = size
        self.hash = hash
        self.date = time
        self.ident = ident

    def __str__(self):
        s = ''
        s += "{} size: {}  ident: {}".format(self.name, self.size, self.ident)
        return s


class Outcome():
    def __init__(self, fileInfo: FileInfo):
        self.fileInfo: FileInfo = fileInfo
        self.matches: List[Match] = []
        self.verification: Verification = None
        self.matchesIt: IntervalTree = IntervalTree()

        self.isDetected: bool = False
        self.isScanned: bool = False
        self.isVerified: bool = False
        self.isAugmented: bool = False

        self.scannerInfo: str = ''
        self.scannerName: str = ''
        self.scanTime: str = ''
        self.fileStructure: str = ''

        self.appraisal: str = ''


    @staticmethod
    def nullOutcome(fileInfo: FileInfo):
        return Outcome(fileInfo)
    

    def saveToFile(self, filepath: str):
        filenameOutcome = filepath + '.outcome'
        logging.info("Saving results to: {}".format(filenameOutcome))
        with open(filenameOutcome, 'wb') as handle:
            pickle.dump(self, handle)


    def __str__(self):
        s = ''
        if self.fileInfo is not None:
            s += str(self.fileInfo)
        s += '\n'
        s += "ScannerInfo: {}\n".format(self.scannerInfo)
        s += "Matches: \n"
        for match in self.matches:
            s += str(match)
        s += "\nVerification: \n"
        s += str(self.verification)
        s += "\n"    
        return s