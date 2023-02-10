from dataclasses import dataclass
from re import S
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum
from intervaltree import Interval, IntervalTree
import os

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


class FileInfo():
    def __init__(self, name, size, fileStructure):
        self.name = name
        self.size = size
        self.fileStructure = fileStructure
        self.type = ''
        self.date = ''


class Outcome():
    def __init__(self, fileInfo, matches, verification, matchesIt=None):
        self.fileInfo: FileInfo = fileInfo
        self.matches: List[Match] = matches
        self.verification: Verification = verification
        self.matchesIt: IntervalTree = matchesIt


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
        for v in self.verification:
            s += str(v)

        s += "\n"    
        return s