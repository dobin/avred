from dataclasses import dataclass
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum
from intervaltree import Interval, IntervalTree
import logging
import pickle
from dataclasses import dataclass

from model.testverify import *

class Appraisal(Enum):
    Unknown = "Unknown"
    Undetected = "Undetected"
    Hash = "Hash"
    One = "One"
    OrSig = "Or-Signature"
    AndSig = "And-Signature"


@dataclass
class Section:
    name: str
    addr: int
    size: int
    virtaddr: int
    scan: bool = True


class SectionsBag:

    def __init__(self):
        self.sections = []
        self.sectionsIntervalTree = IntervalTree()


    def addSection(self, section):
        self.sections.append(section)
        interval = Interval(section.addr, section.addr + section.size, section)
        self.sectionsIntervalTree.add(interval)

    def removeSectionByName(self, sectionName):
        new = []
        for section in self.sections:
            if section.name != sectionName:
                new.append(section)
        self.sections = new

    def getSectionByName(self, sectionName: str) -> Section:
        return next((sec for sec in self.sections if sectionName in sec.name ), None)


    def getSectionByAddr(self, address: int) -> Section:
        for section in self.sections:
            if address >= section.addr and address <= section.addr + section.size:
                return section
        return None
    

    def getSectionNameByAddr(self, address: int) -> Section:
        for section in self.sections:
            if address >= section.addr and address <= section.addr + section.size:
                return section.name
        return "<unknown>"
    

    def getSectionsForRange(self, start: int, end: int) -> List[Section]:
        res = self.sectionsIntervalTree.overlap(start, end)
        res = [r[2] for r in res]
        return res
    

    def printSections(self):
        for section in self.sections:
            print(f"Section {section.name}\t  addr: {hex(section.addr)}   size: {section.size} ")


class UiDisasmLine():
    def __init__(self, fileOffset, rva, isPart, text, textHtml):
        self.offset = fileOffset  # offset in file
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
        self.outflankPatches: List[OutflankPatch] = []

        self.isDetected: bool = False
        self.isScanned: bool = False
        self.isVerified: bool = False
        self.isAugmented: bool = False
        self.isOutflanked: bool = False

        self.scannerInfo: str = ''
        self.scannerName: str = ''
        self.scanTime: str = ''
        self.fileStructure: str = ''

        self.appraisal: Appraisal = Appraisal.Unknown


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
    

class OutflankPatch():
    def __init__(self, matchIdx: int, offset: int, replaceBytes: bytes, info: str, considerations: str):
        self.matchIdx = matchIdx
        self.offset = offset
        self.replaceBytes = replaceBytes
        self.info = info
        self.considerations = considerations

    def __str__(self):
        s = ''
        s += "Patch at Offset: {}  Bytes: {}\n".format(self.offset, self.replaceBytes)
        s += "  {}\n".format(self.info)
        s += "  {}\n".format(self.considerations)
        return s
