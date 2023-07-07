from __future__ import annotations

import os
import base64
from dataclasses import dataclass
from typing import List, Set, Dict, Tuple, Optional
from dataclasses import dataclass
import logging
import random

from model.model_verification import FillType
from model.model_code import AsmInstruction, SectionType, UiDisasmLine, Section


# All Input:    bytes
# All Output:   bytes
# All Internal: bytearray
class Data():
    def __init__(self, data: bytes):
        self._data: bytearray = bytearray(data)


    def getBytes(self) -> bytes:
        return bytes(self._data)
    

    def getBytesRange(self, start: int, end: int) -> bytes:
        data = self._data[start:end]
        return bytes(data)


    def getLength(self) -> int:
        return len(self._data)
    

    def hideMatch(self, match: Match):
        self.hidePart(match.fileOffset, match.size)


    def hideMatches(self, matches: List[Match]):
        for match in matches:
            self.hidePart(match.fileOffset, match.size)


    def hidePart(self, offset: int, size: int, fillType: FillType=FillType.null):
        """Overwrites size bytes at base with fillType"""
        self.patchDataFill(offset, size, fillType)


    def patchDataFill(self, offset: int, size: int, fillType: FillType=FillType.null):
        origLen = len(self._data)

        fill = None # has to be exactly <size> bytes
        if fillType is FillType.null:
            fill = b"\x00" * size
        elif fillType is FillType.space:
            fill = b" " * size
        elif fillType is FillType.highentropy:
            random.seed(offset)  # make it deterministic
            fill = randbytes(size)
        elif fillType is FillType.lowentropy:
            random.seed(offset)  # make it deterministic
            temp = randbytes(size)
            temp = base64.b64encode(temp)
            fill = temp[:size]

        self.patchData(offset, fill)
        if len(self._data) != origLen:
            raise Exception("patchData cant patch, different size: {} {}".format(origLen, len(self._data)))
    

    def patchData(self, offset: int, replace: bytes) -> bytes:
        self._data[offset:offset+len(replace)] = replace

    
    def swapData(self, offset_a, size_a, offset_b, size_b):
        data_a = self._data[offset_a:offset_a+size_a]
        data_b = self._data[offset_b:offset_b+size_b]
        
        self._data[offset_a:offset_a + size_b] = data_b
        self._data[offset_a + size_b:offset_a + size_b + size_a] = data_a



def randbytes(n):
    #temp = random.randbytes(size) # 3.9..
    random_bytes = bytes([random.getrandbits(8) for _ in range(0, n)])
    return random_bytes


class Match():
    def __init__(self, idx: int, fileOffset:int , size: int, iteration: int = 0):
        self.idx: int = idx
        self.fileOffset: int = fileOffset
        self.size: int = size
        self.iteration = iteration
        
        # set by augmentation
        self.data: bytes = b''
        self.dataHexdump: str = ''
        self.sectionInfo: str = ''
        self.section: Section = Section('', 0, 0, 0, False)  # init with empty section
        self.sectionType: SectionType = SectionType.UNKNOWN
        self.disasmLines: List[UiDisasmLine] = []
        self.asmInstructions: List[AsmInstruction] = []

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
    
    def setSection(self, section: Section):
        self.section = section

    def getSection(self):
        return self.section

    def setDisasmLines(self, disasmLines):
        self.disasmLines = disasmLines

    def getDisasmLines(self):
        return self.disasmLines
    
    def setAsmInstructions(self, asminstruction):
        self.asmInstructions = asminstruction

    def getAsmInstructions(self):
        return self.asmInstructions

    def __str__(self):
        s = ""
        s += "id:{}  offset:{}  len:{}\n".format(self.idx, self.fileOffset, self.size)
        if self.sectionInfo is not None:
            s += "  Section: {}\n".format(self.sectionInfo)
        #if self.disasmLines is not None:
        #    s += "  DisasmLines: {}\n".format(self.disasmLines)
        if self.dataHexdump is not None:
            s += "  Hexdump: \n{}\n".format(self.dataHexdump)
        s += '\n'
        return s
    
    def __eq__(self, other: Match):
        # TODO: Size too?
        return self.fileOffset == other.fileOffset
    
    def __lt__(self, other: Match):
        return self.fileOffset < other.fileOffset


