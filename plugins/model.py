from dataclasses import dataclass
import os
import copy
from abc import abstractmethod
from typing import List, Tuple, Set

from model.model_data import Match, Data
from model.model_verification import MatchConclusion
from model.model_base import Scanner, OutflankPatch


class BaseFile():
    """Interface for file format plugins"""
    def __init__(self):
        self.filepath: str = None
        self.filename: str = None
        self.fileData: Data = Data(b'')  # The content of the file
        self.data: Data = Data(b'')      # The data we work on
        

    def parseFile(self) -> bool:
        self.data = self.fileData  # Default: File is Data


    def Data(self) -> Data:
        return self.data
    

    def DataCopy(self) -> Data:
        return copy.deepcopy(self.data)


    def DataAsBytes(self) -> bytes:
        return self.data.getBytes()


    def getFileDataWith(self, data: Data) -> Data:
        return data  # Default: Data is the File. No need to modify.


    def loadFromFile(self, filepath: str) -> bool:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(self.filepath, "rb") as f:
            self.fileData = Data(f.read())

        return self.parseFile()
    
    def saveToFile(self, filepath: str):
        with open(filepath, "wb") as f:
            f.write(self.fileData.getBytes())


    def loadFromMem(self, data: bytes, filename: str) -> bool:
        self.filepath = filename
        self.filename = filename
        self.fileData = Data(data)
        return self.parseFile()


class Plugin():
    def __init__(self):
        pass
    
    @abstractmethod
    def makeFile(self, filepath: str):
        pass

    @abstractmethod
    def analyzeFile(self, file: BaseFile, scanner: Scanner, analyzerOptions={}):
        pass

    @abstractmethod
    def augmentMatches(self, file: BaseFile, matches: List[Match]) -> str:
        pass

    @abstractmethod
    def outflankFile(
        self, filePe: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        pass
