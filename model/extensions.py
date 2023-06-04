from dataclasses import dataclass
import os
import copy

from model.model import Data


@dataclass
class Scanner:
    """Interface to the AV scanner"""
    scanner_path: str = ""
    scanner_name: str = ""

    def scannerDetectsBytes(self, data: bytes, filename: str):
        pass


class PluginFileFormat():
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


    def loadFromMem(self, data: bytes, filename: str) -> bool:
        self.filepath = filename
        self.filename = filename
        self.fileData = Data(data)
        return self.parseFile()