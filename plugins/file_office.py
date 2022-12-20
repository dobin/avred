import os
import zipfile
import io
from model.model import FileFormat

MAKRO_PATH = 'word/vbaProject.bin'


class FileOffice(FileFormat):
    def __init__(self):
        self.filepath: str = None 
        self.filename: str = None

        self.dataFile: bytes = None
        self.data: bytes = None


    def loadFromFile(self, filepath: str) -> bool:
        self.filepath = filepath 
        self.filename = os.path.basename(filepath)

        # read complete file
        with open(self.filepath, "rb") as file:
            self.dataFile = file.read()

        return self._loadData()


    def loadFromMem(self, dataFile: bytes) -> bool:
        self.filepath = "test.exe"
        self.filename = "test.exe"
        self.dataFile = dataFile
        return self._loadData()


    def parseFile(self) -> bool:
        # get the relevant part (makro)
        with zipfile.ZipFile(io.BytesIO(self.dataFile)) as thezip:
            for zipinfo in thezip.infolist():
                if zipinfo.filename == MAKRO_PATH:
                    with thezip.open(zipinfo) as thefile:
                        self.data = thefile.read()
                        return True
        return False


    def getPatchedByReplacement(self, data: bytes) -> bytes:
        outData = io.BytesIO()

        # create a new zip
        with zipfile.ZipFile(io.BytesIO(self.dataFile), 'r') as zipread:
            with zipfile.ZipFile(outData, 'w') as zipwrite:
                for item in zipread.infolist():
                    # skip existing makro
                    if item.filename != MAKRO_PATH:
                        tmp = zipread.read(item.filename)
                        zipwrite.writestr(item, tmp)

                # add our new makro
                zipwrite.writestr(
                    MAKRO_PATH,
                    data
                )
        
        return outData.getvalue()


    def getPatchedByOffset(self, offset: int, patch: bytes) -> bytes:
        goat = self.data[:offset] + patch + self.data[offset+len(patch):]
        return self.getPatchedByReplacement(goat)
