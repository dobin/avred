import os
import zipfile
import io
from model.model import FileFormat

MAKRO_PATH = 'word/vbaProject.bin'


class FileOffice(FileFormat):
    def __init__(self):
        super().__init__()


    def loadFromMem(self, dataFile: bytes) -> bool:
        self.filepath = "test.exe"
        self.filename = "test.exe"
        self.fileData = dataFile
        return self.parseFile()


    def parseFile(self) -> bool:
        # get the relevant part (makro)
        with zipfile.ZipFile(io.BytesIO(self.fileData)) as thezip:
            for zipinfo in thezip.infolist():
                if zipinfo.filename == MAKRO_PATH:
                    with thezip.open(zipinfo) as thefile:
                        self.data = thefile.read()
                        return True
        return False


    def getPatchedByReplacement(self, data: bytes) -> bytes:
        outData = io.BytesIO()

        # create a new zip
        with zipfile.ZipFile(io.BytesIO(self.fileData), 'r') as zipread:
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
