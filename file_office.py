import os
import zipfile
import io


MAKRO_PATH = 'word/vbaProject.bin'


class FileOffice():
    def __init__(self, filepath: str):
        self.filepath: str = filepath 
        self.filename: str = os.path.basename(filepath)

        self.dataFile: bytes = None
        self.data: bytes = None


    def load(self):
        # read complete file
        with open(self.filepath, "rb") as file:
            self.dataFile = file.read()

        # get the relevant part (makro)
        with zipfile.ZipFile(io.BytesIO(self.dataFile)) as thezip:
            for zipinfo in thezip.infolist():
                if zipinfo.filename == MAKRO_PATH:
                    with thezip.open(zipinfo) as thefile:
                        self.data = thefile.read()


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
    