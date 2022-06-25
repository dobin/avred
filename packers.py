from copy import copy
import zipfile
import io
from dataclasses import dataclass

@dataclass
class Packer:
    data: bytes = None

    def pack(self, data):
        pass



MAKRO_PATH = 'word/vbaProject.bin'
class PackerWord(Packer):
    def __init__(self, data):
        self.data = data  # content of the office file (e.g. .dotm)


    def getMakroData(self):
        with zipfile.ZipFile(io.BytesIO(self.data)) as thezip:
            for zipinfo in thezip.infolist():
                if zipinfo.filename == MAKRO_PATH:
                    with thezip.open(zipinfo) as thefile:
                        return thefile.read()


    def pack(self, data):
        outData = io.BytesIO()

        # create a new zip
        with zipfile.ZipFile(io.BytesIO(self.data), 'r') as zipread:
            with zipfile.ZipFile(outData, 'w') as zipwrite:
                for item in zipread.infolist():
                    # skip MAKRO
                    if item.filename != MAKRO_PATH:
                        tmp = zipread.read(item.filename)
                        zipwrite.writestr(item, tmp)

                # add our new MAKRO
                zipwrite.writestr(
                    MAKRO_PATH,
                    data
                )
        
        return outData.getvalue()
