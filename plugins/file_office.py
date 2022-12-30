import os
import zipfile
import io
from model.model import PluginFileFormat
import olefile

MAKRO_PATH = 'word/vbaProject.bin'


class FileOffice(PluginFileFormat):
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


    def getFileWithNewData(self, data):
        return self.getPatchedByReplacement(data)


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


class VbaAddressConverter():
    def __init__(self, ole: olefile.olefile.OleFileIO):
        self.ole = ole
        self.correlation = None
        self.sectorsize: int = None
        self.init()

    def init(self):
        arr = {}
        ole = self.ole

        # find initial sector for VBA: Root+VBA
        initialSector: int = self._findSectorForDir("Root Entry").isectStart # usually 2048
        initialSector += self._findSectorForDir("VBA").isectStart # usually 0

        # create offset -> physical addr correlation table
        nextSector: int = initialSector
        nextAddress: int = 0  # multiple of sectorsize
        for i in range(len(ole.fat)):
            if i == nextSector:
                arr[nextAddress] = ole.sectorsize * (i+1)
                nextSector = ole.fat[i]
                nextAddress += ole.sectorsize

                if ole.fat[i] == olefile.ENDOFCHAIN:
                    break

        self.correlation = arr


    def _findSectorForDir(self, name: str) -> olefile.olefile.OleDirectoryEntry:
        for id in range(len(self.ole.direntries)):
            d: olefile.olefile.OleDirectoryEntry = self.ole.direntries[id]
            if d.name == name:
                return d

        print("Error: could not find directory entry for name {}".format(name))
        return None
    
    def physicalAddressFor(self, modulepath: str, offset: int) -> int:
        # sanity checks
        mp = modulepath.split('/')
        if len (mp) != 2:
            return 0
        if mp[0] != 'VBA':
            return 0
        moduleName = mp[1]

        # find offset of module into VBA/ storage
        # these are mini-sectors (usually 64 byte)
        moduleOffsetSect = self._findSectorForDir(moduleName).isectStart
        moduleOffset = moduleOffsetSect * self.ole.minisectorsize

        # offset is originally relative to its module (e.g. "VBA/Thisdocument") 
        # make it an offset into "VBA/"" storage
        offset += moduleOffset

        # e.g. offset = 1664
        # roundDown = 1536 (multiple of 512)
        # use roundDown to find effective sector in file via self.correlation,
        # and add the remainding offset to that address
        roundDown: int = self.ole.sectorsize * round(offset/self.ole.sectorsize)
        physBase: int = self.correlation[roundDown]
        result: int = physBase + (offset - roundDown)
        return result
