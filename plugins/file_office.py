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
        self.ministream = None
        self.sectorsize: int = None
        self.init()


    def init(self):
        arr = {}
        ole = self.ole

        # find initial sector for ministream
        initialSector: int = self._getDirForName("Root Entry").isectStart

        # create offset -> physical addr ministream table
        sector: int = initialSector
        address: int = 0  # multiple of sectorsize (typically 512)
        while sector < len(self.ole.fat):
            arr[address] = ole.sectorsize * (sector+1)

            address += ole.sectorsize
            sector = ole.fat[sector]

        self.ministream = arr


    def _getDirForName(self, name:str) -> olefile.olefile.OleDirectoryEntry:
        for id in range(len(self.ole.direntries)):
            d: olefile.olefile.OleDirectoryEntry = self.ole.direntries[id]
            if d is None:
                continue
            if d.name == name:
                return d


    def print(self):
        pprint(self.ministream)


    def physicalAddressFor(self, modulepath: str, offset: int) -> int:
        # sanity checks
        mp = modulepath.split('/')
        if len (mp) != 2:
            return 0
        if mp[0] != 'VBA':
            return 0
        moduleName = mp[1]

        # If the stream is >4096: use normal sectors
        # else: use ministream sectors
        dir = self._getDirForName(moduleName)
        if dir is None: 
            return -1

        if dir.size > self.ole.minisectorcutoff:
            return self._streamAddr(moduleName, offset)
        else:
            return self._ministreamAddr(moduleName, offset)


    def _streamAddr(self, moduleName, offset):
        sector = self._getDirForName(moduleName).isectStart
        consumed = 0

        while consumed < offset:
            sector = self.ole.fat[sector]
            consumed += self.ole.sectorsize

        offset = ((sector+1) * self.ole.sectorsize) + (offset-consumed)
        return offset

    def _ministreamAddr(self, moduleName, offset):
        # add module offset into ministream
        moduleOffsetSect = self._getDirForName(moduleName).isectStart
        moduleOffset = moduleOffsetSect * self.ole.minisectorsize
        offset += moduleOffset

        # e.g. offset = 1664
        # roundDown = 1536 (multiple of 512)
        # use roundDown to find effective sector in file via self.ministream,
        # and add the remainding offset to that address
        roundDown: int = self.ole.sectorsize * round(offset/self.ole.sectorsize)
        physBase: int = self.ministream[roundDown]
        result: int = physBase + (offset - roundDown)
        return result