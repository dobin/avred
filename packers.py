from file_office import FileOffice
from model import Packer

class PackerWord(Packer):
    def __init__(self, fileOffice: FileOffice):
        self.fileOffice = fileOffice

    def pack(self, data: bytes) -> bytes:
        return self.fileOffice.getPatchedByReplacement(data)
