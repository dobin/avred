from dataclasses import dataclass
from file_office import FileOffice

@dataclass
class Packer:
    data: bytes = None

    def pack(self, data) -> bytes:
        pass


class PackerWord(Packer):
    def __init__(self, fileOffice: FileOffice):
        self.fileOffice = fileOffice

    def pack(self, data: bytes) -> bytes:
        return self.fileOffice.getPatchedByReplacement(data)
