import logging
import os


class FilePlain():
    def __init__(self):
        self.filepath = None
        self.filename = None
        self.data = b""


    def loadFromFile(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(self.filepath, "rb") as f:
            self.data = f.read()
