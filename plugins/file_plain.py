import logging
import os
from model.model import FileFormat


class FilePlain(FileFormat):
    def __init__(self):
        self.filepath = None
        self.filename = None
        self.data = b""
