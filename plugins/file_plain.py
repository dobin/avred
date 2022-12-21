import logging
import os
from model.model import FileFormat


class FilePlain(FileFormat):
    def __init__(self):
        super().__init__()
