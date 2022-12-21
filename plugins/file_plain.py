import logging
import os
from model.model import PluginFileFormat


class FilePlain(PluginFileFormat):
    def __init__(self):
        super().__init__()
