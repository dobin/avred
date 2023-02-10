import logging
import os
from model.extensions import PluginFileFormat


class FilePlain(PluginFileFormat):
    def __init__(self):
        super().__init__()
