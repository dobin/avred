
from dataclasses import dataclass
import subprocess
import logging
import re
import os
import shutil
import tempfile
import config
import requests as req

WDEFENDER_INSTALL_PATH = config.get_value("loadlibrary_path")
WDEFENDER_INSTALL_PATH_DIR = config.get_value("loadlibrary_path_dir")

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)


@dataclass
class Scanner:

    scanner_path: str = ""
    scanner_name: str = ""

    def scan(self, path):
        return False


class VMWindowsDefender(Scanner):

    def __init__(self):
        self.scanner_path = "http://10.10.10.107:9001"
        self.scanner_name = "Windows Defender"

    """
        Sends a file to a Windows VM, scans a file with Windows Defender
        and returns True if the file is detected as a threat.
    """

    def scan(self, file_path, with_name=False, method="run"):
        with open(file_path, "rb") as f:
            data = f.read()

        res = req.post(f"{self.scanner_path}/scan?method={method}", data=data)
        jsonRes = res.json()

        ret_value = jsonRes['detected']
        threat_name = "undef"

        if with_name:
            return ret_value, threat_name
        return ret_value

g_scanner = VMWindowsDefender()
