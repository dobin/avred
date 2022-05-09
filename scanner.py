
from dataclasses import dataclass
import subprocess
import logging
import re
import os
import shutil
import tempfile
import config
import requests as req

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


class ScannerTest(Scanner):
    def __init__(self, detections):
        self.detections = detections

    def scan(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()

        for detection in self.detections:
            fileData = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData != detection.refData:
                return False

        return True    


class ScannerRest(Scanner):
    def __init__(self):
        self.scanner_path = "http://10.10.10.107:9001"
        self.scanner_name = "Windows Defender"

    def scan(self, file_path, with_name=False, method="run"):
        with open(file_path, "rb") as f:
            data = f.read()

        res = req.post(f"{self.scanner_path}/scan?method={method}", data=data)
        jsonRes = res.json()

        if res.status_code != 200:
            print("Err: " + str(res.status_code))
            print("ERr: " + str(res.text))
        
        ret_value = jsonRes['detected']
        threat_name = "undef"

        if with_name:
            return ret_value, threat_name
        return ret_value
