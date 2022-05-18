
from dataclasses import dataclass
import logging
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

    def scan(self, data):
        return False


class ScannerTest(Scanner):
    def __init__(self, detections):
        self.detections = detections

    def scan(self, data):
        for detection in self.detections:
            fileData = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData != detection.refData:
                return False

        return True    


class ScannerTestWeighted(Scanner):
    def __init__(self, detections):
        self.detections = detections

    def scan(self, data):
        # 2/3
        n = 0
        for detection in self.detections:
            fileData = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData == detection.refData:
                n += 1

        if n >= 2:
            return True
        else:
            return False


class ScannerRest(Scanner):
    def __init__(self):
        self.scanner_path = "http://10.10.10.107:9001"
        self.scanner_name = "Windows Defender"

    def scan(self, data):
        res = req.post(f"{self.scanner_path}/scan?method=run", data=data)
        jsonRes = res.json()

        if res.status_code != 200:
            print("Err: " + str(res.status_code))
            print("ERr: " + str(res.text))
        
        ret_value = jsonRes['detected']

        return ret_value
