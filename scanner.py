import requests as req
import logging
import yara

from model.model_base import Scanner


class ScannerRest(Scanner):
    def __init__(self, url, name):
        self.scanner_path = url
        self.scanner_name = name
        

    def scannerDetectsBytes(self, data: bytes, filename: str):
        """Returns true if file is detected"""
        params = { 'filename': filename }

        ###
        res = req.post(f"{self.scanner_path}/scan", params=params, data=data, timeout=10)
        jsonRes = res.json()

        if res.status_code != 200:
            logging.error("Err: " + str(res.status_code))
            logging.error("Err: " + str(res.text))
        
        ret_value = jsonRes['detected']
        return ret_value


    def checkOnlineOrExit(self):
        try:
            res = req.post(f"{self.scanner_path}/test", timeout=1)
        except:
            logging.error("Scanner {} is not online at: {}".format(
                self.scanner_name, self.scanner_path
            ))
            exit(1)


class ScannerYara(Scanner):
    def __init__(self, url, name):
        self.scanner_path = url
        self.scanner_name = name
        

    def scannerDetectsBytes(self, data: bytes, filename: str):
        """Returns true if file is detected"""
        rule = yara.compile(filepath=self.scanner_path)
        matches = rule.match(data=data)
        if len(matches) > 0:
            return True
        return False


    def checkOnlineOrExit(self):
        try:
            rule = yara.compile(filepath=self.scanner_path)
        except Exception as e:
            logging.error("Scanner Yara failed for file {} error: {}".format(
                self.scanner_path, e,
            ))
            exit(1)
