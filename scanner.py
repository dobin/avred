import requests as req
import logging

from model.extensions import Scanner


class ScannerRest(Scanner):
    def __init__(self, url, name):
        self.scanner_path = url
        self.scanner_name = name
        

    def scan(self, data: bytes, filename: str):
        """Returns true if file is detected"""
        params = { 'filename': filename }

        res = req.post(f"{self.scanner_path}/scan", params=params, data=data, timeout=10)
        jsonRes = res.json()

        if res.status_code != 200:
            print("Err: " + str(res.status_code))
            print("Err: " + str(res.text))
        
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
