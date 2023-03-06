import requests as req
from model.extensions import Scanner


class ScannerRest(Scanner):
    def __init__(self, url, name):
        self.scanner_path = url
        self.scanner_name = name
        

    def scan(self, data, filename):
        params = { 'filename': filename }

        res = req.post(f"{self.scanner_path}/scan", params=params, data=data)
        jsonRes = res.json()

        if res.status_code != 200:
            print("Err: " + str(res.status_code))
            print("Err: " + str(res.text))
        
        ret_value = jsonRes['detected']
        return ret_value
