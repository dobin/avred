import requests as req
import logging
import yara
import brotli
import os
import pickle
import hashlib
import time
import shutil

from model.model_base import Scanner
from config import config


HASHCACHE_FILE = "hashcache.pickle"


class HashCacheEntry():
    def __init__(self, filename, result, scanTime, scannerName):
        self.filename = filename
        self.scanTime = scanTime
        self.result = result
        self.scannerName = scannerName


class HashCache():
    def __init__(self):
        self.cache = {}

    def load(self):
        if os.path.exists(HASHCACHE_FILE):
            with open(HASHCACHE_FILE, "rb") as file:
                logging.info("Loading HashCache")
                self.cache = pickle.load(file)
                logging.info("  {} hashes loaded".format(len(self.cache)) )


    def save(self):
        new = HASHCACHE_FILE + ".new"
        with open(new, "wb") as file:
            logging.info("Saving HashCache ({})".format(len(self.cache)))
            pickle.dump(self.cache, file)
        shutil.move(new, HASHCACHE_FILE)


    def getResult(self, data, scannerName):
        hash = hashlib.md5(data).hexdigest() + "_" + scannerName

        if not hash in self.cache:
            logging.debug("Not exist: {}".format(hash))

        return self.cache.get(hash, None)


    def addResult(self, data, filename, result, scanTime, scannerName):
        hash = hashlib.md5(data).hexdigest()  + "_" + scannerName
        logging.debug("Add result: {}".format(hash))
        self.cache[hash] = HashCacheEntry(filename, result, scanTime, scannerName)
        

hashCache = HashCache()


class ScannerRest(Scanner):
    def __init__(self, url, name):
        self.scanner_path = url
        self.scanner_name = name


    def scannerDetectsBytes(self, data: bytes, filename: str, useBrotli=True):
        """Returns true if file is detected"""

        if config.get("hashCache") == True:
            cacheResult = hashCache.getResult(data, self.scanner_name)
            if cacheResult is not None:
                return cacheResult.result

        params = { 'filename': filename, 'brotli': useBrotli }
        if useBrotli:
            scanData = brotli.compress(data)
        else:
            scanData = data

        timeStart = time.time()
        try:
            res = req.post(f"{self.scanner_path}/scan", params=params, data=scanData, timeout=10)
        except:
            # try again
            logging.warn("Invalid server answer, retrying once")
            res = req.post(f"{self.scanner_path}/scan", params=params, data=scanData, timeout=10)
        jsonRes = res.json()
        scanTime = round(time.time() - timeStart, 3)

        if res.status_code != 200:
            logging.error("Err: " + str(res.status_code))
            logging.error("Err: " + str(res.text))
        
        ret_value = jsonRes['detected']

        if config.get("hashCache") == True:
            hashCache.addResult(data, filename, ret_value, scanTime, self.scanner_name)
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
