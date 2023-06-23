import logging
import time
from intervaltree import Interval, IntervalTree
from typing import List
from copy import deepcopy

from model.model_base import Scanner
from model.model_data import Data, Match
from plugins.model import BaseFile

from utils import *

SIG_SIZE = 8 # minimum size of a match
PRINT_DELAY_SECONDS = 1


class Reducer():
    """Reducer will scan data in file with scanner, and return List of matches"""

    def __init__(self, file: BaseFile, scanner: Scanner):
        self.file: BaseFile = file
        self.scanner = scanner

        self.lastPrintTime: int = 0
        self.chunks_tested: int = 0
        self.iterations: int = 0
        self.matchIdx: int = 0


    def scan(self, offsetStart, offsetEnd) -> List[Match]:
        """Scan self.file.Data() from offsetStart to offsetEnd, return matches"""
        it = IntervalTree()
        data = self.file.Data()  # get the data of the file to work on
        self._scanDataPart(data, offsetStart, offsetEnd, it)
        it.merge_overlaps(strict=False)
        it = sorted(it)

        matches = convertMatchesIt(it, self.iterations, self.matchIdx)
        self.matchIdx += len(matches)
        self.iterations += 1

        return matches


    def _scanData(self, data: Data):
        """Use self.file with data, scan it and return true/false"""
        newFileData: Data = self.file.getFileDataWith(data)
        return self.scanner.scannerDetectsBytes(newFileData.getBytes(), self.file.filename)


    # recursive
    def _scanDataPart(self, data: Data, sectionStart, sectionEnd, it):
        size = sectionEnd - sectionStart
        chunkSize = int(size // 2)
        self._printStatus()
        
        #logging.info(f"Testing: {sectionStart}-{sectionEnd} with size {sectionEnd-sectionStart} (chunkSize {chunkSize} bytes)")
        #logging.info(f"Testing Top: {sectionStart}-{sectionStart+chunkSize}")
        #logging.info(f"Testing Bot: {sectionStart+chunkSize}-{sectionStart+chunkSize+chunkSize}")

        if chunkSize < 2:
            # dangling bytes
            dataBytes = data.getBytesRange(sectionStart, sectionEnd)
            logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)" 
                            + "\n" + hexdmp(dataBytes, offset=sectionStart))
            it.add ( Interval(sectionStart, sectionEnd) )
            return

        dataChunkTopNull = deepcopy(data)
        dataChunkTopNull.patchDataFill(sectionStart, chunkSize)

        dataChunkBotNull = deepcopy(data)
        dataChunkBotNull.patchDataFill(sectionStart+chunkSize, chunkSize)

        detectTopNull = self._scanData(dataChunkTopNull)
        detectBotNull = self._scanData(dataChunkBotNull)

        if detectTopNull and detectBotNull:
            #logging.info("--> Both Detected")
            # Both halves are detected
            # Continue scanning both halves independantly, but with each other halve
            # zeroed out (instead of the complete file)
            self._scanDataPart(dataChunkBotNull, sectionStart, sectionStart+chunkSize, it)
            self._scanDataPart(dataChunkTopNull, sectionStart+chunkSize, sectionEnd, it)

        elif not detectTopNull and not detectBotNull:
            #logging.info("--> Both UNdetected")
            # both parts arent detected anymore

            if chunkSize <= SIG_SIZE:
                # Small enough, no more detections.
                # The "previous" section is our match
                dataBytes = data.getBytesRange(sectionStart, sectionStart+size)
                logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)" 
                             + "\n" + hexdmp(dataBytes, offset=sectionStart))
                it.add ( Interval(sectionStart, sectionStart+size) )
            else: 
                # make it smaller still. 
                # Take complete data (not nulled)
                self._scanDataPart(data, sectionStart, sectionStart+chunkSize, it)
                self._scanDataPart(data, sectionStart+chunkSize, sectionEnd, it)

        elif not detectTopNull:
            # Detection in the top half
            #logging.info("--> Do Top")
            self._scanDataPart(data, sectionStart, sectionStart+chunkSize, it)
        elif not detectBotNull:
            # Detection in the bottom half
            #logging.info("--> Do Bot")
            self._scanDataPart(data, sectionStart+chunkSize, sectionEnd, it)

        return


    def _printStatus(self):
        self.chunks_tested += 1

        currentTime = time.time()
        if currentTime > self.lastPrintTime + PRINT_DELAY_SECONDS:
            self.lastPrintTime = currentTime
            logging.info("Reducing: {} chunks done".format(self.chunks_tested))
