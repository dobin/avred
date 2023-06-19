import logging
import time
from intervaltree import Interval, IntervalTree
from typing import List
from model.extensions import Scanner, PluginFileFormat
from model.model import Data
from copy import deepcopy

from utils import *

SIG_SIZE = 8 # minimum size of a match
PRINT_DELAY_SECONDS = 1


class Reducer():
    def __init__(self, file: PluginFileFormat, scanner: Scanner):
        self.file: PluginFileFormat = file
        self.scanner = scanner

        self.lastPrintTime: int = 0
        self.chunks_tested: int = 0


    def scan(self, offsetStart, offsetEnd) -> List[Interval]:
        it = IntervalTree()
        data = self.file.Data()
        self._scanSection(data, offsetStart, offsetEnd, it)
        it.merge_overlaps(strict=False)
        return sorted(it)


    def _scanData(self, data: Data):
        newFileData: Data = self.file.getFileDataWith(data)
        return self.scanner.scannerDetectsBytes(newFileData.getBytes(), self.file.filename)


    # recursive
    def _scanSection(self, data: Data, sectionStart, sectionEnd, it):
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
            self._scanSection(dataChunkBotNull, sectionStart, sectionStart+chunkSize, it)
            self._scanSection(dataChunkTopNull, sectionStart+chunkSize, sectionEnd, it)

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
                self._scanSection(data, sectionStart, sectionStart+chunkSize, it)
                self._scanSection(data, sectionStart+chunkSize, sectionEnd, it)

        elif not detectTopNull:
            # Detection in the top half
            #logging.info("--> Do Top")
            self._scanSection(data, sectionStart, sectionStart+chunkSize, it)
        elif not detectBotNull:
            # Detection in the bottom half
            #logging.info("--> Do Bot")
            self._scanSection(data, sectionStart+chunkSize, sectionEnd, it)

        return


    def _printStatus(self):
        self.chunks_tested += 1

        currentTime = time.time()
        if currentTime > self.lastPrintTime + PRINT_DELAY_SECONDS:
            self.lastPrintTime = currentTime
            logging.info("Reducing: {} chunks done".format(self.chunks_tested))
