import logging
import time
from intervaltree import Interval, IntervalTree
from typing import List
from model.extensions import Scanner, PluginFileFormat

from utils import *

SIG_SIZE = 128
PRINT_DELAY_SECONDS = 1


class Reducer():
    def __init__(self, file: PluginFileFormat, scanner: Scanner):
        self.file = file
        self.scanner = scanner

        self.lastPrintTime = 0
        self.chunks_tested = 0


    def scan(self, offsetStart, offsetEnd) -> List[Interval]:
        it = IntervalTree()
        data = self.file.getData()

        # pre check: defeat hash of binary (or scan would take very long for nothing)
        if self.scanIsHash():
            logging.info("Signature is hash based")
            return [Interval(0, len(data))]
        else:
            self._scanSection(data, offsetStart, offsetEnd, it)
            it.merge_overlaps(strict=False)
            return sorted(it)


    def scanIsHash(self):
        """check if the detection is hash based (complete file)"""
        size = len(self.file.getData())
        data = self.file.getData()

        firstOff = int(size//3)
        firstByte = makeWithPatch(data, firstOff, 1)
        firstRes = self._scanData(firstByte)

        lastOff = int((size//3) * 2)
        lastByte = makeWithPatch(data, lastOff, 1)
        lastRes = self._scanData(lastByte)

        logging.info("Change: {} {} {}".format(firstOff, lastOff, size))
        logging.info("  Result: {} {}".format(firstRes, lastRes))

        if not firstRes and not lastRes:
            return True
        else:
            return False
        

    def _scanData(self, data):
        newFile = self.file.getFileWithNewData(data)
        return self.scanner.scan(newFile, self.file.filename)


    def printStatus(self):
        self.chunks_tested += 1

        currentTime = time.time()
        if currentTime > self.lastPrintTime + PRINT_DELAY_SECONDS:
            self.lastPrintTime = currentTime
            logging.info("Reducing: {} chunks done".format(self.chunks_tested))


    # recursive
    def _scanSection(self, data, sectionStart, sectionEnd, it):
        size = sectionEnd - sectionStart
        chunkSize = int(size // 2)
        self.printStatus()
        
        logging.debug(f"Testing: {sectionStart}-{sectionEnd} with size {sectionEnd-sectionStart} (chunkSize {chunkSize} bytes)")
        #logging.debug(f"Testing Top: {sectionStart}-{sectionStart+chunkSize} (chunkSize {chunkSize} bytes)")
        #logging.debug(f"Testing Bot: {sectionStart+chunkSize}-{sectionStart+chunkSize+chunkSize} (chunkSize {chunkSize} bytes)")

        if chunkSize < 2:
            logging.debug(f"Very small chunksize for a signature, weird. Ignoring. {sectionStart}-{sectionEnd}")
            return

        chunkTopNull = makeWithPatch(data, sectionStart, chunkSize)
        chunkBotNull = makeWithPatch(data, sectionStart+chunkSize, chunkSize)

        detectTopNull = self._scanData(chunkTopNull)
        detectBotNull = self._scanData(chunkBotNull)

        if detectTopNull and detectBotNull:
            # Both halves are detected
            # Continue scanning both halves independantly, but with each other halve
            # zeroed out (instead of the complete file)
            logging.debug("--> Both halves are detected!")
            
            self._scanSection(chunkBotNull, sectionStart, sectionStart+chunkSize, it)
            self._scanSection(chunkTopNull, sectionStart+chunkSize, sectionEnd, it)

        elif not detectTopNull and not detectBotNull:
            # both parts arent detected anymore

            if chunkSize < SIG_SIZE:
                # Small enough, no more detections
                logging.debug("No more detection")
                data = data[sectionStart:sectionStart+size]

                logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)" + "\n" + hexdmp(data, offset=sectionStart))
                it.add ( Interval(sectionStart, sectionStart+size) )
            else: 
                # make it smaller still. Take complete data (not nulled)
                logging.debug("--> No detections anymore, but too big. Continue anyway...")
                self._scanSection(data, sectionStart, sectionStart+chunkSize, it)
                self._scanSection(data, sectionStart+chunkSize, sectionEnd, it)

            #print("TopNull:")
            #data = chunkBotNull[sectionStart:sectionStart+chunkSize]
            #print(hexdump.hexdump(data, result='return'))

            #print("BotNull:")
            #data = chunkTopNull[sectionStart+chunkSize:sectionStart+chunkSize+chunkSize]
            #print(hexdump.hexdump(data, result='return'))

        elif not detectTopNull:
            # Detection in the top half
            logging.debug("--> Do Top")
            self._scanSection(data, sectionStart, sectionStart+chunkSize, it)
        elif not detectBotNull:
            # Detection in the bottom half
            logging.debug("--> Do Bot")
            self._scanSection(data, sectionStart+chunkSize, sectionEnd, it)

        return


def makeWithPatch(data, offset, size):
    patch = bytes(chr(0),'ascii') * int(size)
    goat = data[:offset] + patch + data[offset+size:]
    return goat
