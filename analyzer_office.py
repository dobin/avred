
import copy
import logging
from re import I

from reducer import scanData
from packers import PackerWord
from utils import *
from model import Match
import argparse
import pcodedmp.pcodedmp as pcodedmp


def analyzeFileWord(fileOffice, scanner, verify=True):
    makroData = fileOffice.data

    packer = PackerWord(fileOffice)
    scanner.setPacker(packer)

    matchesIntervalTree = scanData(scanner, makroData, fileOffice.filename, 0, len(makroData))
    return matchesIntervalTree


def augmentFileWord(fileOffice, matchesIntervalTree):
    matches = []
    results = pcodedmp.processFile("tests/data/P5-5h3ll.docm")
    
    idx = 0
    for m in matchesIntervalTree:
        data = fileOffice.data[m.begin:m.end]
        dataHexdump = hexdump.hexdump(data, result='return')
        sectionName = 'word/vbaProject.bin'
        detail = ''

        itemSet = results[0].at(m.begin)
        if len(itemSet) > 0:
            item = next(iter(itemSet))
            detail = "{} {} {}: ".format(item.data.lineNr, item.data.begin, item.data.end) + "\n" + item.data.text
        
        match = Match(idx, data, dataHexdump, m.begin, m.end-m.begin, sectionName, detail)
        matches.append(match)
        idx += 1

    return matches


def verifyFile(officeFile, matches, scanner, patchSize=None):
    print("Patching file with results...")
    logging.info("Patching file with results...")

    officeFile = copy.deepcopy(officeFile)
    data = copy.copy(officeFile.data)

    for i in matches:
        size = i.end - i.begin
        if patchSize is not None:
            size = patchSize

        print(f"Patch: {i.begin}-{i.end} size {size}")
        logging.info(f"Patch: {i.begin}-{i.end} size {size}")

        data = patchData(data, i.begin, size)

        if not scanner.scan(officeFile.getPatchedByReplacement(data), officeFile.filename):
            print("Success, not detected!")
            logging.info("Success, not detected!")
            return

    print("Still detected? :-(")
    logging.info("Still detected? :-(")

