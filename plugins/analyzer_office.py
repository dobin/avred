
import copy
import logging
from re import I

from reducer import Reducer
from utils import *
from model.model import Match
import pcodedmp.pcodedmp as pcodedmp


def analyzeFileWord(fileOffice, scanner, analyzerOptions):
    makroData = fileOffice.data

    reducer = Reducer(fileOffice, scanner)
    matchesIntervalTree = reducer.scan(0, len(makroData))
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
        
        match = Match(idx, m.begin, m.end-m.begin)
        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(sectionName)
        match.setDetail(detail)

        matches.append(match)
        idx += 1

    return matches
