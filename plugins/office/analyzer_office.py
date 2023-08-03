import logging
from typing import List, Tuple
import time
import datetime

from reducer import Reducer
from model.model_base import Scanner, ScanInfo, ScanSpeed
from model.model_data import Match
import pcodedmp.pcodedmp as pcodedmp
from plugins.office.file_office import FileOffice


def analyzeFileWord(fileOffice: FileOffice, scanner: Scanner, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
    # Scans a office file given with fileOffice with Scanner scanner. 
    # Returns all matches.
    reducer = Reducer(fileOffice, scanner)
    scanInfo = ScanInfo(scanner.scanner_name, ScanSpeed.Normal)

    timeStart = time.time()
    matches = reducer.scan(0, fileOffice.Data().getLength())
    scanInfo.scanDuration = round(time.time() - timeStart)

    return matches, scanInfo
