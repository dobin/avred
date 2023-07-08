from typing import List, Tuple
import time
import datetime

from model.model_base import ScanInfo, ScanSpeed
from reducer import Reducer
from plugins.plain.file_plain import FilePlain
from utils import *


# no PE file, just check its content
def analyzeFilePlain(filePlain, scanner, analyzerOptions) -> Tuple[Match, ScanInfo]:
    reducer = Reducer(filePlain, scanner)
    scanInfo = ScanInfo(scanner.scanner_name, ScanSpeed.Normal)

    timeStart = time.time()
    matches = reducer.scan(0, len(filePlain.data))
    scanInfo.scanDuration = round(time.time() - timeStart)

    return matches, scanInfo


def augmentFilePlain(filePlain: FilePlain, matches: List[Match]) -> str:
    for match in matches:
        data = filePlain.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setSectionInfo('')
        #match.setDisasmLines()
