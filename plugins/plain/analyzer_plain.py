from typing import List, Tuple
import time
import datetime

from model.model_base import ScanInfo, ScanSpeed, Match
from reducer import Reducer
from plugins.plain.file_plain import FilePlain
from myutils import hexdmp


# no PE file, just check its content
def analyzeFilePlain(filePlain: FilePlain, scanner, reducer, analyzerOptions) -> Tuple[Match, ScanInfo]:
    scanInfo = ScanInfo(scanner.scanner_name, ScanSpeed.Normal)

    timeStart = time.time()
    matches = reducer.scan(0, filePlain.Data().getLength())
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
