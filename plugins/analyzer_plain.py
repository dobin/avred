from typing import List

from reducer import Reducer
from plugins.file_plain import FilePlain
from model.model import Match, FileInfo, UiDisasmLine
from utils import *


# no PE file, just check its content
def analyzeFilePlain(filePlain, scanner, analyzerOptions):
    reducer = Reducer(filePlain, scanner)
    matchesIntervalTree = reducer.scan(0, len(filePlain.data))
    return matchesIntervalTree


def augmentFilePlain(filePlain: FilePlain, matches: List[Match]) -> str:
    for match in matches:
        data = filePlain.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setSectionInfo('')
        #match.setDisasmLines()
