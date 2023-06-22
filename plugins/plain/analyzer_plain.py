from typing import List, Tuple

from reducer import Reducer
from plugins.plain.file_plain import FilePlain
from utils import *


# no PE file, just check its content
def analyzeFilePlain(filePlain, scanner, analyzerOptions) -> Tuple[Match, str]:
    reducer = Reducer(filePlain, scanner)
    matches = reducer.scan(0, len(filePlain.data))
    return matches, ''


def augmentFilePlain(filePlain: FilePlain, matches: List[Match]) -> str:
    for match in matches:
        data = filePlain.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setSectionInfo('')
        #match.setDisasmLines()
