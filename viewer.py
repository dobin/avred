from dataclasses import dataclass
import r2pipe
import json
from ansi2html import Ansi2HTMLConverter
import pprint
import hexdump
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum

PREV = 16
POST = 16

def GetViewData(fileContent: bytes, matches, filename):
    conv = Ansi2HTMLConverter()
    r2 = r2pipe.open(filename)
    r2.cmd("e scr.color=2") # enable terminal color output
    r2.cmd("aaa")

    baddr = r2.cmd("e bin.baddr")
    baseAddr = int(baddr, 16)

    full = ""
    for idx, match in enumerate(matches):
        match['idx'] = str(idx)

        data = fileContent[match['start']:match['end']]
        match['textHex'] = hexdump.hexdump(data, result='return')

        match['startHex'] = str(hex(baseAddr + match['start']))
        match['endHex'] = str(hex(baseAddr + match['end']))
        size = match['end'] - match['start'] + PREV + POST
        addr = baseAddr + match['start'] - PREV

        # r2: Print Dissabled (by bytes)
        asm = r2.cmd("pDJ {} @{}".format(size, addr))
        asm = json.loads(asm)

        for a in asm:
            relOffset = a['offset'] - baseAddr

            if relOffset >= match['start'] and relOffset < match['end']:
                a['part'] = True

            a['textHtml'] = conv.convert(a['text'], full=False)
            full += a["text"]

        match['asm'] = asm

    return matches



class TestType(Enum):
    COMPLETE = 1
    ONE_BYTE_MIDDLE = 2


@dataclass
class VerificationRun():
    index: int = None
    result: bool = None
    type: TestType = None
    testEntries = []
    

@dataclass
class VerifyData():
    verificationRuns = []


def GetVerifyData(fileContent: bytes, matches, filename):
    verifyData = VerifyData()

    verificationRun = VerificationRun(index=0, result=False, type=TestType.COMPLETE)
    verificationRun.testEntries.append(True)
    verificationRun.testEntries.append(False)
    verificationRun.testEntries.append(False)
    verifyData.verificationRuns.append(verificationRun)

    verificationRun = VerificationRun(index=1, result=True, type=TestType.ONE_BYTE_MIDDLE)
    verificationRun.testEntries.append(False)
    verificationRun.testEntries.append(True)
    verificationRun.testEntries.append(False)
    verifyData.verificationRuns.append(verificationRun)

    pprint.pprint(verifyData)
    return verifyData

