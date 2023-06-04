from typing import List, Set, Dict, Tuple, Optional
import re
import logging

from model.model import Outcome, OutflankPatch, Match, MatchConclusion, Data
from model.testverify import VerifyStatus
from model.extensions import Scanner
from plugins.file_pe import FilePe


class PossiblePatch():
    def __init__(self, offset, matchId):
        self.offset = offset
        self.matchId = matchId


def outflankPe(
        filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
) -> List[OutflankPatch]:
    results: List[OutflankPatch] = []

    #for line in matches[0].disasmLines:
    #    print(escape_ansi(str(line)))

    nopLines: List[PossiblePatch] = []
    int3Lines: List[PossiblePatch] = []
    for idx, match in enumerate(matches):
        if matchConclusion.verifyStatus[idx] != VerifyStatus.GOOD:
            continue

        disasmLines = match.getDisasmLines()
        for line in disasmLines:
            if not line.isPart:
                continue

            s = escape_ansi(str(line))
            if '90             nop' in s:
                nopLines.append(PossiblePatch(line.offset, idx))

            if 'cc             int3' in s:
                int3Lines.append(PossiblePatch(line.offset, idx))

    # check for double-nop (very reliable)
    for idx, possibleMatch in enumerate(nopLines):
        # check if next byte is a nop too
        if (idx+1 < len(nopLines)) and (possibleMatch.offset + 1 == nopLines[idx+1].offset):
            # $ rasm2 -a x86 -b 64 -d '89c0'
            # mov eax, eax
            outflankPatch = OutflankPatch(
                possibleMatch.matchId,
                possibleMatch.offset,
                b"\x89\xc0",
                "Replace NOP;NOP with mov eax,eax",
                "No side effects"
            )
            results.append(outflankPatch)

    # double nop is enough
    #if len(results) > 0:
    #    return results
    
    # check for int3
    for idx, possibleMatch in enumerate(int3Lines):
        outflankPatch = OutflankPatch(
            possibleMatch.matchId,
            possibleMatch.offset,
            b"\x90",
            "Replace int3 with NOP",
            "No real side effects"
        )
        results.append(outflankPatch)

    # int3 replace is fine
    #if len(results) > 0:
    #    return results
    
    # find single-nops
    for idx, possibleMatch in enumerate(nopLines):
        outflankPatch = OutflankPatch(
            possibleMatch.matchId,
            possibleMatch.offset,
            b"\xfc",
            "Replace NOP with cld (clear direction flag)",
            "Few side effects"
        )
        results.append(outflankPatch)

    # scan results, remove one's which gets detected
    if scanner is None:
        return results
    ret = []
    for patch in results:
        data: Data = filePe.DataCopy()
        data.patchData(patch.offset, patch.replaceBytes)
        if not scanner.scannerDetectsBytes(data.getBytes(), filePe.filename):
            logging.warn("Outflank OK! " + str(patch))

            ret.append(patch)
        else:
            logging.warn("Outflank failed: " + str(patch))

    return ret


# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)
