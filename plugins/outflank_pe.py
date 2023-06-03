from model.model import Outcome, OutflankPatch, Match, MatchConclusion
from model.testverify import VerifyStatus

from plugins.file_pe import FilePe
from typing import List, Set, Dict, Tuple, Optional
import re


class PossiblePatch():
    def __init__(self, offset, matchId):
        self.offset = offset
        self.matchId = matchId


def outflankPe(filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion) -> List[OutflankPatch]:
    ret: List[OutflankPatch] = []

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
                1337,
                possibleMatch.offset,
                "\x89\xc0",
                "Replace NOP;NOP with mov eax,eax",
                "No side effects"
            )
            ret.append(outflankPatch)

    # double nop is enough
    if len(ret) > 0:
        return ret
    
    # check for int3
    for idx, possibleMatch in enumerate(int3Lines):
        outflankPatch = OutflankPatch(
            possibleMatch.matchId,
            possibleMatch.offset,
            "\xfc",
            "Replace int3 with NOP",
            "No real side effects"
        )
        ret.append(outflankPatch)

    # int3 replace is fine
    if len(ret) > 0:
        return ret
    
    # find single-nops
    for idx, possibleMatch in enumerate(nopLines):
        outflankPatch = OutflankPatch(
            possibleMatch.matchId,
            possibleMatch.offset,
            "\xfc",
            "Replace NOP with cld (clear direction flag)",
            "Few side effects"
        )
        ret.append(outflankPatch)

    return ret


# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)
