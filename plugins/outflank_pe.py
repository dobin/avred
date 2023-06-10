from typing import List, Set, Dict, Tuple, Optional

import logging

from model.model import Outcome, OutflankPatch, Match, MatchConclusion, Data, AsmInstruction
from model.testverify import VerifyStatus
from model.extensions import Scanner
from plugins.file_pe import FilePe
from utils import removeAnsi

class PossiblePatch():
    def __init__(self, offset, matchId):
        self.offset = offset
        self.matchId = matchId


def outflankPe(
        filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
) -> List[OutflankPatch]:
    results: List[OutflankPatch] = []

    for idx, match in enumerate(matches):
        #if matchConclusion.verifyStatus[idx] != VerifyStatus.GOOD:
        #    continue

        asm: AsmInstruction
        n = 0
        while n < len(match.asmInstructions) - 1:
            asm = match.asmInstructions[n]
            nextAsm = match.asmInstructions[n+1]
            print(asm)

            if (asm.type == "nop" and nextAsm.type == "nop") or (asm.type=="int3" and nextAsm.type == "int3"):
                if not asm.registersTouch(nextAsm):
                    toPatch = nextAsm.rawBytes + asm.rawBytes
                    outflankPatch = OutflankPatch(
                        idx,
                        asm.offset,
                        b"\x89\xc0", # mov eax, eax
                        asm,
                        nextAsm,
                        "Replace NOP".format(),
                        "."
                    )
                    results.append(outflankPatch)
                    n += 1  # skip nextAsm

            if (asm.type == "mov" and nextAsm.type == "mov") or (asm.type=="lea" and nextAsm.type == "lea"):
                if not asm.registersTouch(nextAsm):
                    toPatch = nextAsm.rawBytes + asm.rawBytes
                    outflankPatch = OutflankPatch(
                        idx,
                        asm.offset,
                        toPatch,
                        asm,
                        nextAsm,
                        "Swap {}".format(asm.type),
                        "."
                    )
                    results.append(outflankPatch)
                    n += 1  # skip nextAsm

            n += 1

    # scan results, remove one's which gets detected
    if scanner is None:
        return results
    ret = []
    data: Data = filePe.DataCopy()
    for patch in results:
        print("Patch location {} with: {}  -> {}".format(patch.offset, patch.replaceBytes, patch.info))
        data.patchData(patch.offset, patch.replaceBytes)
        ret.append(patch)
        if not scanner.scannerDetectsBytes(data.getBytes(), filePe.filename):
            logging.warn("Outflank possible")
            return ret
        #else:
        #    logging.warn("Outflank failed: " + str(patch))
    
    # fail
    logging.info("Outflank failed with attempted {} patches".format(len(results)))
    return []

