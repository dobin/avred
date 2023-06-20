from typing import List, Set, Dict, Tuple, Optional

import logging

from model.model import Outcome, OutflankPatch, Match, MatchConclusion, Data, AsmInstruction
from model.testverify import VerifyStatus
from model.extensions import Scanner
from plugins.file_pe import FilePe
from utils import removeAnsi


def outflankPe(
        filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
) -> List[OutflankPatch]:
    results: List[OutflankPatch] = []
    useTypes = [ 'mov', 'lea', 'xor', 'and', 'inc', 'cmp' ]
    blacklist = [ 'clc' ]

    for idx, match in enumerate(matches):
        if idx > len(matchConclusion.verifyStatus)+1:
            logging.error("Could not find verifyStatus with index: {}. Delete outcome and scan again.".format(idx))
            break
        if matchConclusion.verifyStatus[idx] != VerifyStatus.DOMINANT:
            continue

        asm: AsmInstruction
        n = 0
        while n < len(match.asmInstructions)-1:
            asm = match.asmInstructions[n]
            nextAsm = match.asmInstructions[n+1]

            if (asm.disasm == "nop" and nextAsm.disasm == "nop") or (asm.disasm == "int3" and nextAsm.disasm == "int3"):
                if not asm.registersTouch(nextAsm):
                    toPatch = nextAsm.rawBytes + asm.rawBytes
                    outflankPatch = OutflankPatch(
                        idx,
                        asm.offset,
                        b"\x89\xc0", # mov eax, eax
                        asm,
                        nextAsm,
                        "Replace with 'mov eax, eax'".format(),
                        "."
                    )
                    results.append(outflankPatch)
                    n += 1  # skip nextAsm

            if asm.type in useTypes and nextAsm.type in useTypes:
                # some commands with inappropriate types should not be used
                if asm.disasm in blacklist or nextAsm.disasm in blacklist:
                    n += 1
                    continue

                if not asm.registersTouch(nextAsm):
                    toPatch = nextAsm.rawBytes + asm.rawBytes
                    outflankPatch = OutflankPatch(
                        idx,
                        asm.offset,
                        toPatch,
                        asm,
                        nextAsm,
                        "Swap",
                        ""
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
        print("Match {} offset {}: {} <-> {}   ({})".format(
            patch.matchIdx,  hex(patch.offset), patch.asmOne.disasm, patch.asmTwo.disasm, patch.info))
        data.patchData(patch.offset, patch.replaceBytes)
        ret.append(patch)
        if not scanner.scannerDetectsBytes(data.getBytes(), filePe.filename):
            logging.warn("Outflank possible")
            return ret
        #else:
        #    logging.warn("Outflank failed: " + str(patch))
    
    # fail
    logging.info("Outflank failed with attempted {} patches".format(len(results)))
    #with open("test2-patched.exe", "wb") as f:
    #    f.write(data.getBytes())

    return []

