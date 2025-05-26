from typing import List, Set, Dict, Tuple, Optional
import logging

from model.model_verification import VerifyStatus
from model.model_base import Scanner, OutflankPatch
from model.model_data import Data, Match
from model.model_code import AsmInstruction
from model.model_verification import MatchConclusion
from model.model_verification import VerifyStatus
from plugins.pe.file_pe import FilePe


def outflankPe(
        filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
) -> List[OutflankPatch]:
    results: List[OutflankPatch] = []
    useTypes = [ 'mov', 'lea', 'xor', 'and', 'inc', 'cmp', 'add']
    blacklist = [ 'clc' ]

    logging.info("-> Matches: {}   VerifyStatus: B: {}".format(len(matches), len(matchConclusion.verifyStatus)))

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
            logging.warning("Outflank possible")
            return ret
        #else:
        #    logging.warning("Outflank failed: " + str(patch))
    
    # fail
    logging.info("Outflank failed with attempted {} patches".format(len(results)))
    #with open("test2-patched.exe", "wb") as f:
    #    f.write(data.getBytes())

    return []

