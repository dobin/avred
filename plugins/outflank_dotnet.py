from typing import List, Set, Dict, Tuple, Optional
import logging
import pprint

from model.testverify import VerifyStatus
from model.model import Outcome, OutflankPatch, Match, MatchConclusion, Data, AsmInstruction
from model.extensions import Scanner
from plugins.file_pe import FilePe
from dotnetfile import DotNetPE
from dotnetfile.util import BinaryStructureField, FileLocation


def outflankDotnet(
        filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
) -> List[OutflankPatch]:
    results: List[OutflankPatch] = []

    if len(matches) == 0:
        return []
    
    for idx, match in enumerate(matches):
        if idx > len(matchConclusion.verifyStatus)+1:
            logging.error("Could not find verifyStatus with index: {}. Delete outcome and scan again.".format(idx))
            break
        if matchConclusion.verifyStatus[idx] != VerifyStatus.DOMINANT:
            continue

        asm: AsmInstruction
        n = 0
        while n < len(match.asmInstructions):
            asm = match.asmInstructions[n]
    
            if 'MethodHeader: maxStack:' in asm.disasm:
                outflankPatch = OutflankPatch(
                    idx,
                    asm.offset,
                    b"0909",
                    asm,
                    asm,
                    "Replace maxStack in Method header",
                    ""
                )
                results.append(outflankPatch)
            
            if False:
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
        print("Patch: Match {} offset {}: {} <-> {}   ({})".format(
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
    return []
