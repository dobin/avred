from typing import List, Set, Dict, Tuple, Optional
import logging

from model.testverify import VerifyStatus
from model.model import Outcome, OutflankPatch, Match, MatchConclusion, Data
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

    # Metadata header patch
    # 0x25fa4: 00 00 00 00         Metadata Header: Reserved1: 0
    metadataPatch = False
    matchIdx = -1
    for idx, match in enumerate(matches):
        if matchConclusion.verifyStatus[idx] != VerifyStatus.GOOD:
            continue

        for line in match.disasmLines:
            if 'Metadata Header: Reserved1' in line.text:
                metadataPatch = True
                matchIdx = idx
                break

    # should be a good match
    if matchConclusion.verifyStatus[matchIdx] != VerifyStatus.GOOD:
        return []

    # nothing found
    if not metadataPatch:
        return []
    
    dotnet_file = DotNetPE(filePe.filepath)
    textSection = filePe.sectionsBag.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    entry: BinaryStructureField
    for entry in dotnet_file.dotnet_metadata_header.structure_fields:
        if entry.display_name == "Reserved1":
            addr = entry.address - addrOffset
            outflankPatch = OutflankPatch(
                matchIdx,
                addr, 
                b"\x01",
                "",
                "",
                "Modify Metadata Header: Reserved1 field", 
                "Very reliable, no side effects, but may be sigged in the future")
            results.append(outflankPatch)

    # scan results, remove one's which gets detected
    if scanner is None:
        return results
    ret = []
    for patch in results:
        data: Data = filePe.DataCopy()
        data.patchData(patch.offset, patch.replaceBytes)
        if not scanner.scannerDetectsBytes(data.getBytes(), filePe.filename):
            logging.info("outflank ok")
            ret.append(patch)
        else:
            logging.warn("Outflank failed: " + str(patch))

    return ret
