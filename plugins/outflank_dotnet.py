from typing import List, Set, Dict, Tuple, Optional

from model.testverify import VerifyStatus
from model.model import Outcome, OutflankPatch, Match, MatchConclusion
from plugins.file_pe import FilePe

from dotnetfile import DotNetPE
from dotnetfile.util import BinaryStructureField, FileLocation


def outflankDotnet(filePe: FilePe, matches: List[Match], matchConclusion: MatchConclusion) -> List[OutflankPatch]:
    ret: List[OutflankPatch] = []

    # Find:
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
        return ret

    # nothing found
    if not metadataPatch:
        return ret
    
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
                "\x01", 
                "Modify Metadata Header: Reserved1 field", 
                "Very reliable, no side effects, but may be sigged in the future")
            ret.append(outflankPatch)
    
    return ret
