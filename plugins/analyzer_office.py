import logging
import olefile
from typing import List, Tuple
from intervaltree import Interval, IntervalTree
import os

from reducer import Reducer
from utils import *
from model.model import Match, FileInfo, UiDisasmLine
from model.extensions import Scanner
import pcodedmp.pcodedmp as pcodedmp
from plugins.file_office import FileOffice, VbaAddressConverter, OleStructurizer
from pcodedmp.disasm import DisasmEntry


def analyzeFileWord(fileOffice: FileOffice, scanner: Scanner, analyzerOptions={}) -> Tuple[List[Match], str]:
    # Scans a office file given with fileOffice with Scanner scanner. 
    # Returns all matches.
    reducer = Reducer(fileOffice, scanner)
    matches = reducer.scan(0, fileOffice.Data().getLength())
    return matches, ''


def augmentFileWord(fileOffice: FileOffice, matches: List[Match]) -> str:
    # Augment the matches with VBA decompilation and section information.
    # Returns a FileInfo object with detailed file information too.

    # dump all makros as disassembled code
    fd = open(os.devnull, 'w')
    disasmList = pcodedmp.processFile(fileOffice.filepath, output_file=fd)
    fd.close()

    oleFile = olefile.OleFileIO(fileOffice.DataAsBytes())
    disasmList = convertDisasmAddr(oleFile, disasmList)
    ac = OleStructurizer(oleFile)

    # correlate the matches with the dumped code
    m: Match
    for m in matches:
        matchDisasmLines: List[UiDisasmLine] = []

        matchBytes = fileOffice.Data().getBytesRange(m.start(), m.end())
        matchHexdump = hexdmp(matchBytes, offset=m.start())
        matchSectionName = ac.getSectionsForAddr(m.start(), m.size)

        disasmMatches = disasmList.overlap(m.fileOffset, m.fileOffset+m.size)
        for item in sorted(iter(disasmMatches)):
            text =  "line #{} (size {}): ".format(
                item.data.lineNr, item.data.end - item.data.begin)
            text += "\n" + item.data.text
            disasmLine = UiDisasmLine(
                item.data.begin, 
                item.data.begin,
                False,
                text,
                text,
            )
            matchDisasmLines.append(disasmLine)

        m.setData(matchBytes)
        m.setDataHexdump(matchHexdump)
        m.setSectionInfo(matchSectionName)
        m.setDisasmLines(matchDisasmLines)

    return ac.getStructure()


def convertDisasmAddr(ole: olefile.olefile.OleFileIO, results: List[DisasmEntry]) -> IntervalTree:
    ac = VbaAddressConverter(ole)
    it = IntervalTree()

    for result in results: 
        ite: DisasmEntry
        for ite in result:
            physBegin = ac.physicalAddressFor(ite.data.modulename, ite.begin)
            physEnd = ac.physicalAddressFor(ite.data.modulename, ite.end)
            ite.data.begin = physBegin
            ite.data.end = physEnd

            if physBegin > physEnd:
                logging.warn("Physical addresses: {}-{}, cant add interval".format(physBegin, physEnd))
            else:
                it.add(Interval(physBegin, physEnd, ite.data))
      
    return it