import logging
import olefile
from typing import List
from reducer import Reducer
from utils import *
from model.model import Match, FileInfo, Scanner, DisasmLine
import pcodedmp.pcodedmp as pcodedmp
from plugins.file_office import FileOffice, VbaAddressConverter, OleStructurizer
from pcodedmp.disasm import DisasmEntry
from intervaltree import Interval, IntervalTree


def analyzeFileWord(fileOffice: FileOffice, scanner: Scanner, analyzerOptions={}) -> IntervalTree:
    # Scans a office file given with fileOffice with Scanner scanner. 
    # Returns all matches.
    makroData = fileOffice.data

    reducer = Reducer(fileOffice, scanner)
    matchesIntervalTree = reducer.scan(0, len(makroData))
    return matchesIntervalTree


def augmentFileWord(fileOffice: FileOffice, matches: List[Match]) -> FileInfo:
    # Augment the matches with VBA decompilation and section information.
    # Returns a FileInfo object with detailed file information too.

    # dump all makros as disassembled code
    fd = open('/dev/null', 'w')
    disasmList = pcodedmp.processFile(fileOffice.filepath, output_file=fd)
    fd.close()

    oleFile = olefile.OleFileIO(fileOffice.data)
    disasmList = convertDisasmAddr(oleFile, disasmList)
    ac = OleStructurizer(oleFile)

    # correlate the matches with the dumped code
    m: Match
    for m in matches:
        data = fileOffice.data[m.start():m.end()]
        dataHexdump = hexdmp(data, offset=m.start())
        sectionName = ac.getSectionsForAddr(m.start(), m.size)

        disasmMatches = disasmList.overlap(m.fileOffset, m.fileOffset+m.size)
        details = []
        for item in iter(disasmMatches):
            text =  "line #{} (0x{:X}-0x{:X}): ".format(
                item.data.lineNr, item.data.begin, item.data.end)
            text += "\n" + item.data.text
            disasmLine = DisasmLine(
                item.data.begin, 
                item.data.begin,
                False,
                text,
                text,
            )
            details.append(disasmLine)

        m.setData(data)
        m.setDataHexdump(dataHexdump)
        m.setInfo(sectionName)
        m.setDetail(details)

    fileInfo = FileInfo(fileOffice.filename, 0, ac.getStructure())
    return fileInfo


def convertDisasmAddr(ole: olefile.olefile.OleFileIO, results: List[DisasmEntry]) -> IntervalTree:
    # the output of pcodedmp is wrong. Convert results to real physical addresses.
    # use the extracted vbaProject.bin from fileOffice.data
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