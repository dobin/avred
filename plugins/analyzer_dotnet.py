from intervaltree import Interval, IntervalTree
import logging
from typing import List
from model.model import Match, FileInfo, Scanner, DisasmLine
from plugins.file_pe import FilePe, Section
import os
from utils import *
import struct


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> FileInfo:
    fileIl = filePe.filepath + '.il'

    # reload existing .il disassembly if already exists
    if not os.path.exists(fileIl):
        cmdline = "ilspycmd -il {} > {}".format(filePe.filepath, fileIl)
        os.system(cmdline)

        if not os.path.exists(fileIl):
            logging.error("Could not decompile with command {}".format(cmdline))
            logging.error("  File {} does not exist".format(fileIl))
            return None
    
    ilspyParser = IlspyParser()
    ilspyParser.parseFile(fileIl)

    # calculate offset for disassembly
    textSection = filePe.getSectionByName('.text')
    if textSection is None:
        logging.error("No text section?")
        return None
    addrOffset = textSection.virtaddr - textSection.addr  # usually 0x1E00
    logging.info("Section Virt: 0x{:X} - Section Phys: 0x{:X} -> Offset: 0x{:X}".format(
        textSection.virtaddr, textSection.addr, addrOffset))


    dotnetSections = getDotNetSections(filePe)

    for match in matches:
        detail = []
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdmp(data, offset=match.start())
        sectionName = filePe.findSectionNameFor(match.fileOffset)
        info = sectionName

        if sectionName == ".text":  # only disassemble in .text
            # We have the physical file offset/address given in match
            # What we need is the RVA, as used by ilspy
            addr = match.start() + addrOffset
            detail, info = getDotNetDisassembly(match, addr, ilspyParser, addrOffset)

        sections = list(filter(lambda x: match.start() > x.addr and match.start() < x.addr + x.size, dotnetSections))
        if len(sections) > 0:
            info = ' '.join(s.name for s in sections)

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(info)
        match.setDetail(detail)


def getDotNetDisassembly(match: Match, addr: int, ilspyParser, addrOffset: int):
    detail = []

    ilMethod = ilspyParser.query(addr, addr+match.size)
    if ilMethod is None:
        return detail, '.text'
    logging.info("Match physical {}/0x{:X} (converted to {}/0x{:X}), disassembly found: {}".format(
        match.start(), match.start(), addr, addr, ilMethod))

    # The "method" has RVA addresses
    # But the method's instructions have addresses relative to the method start (in bytes)
    # e.g. addrBase is between 0 - len(method)
    addrBase = addr - ilMethod.addr

    # all relevant instructions
    addrTightStart = addrBase
    addrTightEnd = addrBase + match.size

    # provide some context
    addrWideStart = addrTightStart - 16
    addrWideEnd = addrTightEnd + 16

    # find all instructions of method which are part of the match
    for instrOff in sorted(ilMethod.instructions.keys()):
        if instrOff > addrWideStart and instrOff < addrWideEnd:
            d = ilMethod.instructions[instrOff]

            isPart = False
            if instrOff > addrTightStart and instrOff < addrTightEnd:
                isPart = True
            #line = "0x{:X}: {}".format(ilMethod.addr + instrOff - addrOffset, d)
            line = d

            disasmLine = DisasmLine(
                ilMethod.addr+instrOff-addrOffset,
                ilMethod.addr+instrOff,
                isPart, 
                line, 
                line
            )
            detail.append(disasmLine)

    info = ".text: {} (@RVA 0x{:X})".format(ilMethod.getName(), ilMethod.addr)
    return detail, info


class IlMethod():
    def __init__(self):
        self.name = None
        self.addr = None
        self.codeSize = None
        self.headerSize = None
        self.className = None
        self.instructions = {}

    def setName(self, name, className=''):
        self.name = name
        self.className = className

    def getName(self):
        return self.className + '::' + self.name

    def setAddr(self, addr):
        self.addr = addr

    def setCodeSize(self, size):
        self.codeSize = size

    def setHeaderSize(self, size):
        self.headerSize = size
        self.instructions[0] = "Header (size {})".format(size)

    def getSize(self):
        return self.codeSize + self.headerSize

    def addInstruction(self, instructionLine):
        # IL_0005: stloc.0
        s = instructionLine.split(' ')
        nr = s[0].lstrip('IL_').rstrip(':')
        nrInt = int(nr, 16)
        nrInt += self.headerSize
        self.instructions[nrInt] = instructionLine

    def __str__(self):
        s = ''
        s += "Func {}::{} at {} with size {}\n".format(
            self.className, self.name, self.addr, self.getSize())
        #for instruction in self.instructions:
        #    s += "  {}\n".format(instruction)
        return s


class IlspyParser():
    # IlspyParser contains the disassembled .NET IL instructions of a PE file
    # stored by function. It uses RVA addresses, as outputted by Ilspy
    def __init__(self):
        self.methods = []
        self.currentMethod = None
        self.currentClassName = ''
        self.methodsIt = IntervalTree()


    def parseFile(self, fileName):
        file = open(fileName, 'r')
        count = 0

        while True:
            line = file.readline()
            if not line:
                break
            line = line.lstrip().rstrip()

            if line.startswith('.class'):
                self.newClass(line)

            if line.startswith('.method'):
                line2 = file.readline()
                line2 = line2.lstrip().rstrip()

                self.newMethod(line + ' ' + line2)

            if line.startswith('//'):
                self.newComment(line)

            if line.startswith('IL_'):
                self.newIl(line)

            count += 1

        file.close()

        # convert
        for method in self.methods:
            if method.addr is None or method.codeSize is None or method.headerSize is None:
                #logging.error("Error in parsing: " + str(method))
                pass
            else:
                methodIt = Interval(
                    method.addr, 
                    method.addr+method.getSize(), 
                    method)
                self.methodsIt.add(methodIt)


    def query(self, begin, end) -> List[IlMethod]:
        res = self.methodsIt.overlap(begin, end)
        if len(res) == 0:
            return None
        res = list(res)[0].data
        return res


    def print(self):
        for method in self.methods:
            print(method)


    def newClass(self, line):
        # .class nested private auto ansi sealed beforefieldinit '<>c__DisplayClass0_0'
		#   extends [mscorlib]System.Object
        l = line.split(' ')
        if len(l) <= 7:
            pass
        else:
            className = l[7]
            self.currentClassName = className


    def newMethod(self, line):
        # this is mostly weak heuristics to find the method name
        # works for now...
        #
		# .method assembly hidebysig instance bool '<SetPinForPrivateKey>b__0' () cil managed         
        # .method public hidebysig specialname instance class [mscorlib]System.Collections.Generic.List`1<string> get_Files () cil managed
        # .method public hidebysig specialname rtspecialname instance void .ctor (
        self.currentMethod = IlMethod()
        self.methods.append(self.currentMethod)

        start = 0
        if 'instance ' in line:
            start = line.index('instance ')
            start += 9
        elif ' static ' in line:
            start = line.index(' static ')
            start += 8
        else:
            logging.warn("Could not find start of line: " + line)

        end = len(line)
        if 'cil managed' in line:
            end = line.index('cil managed')
        elif ' (' in line:
            end = line.index(' (')
        else:
            logging.warn("Could not find end of line: " + line)

        goodName = line[start:end]
        self.currentMethod.setName(goodName, self.currentClassName)


    def newComment(self, line):
		# // Method begins at RVA 0x2dfa
		# // Header size: 1
		# // Code size: 7 (0x7)
        l = line.split(' ')

        if line.startswith('// Method begins at RVA'):
            addr = l[5]
            addr = int(addr, 16)
            self.currentMethod.setAddr(addr)
        if line.startswith('// Header size: '):
            size = l[3]
            size = int(size)
            self.currentMethod.setHeaderSize(size)
        if line.startswith('// Code size: '):
            size = l[3]
            size = int(size)
            self.currentMethod.setCodeSize(size)


    def newIl(self, line):
        # IL_0000: ldarg.0
        l = line.split(': ')
        self.currentMethod.addInstruction(line)


class DotnetHeader():
    def __init__(self):
        self.crl_loader = None
        self.len = None
        self.clr_major = None
        self.clr_minor = None
        self.metadata_rva = None
        self.metadata_size = None
        self.flags = None
        self.entryPoint = None
        self.null = None
        self.hash = None


def getDotNetSections(filePe):
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sections = []

    # References:
    # https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-1/
    # https://www.codeproject.com/Articles/12585/The-NET-File-Format
    DOTNET_HEADER = "<8sIHHIIII48s112s"  # CLI header
    headerSize = struct.calcsize(DOTNET_HEADER)

    textSection = filePe.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr  # usually 0x1E00

    h = DotnetHeader()
    (
        h.crl_loader,    # 8s
        h.len,           # I
        h.clr_major,     # H
        h.clr_minor,     # H
        h.metadata_rva,  # I
        h.metadata_size, # I
        h.flags,         # I
        h.entryPoint,    # I
        h.null,          # 48s
        h.hash,          # 112s
    ) = struct.unpack(DOTNET_HEADER, bytes(filePe.data[textSection.addr:textSection.addr+headerSize]))

    if h.len != 72 or h.clr_major != 2 or h.clr_minor != 5:
        logging.error("Header error: Len: {}  Major: {}  Minor: {}".format( h.len, h.clr_major, h.clr_minor))
        return
    
    #print(".text         {}  Size: {}".format(textSection.addr, textSection.size))
    #print("Metadata RVA: {}  Size: {}".format(h.metadata_rva, h.metadata_size))
    metaDataOff = h.metadata_rva - addrOffset
    print("Metadata off: {}   Size: {}".format(metaDataOff, h.metadata_size))
    if metaDataOff < 0:
        logging.error("Metadata offset is negative: {}".format(metaDataOff))
        return
    # Metadata: Magic
    md_magic = filePe.data[metaDataOff:metaDataOff+4]
    if md_magic != b'\x42\x53\x4a\x42':
        print("Could not find CLR header at {}, got instead: ".format(metaDataOff, hexdmp(md_magic)))
        return

    # Metadata parsing... dear god

    # Metadata: Skip Version Information (Version is a string of arbitrary length...)
    md_ver_length_Offset = 4 + 2 + 2 + 4 # magic, majorversion, minorversion, reserved
    md_ver_length_bytes = filePe.data[metaDataOff+md_ver_length_Offset:metaDataOff+md_ver_length_Offset+4]
    # Metadata: Version String Length
    md_length = struct.unpack('<L', md_ver_length_bytes)[0]

    # Metadata: Streams Length
    md_streams_offset = md_ver_length_Offset + 4 + md_length + 2  # version_length, version, flags
    md_streams_bytes = filePe.data[metaDataOff+md_streams_offset:metaDataOff+md_streams_offset+2]
    md_streams_count = struct.unpack('<H', md_streams_bytes)[0]
    if md_streams_count > 32:
        logging.error("{} is a lot of .net streams... probably something went wrong")
        return

    s = Section('methods', textSection.addr, metaDataOff - textSection.addr, h.metadata_rva)
    sections.append(s)

    # Metadata: Streams
    offset = metaDataOff + md_streams_offset + 2  # find offset of streams table: streams count and its size (word)
    n = 0
    while n < md_streams_count:
        # First DWORD: Offset
        offset_bytes = filePe.data[offset:offset+4]
        offset += 4  # offset was DWORD
        # Second DWORD: Size
        size_bytes = filePe.data[offset:offset+4]
        offset += 4  # size was DWORD

        s_offset = struct.unpack('<I', offset_bytes)[0]
        s_size = struct.unpack('<I', size_bytes)[0]

        # Name: 0 terminated, and padded to next 4-byte...
        nameStart = offset
        nameEnd = filePe.data[nameStart:nameStart+32].index(b'\x00') + 1  # +1 as there's always one 0 byte
        nameEnd += nameStart  # nameEnd was relative to nameStart
        nameEnd = roundUpToMultiple(nameEnd, 4)  # padding...
        name = filePe.data[nameStart:nameEnd]
        name = name.rstrip(b'\x00').decode("utf-8")

        file_offset = s_offset+metaDataOff
        s = Section('Stream: ' + name, file_offset, s_size, s_offset)
        sections.append(s)

        offset = nameEnd
        n += 1

    return sections


def roundUpToMultiple(number, multiple):
    num = number + (multiple - 1)
    return num - (num % multiple)