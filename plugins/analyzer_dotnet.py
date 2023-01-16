from intervaltree import Interval, IntervalTree
import logging
from typing import List
from model.model import Match, FileInfo, Scanner, DisasmLine
from plugins.file_pe import FilePe, Section
import os
from utils import *
import struct
from dotnetfile import DotNetPE


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
    if dotnetSections is None:
        logging.warn("No dotNet sections")

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

        if dotnetSections is not None:
            sections = list(filter(lambda x: match.start() >= x.addr and match.start() < x.addr + x.size, dotnetSections))
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
        self.null1 = None
        self.signature_rva = None
        self.null2 = None


def getDotNetSections(filePe):
    # Get more details about .net executable (e.g. streams)
    # as most of it is just in PE .text
    sections = []

    dotnet_file = DotNetPE(filePe.filepath)

    textSection = filePe.getSectionByName('.text')
    addrOffset = textSection.virtaddr - textSection.addr

    cli_header_addr = textSection.addr
    cli_header_size = dotnet_file.clr_header.HeaderSize.value

    methods_addr = cli_header_addr + cli_header_size

    metadata_header_addr = dotnet_file.clr_header.MetaDataDirectoryAddress.value
    metadata_header_addr -= addrOffset
    metadata_header_size = dotnet_file.clr_header.MetaDataDirectorySize.value

    methods_size = metadata_header_addr - methods_addr

    signature_addr = dotnet_file.clr_header.StrongNameSignatureAddress.value
    signature_addr -= addrOffset
    signature_size = dotnet_file.clr_header.StrongNameSignatureSize.value

    # CIL header
    s = Section('DotNet Header', 
        cli_header_addr,   
        cli_header_size, 
        0)
    sections.append(s)
    
    # Methods
    s = Section('methods', 
        methods_addr,    
        methods_size, 
        0)
    sections.append(s)

    s = Section('Metadata Header', 
        metadata_header_addr,
        metadata_header_size, 
        0)
    sections.append(s)

    for stream in dotnet_file.dotnet_streams:
        s = Section('Stream: ' + stream.string_representation,
            stream.address - addrOffset, 
            stream.size, 
            0)
        sections.append(s)

    s = Section('Signature', 
        signature_addr,
        signature_size, 
        0)
    sections.append(s)

    return sections
