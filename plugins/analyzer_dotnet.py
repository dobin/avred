from intervaltree import Interval, IntervalTree
import logging
from typing import List
from model.model import Match, FileInfo, Scanner
from plugins.file_pe import FilePe
import os
from utils import *


def augmentFileDotnet(filePe: FilePe, matches: List[Match]) -> FileInfo:
    fileIl = filePe.filepath + '.il'

    if not os.path.exists(fileIl):
        cmdline = "ilspycmd -il {} > {}".format(filePe.filepath, fileIl)
        os.system(cmdline)

        if not os.path.exists(fileIl):
            logging.error("Could not decompile")
            return None
    
    ilspyParser = IlspyParser()
    ilspyParser.parseFile(fileIl)
    #ilspyParser.print()

    for match in matches:
        data = filePe.data[match.start():match.end()]
        dataHexdump = hexdump.hexdump(data, result='return')
        section = filePe.findSectionFor(match.fileOffset)
       
        addrOffset = 0x1E00

        detail = []
        if section.name == ".text":
            addr = match.start() + addrOffset
            ilMethod = ilspyParser.query(addr, addr+match.size)

            if ilMethod is not None:
                print("-> Found!: " + str(match.start()))

                addrBase = addr - ilMethod.addr

                addrTightStart = addrBase
                addrTightEnd = addrBase + match.size

                addrWideStart = addrTightStart - 16
                addrWideEnd = addrTightEnd + 16

                for instrOff in sorted(ilMethod.instructions.keys()):
                    if instrOff > addrWideStart and instrOff < addrWideEnd:
                        d = ilMethod.instructions[instrOff]
                        res = {}
                        if instrOff > addrTightStart and instrOff < addrTightEnd:
                            res['part'] = True
                        else: 
                            res['part'] = False
                        res['textHtml'] = d
                        res['text'] = d
                        detail.append(res)

        match.setData(data)
        match.setDataHexdump(dataHexdump)
        match.setInfo(section.name)
        match.setDetail(detail)


class IlMethod():
    def __init__(self):
        self.name = None
        self.addr = None
        self.size = None
        self.className = None
        self.instructions = {}

    def setName(self, name, className=''):
        self.name = name
        self.className = className

    def setAddr(self, addr):
        self.addr = addr

    def setSize(self, size):
        self.size = size

    def addInstruction(self, instructionLine):
        # IL_0005: stloc.0
        s = instructionLine.split(' ')
        nr = s[0].lstrip('IL_').rstrip(':')
        nrInt = int(nr, 16)
        self.instructions[nrInt] = instructionLine

    def __str__(self):
        s = ''
        s += "Func {}::{} at {} with size {}:\n".format(
            self.className, self.name, self.addr, self.size)
        for instruction in self.instructions:
            s += "  {}\n".format(instruction)
        return s


class IlspyParser():
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
            if method.addr is None or method.size is None:
                #logging.error("Error in parsing: " + str(method))
                pass
            else:
                methodIt = Interval(method.addr, method.addr+method.size, method)
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
		# .method assembly hidebysig 
		#	instance bool '<SetPinForPrivateKey>b__0' () cil managed         
        self.currentMethod = IlMethod()
        self.methods.append(self.currentMethod)

        l = line.split(' ')
        self.currentMethod.setName(l[5], self.currentClassName)


    def newComment(self, line):
		# // Method begins at RVA 0x2dfa
		# // Header size: 1
		# // Code size: 7 (0x7)
        l = line.split(' ')

        if line.startswith('// Method begins at RVA'):
            addr = l[5]
            addr = int(addr, 16)
            self.currentMethod.setAddr(addr)
        if line.startswith('// Code size: '):
            size = l[3]
            size = int(size)
            self.currentMethod.setSize(size)


    def newIl(self, line):
        # IL_0000: ldarg.0
        l = line.split(': ')
        self.currentMethod.addInstruction(line)

