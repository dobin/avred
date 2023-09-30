#!/usr/bin/env python

import unittest
import r2pipe

from plugins.pe.file_pe import FilePe
from plugins.pe.analyzer_pe import analyzeFilePe
from plugins.pe.augment_pe import augmentFilePe, disassemblePe
from plugins.pe.outflank_pe import outflankPe
from tests.helpers import TestDetection
from tests.scanners import *
from model.model_data import Match
from model.model_verification import MatchConclusion, VerifyStatus
from myutils import hexdmp, hexstr, removeAnsi
from reducer import Reducer


class PeTest(unittest.TestCase):
    def test_sections(self):
        # This also tests sectionsbag
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe")

        scanSections = filePe.getScanSections()
        self.assertEqual(len(scanSections), 16)

        textSection = filePe.peSectionsBag.getSectionByName(".text")
        self.assertIsNotNone(textSection)
        self.assertEqual(textSection.scan, True)
        self.assertEqual(textSection.physaddr, 1536)
        self.assertEqual(textSection.size, 27648)
        self.assertEqual(textSection.virtaddr, 4096)
        
        peHeader = filePe.peSectionsBag.getSectionByName("Header")
        self.assertIsNotNone(peHeader)
        self.assertEqual(peHeader.scan, False)
        self.assertEqual(peHeader.physaddr, 0)
        self.assertEqual(peHeader.size, 1536)
        self.assertEqual(peHeader.virtaddr, 0)

        section = filePe.peSectionsBag.getSectionByName("nonexistant")
        self.assertIsNone(section)

        # predefined
        textOffset = 1536
        textVaddr = 4096
        dataOffset = 29184
        dataVaddr = 32768

        # .text offset
        section = filePe.peSectionsBag.getSectionByPhysAddr(textOffset)
        self.assertTrue(section.name == ".text")
        section = filePe.peSectionsBag.getSectionByPhysAddr(textOffset+100)
        self.assertTrue(section.name == ".text")
        # .data offset
        section = filePe.peSectionsBag.getSectionByPhysAddr(dataOffset)
        print(section)
        self.assertTrue(section.name == ".data")
        section = filePe.peSectionsBag.getSectionByPhysAddr(dataOffset+100)
        self.assertTrue(section.name == ".data")
        # .text virt
        section = filePe.peSectionsBag.getSectionByVirtAddr(textVaddr)
        self.assertTrue(section.name == ".text")
        section = filePe.peSectionsBag.getSectionByVirtAddr(textVaddr+100)
        self.assertTrue(section.name == ".text")
        # .data virt
        section = filePe.peSectionsBag.getSectionByVirtAddr(dataVaddr)
        self.assertTrue(section.name == ".data")
        section = filePe.peSectionsBag.getSectionByVirtAddr(dataVaddr+100)
        self.assertTrue(section.name == ".data")

        section = filePe.peSectionsBag.getSectionByPhysAddr(12345678)
        self.assertIsNone(section)
        section = filePe.peSectionsBag.getSectionByVirtAddr(12345678)
        self.assertIsNone(section)

        sections = filePe.peSectionsBag.getSectionsForPhysRange(textOffset, dataOffset + 100)
        self.assertEqual(sections[0].name, ".text")
        self.assertEqual(sections[1].name, ".data")


    def test_disasm(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        # 0x004014e0
        start = 2807  # AF7
        size = 8
        matchAsmInstructions, matchDisasmLines = disassemblePe(
            r2, filePe, start, size, moreUiLines=0)

        #for a in matchDisasmLines:
        #    print(a)
        
        self.assertEqual(start, matchDisasmLines[0].offset)
        self.assertEqual(0x004014f7, matchDisasmLines[0].rva)
        self.assertTrue('nop' in removeAnsi(matchDisasmLines[0].text))
        self.assertTrue('add rsp, 0x28' in removeAnsi(matchDisasmLines[1].text))
        self.assertTrue('ret' in removeAnsi(matchDisasmLines[2].text))
        
        self.assertEqual(start, matchAsmInstructions[0].offset)
        self.assertEqual(0x004014f7, matchAsmInstructions[0].rva)
        self.assertEqual('nop', matchAsmInstructions[0].disasm)
        self.assertEqual('add rsp, 0x28', matchAsmInstructions[1].disasm)
        self.assertEqual('ret', matchAsmInstructions[2].disasm)
        

    def test_disasm_swap_experiment(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        self.assertEqual(0x004014f7, filePe.physOffsetToRva(2807))
        self.assertEqual(2807, filePe.codeRvaToPhysOffset(0x004014f7))

        # 0x004014e0
        start = 2807  # AF7
        size = 8
        matchAsmInstructions, matchDisasmLines = disassemblePe(
            r2, filePe, start, size, moreUiLines=0)
        
        # 0x004014f7      90             nop
        # 0x004014f8      4883c428       add rsp, 0x28
        # 0x004014fc      c3             ret
        self.assertTrue('nop' in removeAnsi(matchDisasmLines[0].text))
        self.assertTrue('add rsp, 0x28' in removeAnsi(matchDisasmLines[1].text))
        self.assertTrue('ret' in removeAnsi(matchDisasmLines[2].text))

        filePe.data.swapData(2807, 1, 2807+1, 4)

        self.assertEqual(filePe.data.getBytesRange(2807, 2807+4), b"\x48\x83\xc4\x28")
        self.assertEqual(filePe.data.getBytesRange(2807+4, 2807+4+1), b"\x90")
        #matchAsmInstructions, matchDisasmLines = disassemblePe(
        #    r2, filePe, start, size, moreUiLines=0)
        #self.assertEqual('nop', matchAsmInstructions[1].disasm)
        #self.assertEqual('add rsp, 0x28', matchAsmInstructions[0].disasm)
        #self.assertEqual('ret', matchAsmInstructions[2].disasm)


    def test_disasm_outflank(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        r2 = r2pipe.open(filePe.filepath)
        r2.cmd("aaa")

        fileOffset = filePe.codeRvaToPhysOffset(0x0040154e)
        matchAsmInstructions, matchDisasmLines = disassemblePe(
            r2, filePe, fileOffset, 16, moreUiLines=0)
        
        # 16 bytes: 4*4
        # 0x0040154e      48894dd0       mov qword [var_30h], rcx    ; format
        # 0x00401552      488955d8       mov qword [var_28h], rdx    ; arg2
        # 0x00401556      4c8945e0       mov qword [var_20h], r8     ; arg3
        # 0x0040155a      4c894de8       mov qword [var_18h], r9     ; arg4
        for entry in matchAsmInstructions:
            print(entry)

        self.assertEqual(len(matchAsmInstructions), 4)

        #for entry in matchAsmInstructions:
        #    print(entry)

        matches = []
        match = Match(0, fileOffset, 16)
        matches.append(match)
        verifyStatus = [ VerifyStatus.DOMINANT ]
        matchConclusion = MatchConclusion(verifyStatus)
        augmentFilePe(filePe, matches)
        patches = outflankPe(filePe, matches, matchConclusion)
        #for patch in patches:
        #    print(patch)

        self.assertEqual(patches[0].offset, 2894)
        self.assertEqual(patches[1].offset, 2902)


    def test_augment_pedataref(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 

        matches = [ Match(0, 30144, 16) ]
        augmentFilePe(filePe, matches)
        self.assertEqual(1, len(matches))
        match = matches[0]
        self.assertEqual(1, len(match.disasmLines))
        disasmLine = match.disasmLines[0]
        self.assertTrue("lea rcx, str.Mingw_w64_runtime_failure:_n" in disasmLine.text)


    def test_pe_regions(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 
        iatRegion = filePe.regionsBag.getSectionByName("IMAGE_DIRECTORY_ENTRY_IAT")
        self.assertIsNotNone(iatRegion)
        self.assertEqual(iatRegion.physaddr, 0x8fdc)
        self.assertEqual(iatRegion.size, 416)
        self.assertEqual(iatRegion.virtaddr, 0xd1dc)


    def test_pe_augment_iat(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/test.exe") 

        ref = 0x00007480
        matches = [ Match(0, ref, 16) ]
        augmentFilePe(filePe, matches)

        match = matches[0]
        self.assertEqual(1, len(match.disasmLines))
        disasmLine = match.disasmLines[0]
        self.assertTrue("lea rbx, str.Unknown_error" in disasmLine.text)
        self.assertEqual(match.sectionInfo, ".rdata")
        self.assertEqual(disasmLine.offset, 0x7480)
        self.assertEqual(disasmLine.rva, 0x409080)
