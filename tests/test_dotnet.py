from typing import List
import unittest

from model.model_data import Match
from plugins.dotnet.augment_dotnet import DncilParser, augmentFileDotnet, getDotNetSections, getDotNetDisassemblyHeader
from plugins.dotnet.dotnet_data import DotnetData
from plugins.dotnet.dncilparser import DncilParser
from plugins.pe.file_pe import FilePe
from plugins.dotnet.outflank_dotnet import outflankDotnet



class DotnetDataTest(unittest.TestCase):
    def test_dotnetdata(self):
        dotnetData = DotnetData("tests/data/dotnet-test.dll")
        dotnetData.init()
        entries = dotnetData.findBy(0x42c, 0x42c+8)

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.tableName, "MethodDef")
        self.assertEqual(entry.offset, 0x42c)
        self.assertEqual(entry.size, 14)

        
        


class DotnetDisasmTest(unittest.TestCase):
    def test_dncilparser(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/dotnet-test.dll")
        dncilParser = DncilParser(filePe.filepath)

        offset = 0x029c # file offset
        headerSize = 1
        codeSize = 24
        rva = 0x209c

        ilMethods = dncilParser.getMethods(offset, offset+16)
        self.assertEqual(len(ilMethods), 1)
        ilMethod = ilMethods[0]

        self.assertIsNotNone(ilMethod)
        self.assertTrue('g__MyMethod' in ilMethod.getName())
        self.assertEqual(ilMethod.getOffset(), offset)
        self.assertEqual(ilMethod.getRva(), rva)
        self.assertEqual(ilMethod.getSize(), headerSize + codeSize)
        self.assertEqual(ilMethod.getCodeSize(), codeSize)
        self.assertEqual(ilMethod.getHeaderSize(), headerSize)
        self.assertTrue("ldarg.1" in ilMethod.instructions[0].disasm)


    def test_augmentFileDotnet(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/dotnet-test.dll")

        """
        private static int MyMethod(string A, int B)
        {
            locals: int local_0,
                    bool local_1

            /* 0000025C 00             */ nop
            /* 0000025D 03             */ ldarg_1 // int B
            /* 0000025E 1F 0A          */ ldc_i4_s 10
            /* 00000260 58             */ add
            /* 00000261 10 01          */ starg_s arg_1 // int B
            /* 00000263 02             */ ldarg_0 // string A
            /* 00000264 72 01 00 00 70 */ ldstr "A"


        disassembled: 

        .method assembly hidebysig static 
                int32 '<<Main>$>g__MyMethod|0_0' (
                    string A,
                    int32 B
                ) cil managed 
            {
                ...
                // Method begins at RVA 0x209c
                // Header size: 1
                // Code size: 24 (0x18)
                .maxstack 8
                IL_0000: ldarg.1
                IL_0001: ldc.i4.s 10
                IL_0003: add
                IL_0004: starg.s B
                IL_0006: ldarg.0
                IL_0007: ldstr "A"

        Find that pattern in binary file:
            
        python3 searchbin.py --pattern "031F0a58100102" dotnet-test.dll
        Match at offset:            669          29D in dotnet-test.dll

        Conclusion: 
        Offset in file:       0x029c = 668
        Offset in decompile:  0x209c
        Difference:           0x1E00
        """
        matches = []
        match = Match(0, 669, 16) # 0x29D
        matches.append(match)

        augmentFileDotnet(filePe, matches)
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertNotEqual(0, len(match.getDisasmLines()))
        disasmLines = match.getDisasmLines()

        self.assertTrue('Function: ::<<Main>$>g__MyMethod' in disasmLines[0].text)
        self.assertTrue('ldarg.1' in disasmLines[1].text)
        self.assertTrue('ldc.i4.s       0xa' in disasmLines[2].text)


    def test_dotnetsections(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/HelloWorld.dll")

        self.assertTrue(filePe.isDotNet)
        sectionsBag = getDotNetSections(filePe)

        section = sectionsBag.getSectionByName('DotNet Header')
        self.assertEqual(section.addr, 512)
        self.assertEqual(section.size, 72)

        section = sectionsBag.getSectionByName('methods')
        self.assertEqual(section.addr, 584)
        self.assertEqual(section.size, 28)

        section = sectionsBag.getSectionByName('#~ Stream Header')
        self.assertEqual(section.addr, 644)
        self.assertEqual(section.size, 12)


    def test_dotnetsection_overlap(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/HelloWorld.dll")
        sectionsBag = getDotNetSections(filePe) 
        overlap = sectionsBag.getSectionsForRange(600, 750)
        
        self.assertEqual(len(overlap), 8)
        #self.assertEqual(overlap[0].name, "Stream: #~")
        #self.assertEqual(overlap[1].name, "methods")


    def test_dotnetheaders(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/HelloWorld.dll")

        sectionsBag = getDotNetSections(filePe) 
        sectionsBag.printSections()

        section = sectionsBag.getSectionByName("DotNet Header")
        self.assertEqual(section.addr, 512)
        self.assertEqual(section.size, 72)

        section = sectionsBag.getSectionByName("#~ Stream Header")
        self.assertEqual(section.addr, 644)
        self.assertEqual(section.size, 12)

        #section = sectionsBag.getSectionByName("Metadata Directory")
        #self.assertEqual(section.addr, 612)
        #self.assertEqual(section.size, 1316)

        uiDisasmLines = getDotNetDisassemblyHeader(filePe, 512, 72)
        self.assertTrue("CLR Header: HeaderSize: 72" in uiDisasmLines[0].text)
        self.assertTrue("CLR Header: MajorRuntimeVersion: 2" in uiDisasmLines[1].text)

        uiDisasmLines = getDotNetDisassemblyHeader(filePe, 612, 640)
        self.assertTrue("Metadata Header: Signature: 1112167234" in uiDisasmLines[0].text)
        self.assertTrue("Metadata Header: MajorVersion: 1" in uiDisasmLines[1].text)

        uiDisasmLines = getDotNetDisassemblyHeader(filePe, 644, 654)
        self.assertTrue("Stream Header: Offset: 108" in uiDisasmLines[0].text)
        self.assertTrue("Stream Header: Size: 424" in uiDisasmLines[1].text)


    def test_dotnet_method_headers(self):
        dncilParser = DncilParser("testing/sharp/Seatbelt.exe")
        #for idx, m in enumerate(dncilParser.methods):
        #    print(str(idx) + ": " + str(m.ilMethodHeaderFat))
        # 4: Fat Header: size:3 flags:4 maxStack:3 codeSize:89 localVarSigTok:285212673
        self.assertGreater(len(dncilParser.methods), 4)
        fat = dncilParser.methods[4].ilMethodHeaderFat
        self.assertIsNotNone(fat)
        self.assertTrue(fat.maxStack, 3)
        self.assertTrue(fat.codeSize, 89)


    def test_dotnetsections_signed(self):
        filePe = FilePe()
        filePe.loadFromFile("tests/data/HelloWorld-signed.dll")

        self.assertTrue(filePe.isDotNet)
        sectionsBag = getDotNetSections(filePe)

        section = sectionsBag.getSectionByName("Signature")
        self.assertEqual(section.addr, 2088)
        self.assertEqual(section.size, 128)
