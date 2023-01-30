#!/usr/bin/env python

import unittest
from plugins.analyzer_dotnet import DncilParser, augmentFileDotnet, getDotNetSections
from plugins.dncilparser import IlMethod
from model.model import Match
from plugins.file_pe import FilePe


class DotnetDisasmTest(unittest.TestCase):
        def test_dncil(self):
            filePe = FilePe()
            filePe.loadFromFile("tests/data/dotnet-test.dll")
            dncilParser = DncilParser(filePe.filepath)

            addr = 0x029c # file offset
            ilMethods = dncilParser.query(addr, addr+16)
            self.assertEqual(len(ilMethods), 1)
            ilMethod = ilMethods[0]

            self.assertIsNotNone(ilMethod)
            self.assertTrue('g__MyMethod' in ilMethod.getName())
            self.assertEqual(ilMethod.getSize(), 25)
            self.assertEqual(ilMethod.getAddr(), addr)
            self.assertEqual(ilMethod.instructions[0], "Function: <<Main>$>g__MyMethod|0_0")
            self.assertEqual(ilMethod.instructions[1], "0001    ldarg.1        ")


        def test_ilspydisasm_offset(self):
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
            headerSize = 1

            matches = []
            match = Match(0, 669, 16) # 0x29D
            matches.append(match)

            augmentFileDotnet(filePe, matches)
            self.assertEqual(len(matches), 1)
            match = matches[0]
            self.assertNotEqual(0, len(match.detail))
            self.assertTrue('ldarg.1' in match.detail[0+headerSize].text)
            self.assertTrue('ldstr          "A"' in match.detail[5+headerSize].text)


        def test_dotnetsections(self):
            filePe = FilePe()
            filePe.loadFromFile("tests/data/HelloWorld.dll")

            self.assertTrue(filePe.isDotNet)
            sections = getDotNetSections(filePe)

            self.assertEqual(sections[0].name, 'DotNet Header')
            self.assertEqual(sections[0].addr, 512)
            self.assertEqual(sections[0].size, 72)

            self.assertEqual(sections[1].name, 'methods')
            self.assertEqual(sections[1].addr, 584)
            self.assertEqual(sections[1].size, 28)

            self.assertEqual(sections[3].name, 'Stream: #~')
            self.assertEqual(sections[3].addr, 720)
            self.assertEqual(sections[3].size, 424)


        def test_dotnetsections_signed(self):
            filePe = FilePe()
            filePe.loadFromFile("tests/data/HelloWorld-signed.dll")

            self.assertTrue(filePe.isDotNet)
            sections = getDotNetSections(filePe)

            self.assertEqual(sections[8].name, 'Signature')
            self.assertEqual(sections[8].addr, 2088)
            self.assertEqual(sections[8].size, 128)
