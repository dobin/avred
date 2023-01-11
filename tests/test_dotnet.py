#!/usr/bin/env python

import unittest
from plugins.analyzer_dotnet import IlspyParser, IlMethod, augmentFileDotnet
from model.model import Match
from plugins.file_pe import FilePe

filename = 'tests/data/ilspy-rubeus.il'

class DotnetDisasmTest(unittest.TestCase):
        def test_ilspydisasm(self):
            ilspyParser = IlspyParser()
            ilspyParser.parseFile(filename)

            method = ilspyParser.query(0, 10)
            self.assertIsNone(method)

            method = ilspyParser.query(155210, 155210+10)
            self.assertIsNotNone(method)
            self.assertTrue("'<SetPinForPrivateKey>b__1'" in method.name)


        def test_ilspydisasm_cmd(self):
            ilspyParser = IlspyParser()
            ilspyParser.parseFile(filename)
            method = ilspyParser.query(155210, 155210+10)

            # Headersize: 1
            # IL_0006: ldc.i4.s 32
            instr = method.instructions[6+1]
            self.assertTrue(instr == 'IL_0006: ldc.i4.s 32')


        def test_ilspydisasm_offset(self):
            filePe = FilePe()
            filePe.loadFromFile("tests/data/dotnet-test.dll")

            """
            as seen online: 

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

            decompiled: 

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
            match = Match(0, 669, 16)
            matches.append(match)

            augmentFileDotnet(filePe, matches)
            self.assertEqual(matches[0].detail[0+1]['text'], 'IL_0000: ldarg.1')
            self.assertEqual(matches[0].detail[5+1]['text'], 'IL_0007: ldstr "A"')
