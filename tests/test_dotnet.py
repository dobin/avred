#!/usr/bin/env python

import unittest
from plugins.analyzer_dotnet import IlspyParser, IlMethod
from model.model import Match

filename = 'tests/data/ilspy-rubeus.il'

class DotnetDisasmTest(unittest.TestCase):
        def test_ilspydisasm(self):
            ilspyParser = IlspyParser()
            ilspyParser.parseFile(filename)
            method = ilspyParser.query(155210)
            self.assertTrue(method.name == "'<SetPinForPrivateKey>b__1'")