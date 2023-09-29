import unittest

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


class TestModelCode(unittest.TestCase):
    def test_modelcode(self):
        filePe = FilePe()

        filePe.peSectionsBag.getSectionByName()
        filePe.peSectionsBag.getSectionByPhysAddr()
        filePe.peSectionsBag.getSectionByVirtAddr()
        filePe.peSectionsBag.containsSectionName()
        filePe.peSectionsBag.getSectionNameByPhysAddr()
        filePe.peSectionsBag.getSectionsForPhysRange()
