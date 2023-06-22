from plugins.model import Plugin, BaseFile
from model.model_base import Scanner, Match, OutflankPatch
from model.model_data import Match
from model.model_verification import MatchConclusion
from typing import List, Tuple, Set

from plugins.office.analyzer_office import analyzeFileWord
from plugins.office.augment_office import augmentFileWord
from plugins.office.file_office import FileOffice


class PluginOffice(Plugin):
    
    def makeFile(self, filepath: str):
        file = FileOffice()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, analyzerOptions={}):
        # We use the simple PE analyzer
        return analyzeFileWord(file, scanner, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return augmentFileWord(file, matches)

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return []
