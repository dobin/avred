from plugins.model import Plugin, BaseFile
from model.model_base import Scanner, OutflankPatch, ScanInfo
from model.model_data import Match
from model.model_verification import MatchConclusion
from typing import List, Tuple, Set

from plugins.plain.analyzer_plain import analyzeFilePlain
from plugins.plain.file_plain import FilePlain


class PluginPlain(Plugin):
    
    def makeFile(self, filepath: str):
        file = FilePlain()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, iteration: int = 0, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
        # We use the simple PE analyzer
        return analyzeFilePlain(file, scanner, iteration, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return [], ''

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return []
