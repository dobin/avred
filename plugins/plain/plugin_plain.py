from model.plugin_model import Plugin
from model.model_base import Scanner, OutflankPatch, ScanInfo
from model.model_data import Match
from model.model_verification import MatchConclusion
from model.file_model import BaseFile
from typing import List, Tuple, Set
from reducer import Reducer
from plugins.plain.analyzer_plain import analyzeFilePlain
from plugins.plain.file_plain import FilePlain


class PluginPlain(Plugin):
    
    def makeFile(self, filepath: str):
        file = FilePlain()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, reducer: Reducer, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
        # We use the simple PE analyzer
        return analyzeFilePlain(file, scanner, reducer, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return [], ''

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return []
