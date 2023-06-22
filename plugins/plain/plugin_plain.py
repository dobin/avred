from plugins.model import Plugin, BaseFile
from model.model import Scanner, Match, OutflankPatch, MatchConclusion
from typing import List, Tuple, Set

from plugins.plain.analyzer_plain import analyzeFilePlain
from plugins.plain.file_plain import FilePlain


class PluginPlain(Plugin):
    
    def makeFile(self, filepath: str):
        file = FilePlain()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, analyzerOptions={}):
        # We use the simple PE analyzer
        return analyzeFilePlain(file, scanner, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return [], ''

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return []
