from typing import List, Tuple, Set

from model.model_base import Scanner, OutflankPatch
from model.model_data import Match
from model.model_verification import MatchConclusion
from plugins.model import Plugin, BaseFile
from plugins.pe.analyzer_pe import analyzeFilePe
from plugins.dotnet.augment_dotnet import augmentFileDotnet
from plugins.dotnet.outflank_dotnet import outflankDotnet
from plugins.pe.file_pe import FilePe


class PluginDotNet(Plugin):
    
    def makeFile(self, filepath: str):
        file = FilePe()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, analyzerOptions={}):
        # We use the simple PE analyzer
        return analyzeFilePe(file, scanner, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return augmentFileDotnet(file, matches)

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return outflankDotnet(file, matches, matchConclusion, scanner)
