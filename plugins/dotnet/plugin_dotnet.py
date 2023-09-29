from typing import List, Tuple, Set

from model.model_base import Scanner, OutflankPatch, ScanInfo
from model.model_data import Match
from model.model_verification import MatchConclusion
from model.plugin_model import Plugin
from model.file_model import BaseFile
from plugins.pe.analyzer_pe import analyzeFilePe
from plugins.dotnet.augment_dotnet import augmentFileDotnet
from plugins.dotnet.outflank_dotnet import outflankDotnet
from plugins.dotnet.file_dotnet import FilePeDotNet
from reducer import Reducer


class PluginDotNet(Plugin):
    
    def makeFile(self, filepath: str):
        file = FilePeDotNet()
        file.loadFromFile(filepath)
        return file

    
    def analyzeFile(self, file: BaseFile, scanner: Scanner, reducer: Reducer, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
        # We use the simple PE analyzer
        return analyzeFilePe(file, scanner, reducer, analyzerOptions)

    
    def augmentFile(self, file: BaseFile, matches: List[Match]) -> str:
        return augmentFileDotnet(file, matches)

    
    def outflankFile(
        self, file: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        return outflankDotnet(file, matches, matchConclusion, scanner)
