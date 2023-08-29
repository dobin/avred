from abc import abstractmethod
from typing import List, Tuple, Set

from model.model_data import Match, Data
from model.model_verification import MatchConclusion
from model.model_base import Scanner, OutflankPatch, ScanInfo
from reducer import Reducer
from model.file_model import BaseFile


class Plugin():
    def __init__(self):
        pass
    
    @abstractmethod
    def makeFile(self, filepath: str):
        pass

    @abstractmethod
    def analyzeFile(self, file: BaseFile, scanner: Scanner, reducer: Reducer, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
        pass

    @abstractmethod
    def augmentMatches(self, file: BaseFile, matches: List[Match]) -> str:
        pass

    @abstractmethod
    def outflankFile(
        self, filePe: BaseFile, matches: List[Match], matchConclusion: MatchConclusion, scanner: Scanner = None
    ) -> List[OutflankPatch]:
        pass
