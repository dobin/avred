import logging
from typing import List, Tuple

from reducer import Reducer
from utils import *
from model.model import Match, Scanner
import pcodedmp.pcodedmp as pcodedmp
from plugins.office.file_office import FileOffice


def analyzeFileWord(fileOffice: FileOffice, scanner: Scanner, analyzerOptions={}) -> Tuple[List[Match], str]:
    # Scans a office file given with fileOffice with Scanner scanner. 
    # Returns all matches.
    reducer = Reducer(fileOffice, scanner)
    matches = reducer.scan(0, fileOffice.Data().getLength())
    return matches, ''
