from typing import List
from copy import deepcopy

from model.file_model import BaseFile
from model.model_base import Match, ScanSpeed
from scanner import Scanner
from reducer import Reducer


# Minimized existing matches
# If scanned with a large chunksize, can minimize it further
# Does not provide any performance increases tho, so currently unused

def minimizeMatches(file: BaseFile, matches: List[Match], scanner: Scanner):
    newAllMatches: List[Match] = []

    for match in matches: 
        filePlay = deepcopy(file)
        
        # hide all other
        for matchPatch in matches:
            if match.fileOffset != matchPatch.fileOffset:
                filePlay.Data().hideMatch(matchPatch)

        reducer = Reducer(filePlay, scanner, ScanSpeed.Complete)
        newMatches = reducer.scan(match.start(), match.end())

        print("New matches for match {}-{} ({}):".format(match.start(), match.end(), match.size))
        newAllMatches += newMatches

    return newAllMatches
