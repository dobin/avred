import json
from dataclasses import dataclass
import argparse
import pprint
from config import Config
from scanner import ScannerRest
from file_pe import FilePe
import pickle

from verifier import verify

@dataclass
class Match:
    index: int
    start: int
    end: int


def loadMatches(filename):
    f = open(filename + ".matches.json")
    data = json.load(f)
    result = []

    n = 0
    for match in data:
        r = Match(n, match["start"], match["end"])
        result.append(r)
        n += 1

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-s', "--server", help="Server")
    args = parser.parse_args()

    # scanner
    config = Config()
    config.load()
    url = config.get("server")[args.server]
    scanner = ScannerRest(url, args.server)

    # PE and its matches
    filePe = FilePe(args.file)
    filePe.load()

    matches = loadMatches(args.file)
    print("Matches: ")
    pprint.pprint(matches)
    print("")

    verificationRuns = verify(scanner, filePe, matches)
    with open(args.file + '.verify.pickle', 'wb') as handle:
        pickle.dump(verificationRuns, handle)

    printVerifyData(verificationRuns)


def printVerifyData(verificationRuns):
    for verificationRun in verificationRuns:
        print(str(verificationRun))

        for test in verificationRun.testEntries:
            print("A: " + str(test))

if __name__ == "__main__":
    main()
    
