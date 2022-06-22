import json
from dataclasses import dataclass
import argparse
import pprint
from copy import deepcopy
from config import Config
from scanner import ScannerRest
from pe_utils import parse_pe, hidePart

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
    pe = parse_pe(args.file)
    matches = loadMatches(args.file)
    print("Matches: ")
    pprint.pprint(matches)
    print("")

    # Patch: ALL
    print("Patch complete match: ")
    for match in matches:
        peCopy = deepcopy(pe)
        size = match.end - match.start
        hidePart(pe, match.start, size)
        result = scanner.scan(pe.data, args.file)
        print(f"Patching: {match.start}-{match.end} size {size}  Detected: {result}")
    print("")

    # Patch: 1 byte
    print("Patch first 1 byte for each match: ")
    for match in matches:
        peCopy = deepcopy(pe)
        size = 1
        hidePart(pe, match.start, size)
        result = scanner.scan(pe.data, args.file)
        print(f"Patching: {match.start}-{match.end} size {size}  Detected: {result}")
          

if __name__ == "__main__":
    main()
    