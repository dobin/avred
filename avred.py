#!/usr/bin/python3

import argparse
from scanner import ScannerRest
from plugins.analyzer_office import analyzeFileWord, augmentFileWord
from plugins.analyzer_pe import analyzeFileExe, augmentFilePe
from analyzer_plain import analyzeFilePlain
from config import Config
import logging
from utils import saveMatchesToFile
from verifier import verify
from plugins.file_pe import FilePe
from model import FileData
import pickle
from plugins.file_office import FileOffice
import os
import sys
from model import Match

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan", required=True)
    parser.add_argument('-s', "--server", help="Avred Server to use from config.json (default \"amsi\")")

    # --logonly (no saving files)
    parser.add_argument("--logtofile", help="Log everything to <file>.log", default=False, action='store_true')

    # debug
    parser.add_argument("--checkOnly", help="Debug: Only check if AV detects the file as malicious", default=False, action='store_true')
    parser.add_argument("--augmentOnly", help="Debug: Load matches from .augmented, and perform augmentation again", default=False, action='store_true')

    # analyzer options
    parser.add_argument("--isolate", help="PE: Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument("--remove", help="PE: Remove some standard sections at the beginning (experimental)", default=False,  action='store_true')
    parser.add_argument("--ignoreText", help="PE: Dont analyze .text section", default=False, action='store_true')

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)
    if args.logtofile:
        logfile = args.file + ".log"
        print(f"Logging to file: {logfile}")
        logging.basicConfig(filename=logfile,
                        filemode='a',
                        format=log_format,
                        datefmt='%Y/%m/%d %H:%M',
                        level=logging.INFO
                )
    else:
        logging.basicConfig(
                format=log_format,
                datefmt='%Y/%m/%d %H:%M',
                level=logging.INFO
        )

    config = Config()
    config.load()

    if args.server not in config.get("server"):
        logging.error(f"Could not find server with name '{args.server}' in config.json")
        sys.exit(1)
    url = config.get("server")[args.server]
    scanner = ScannerRest(url, args.server)

    if args.checkOnly:
        checkFile(args.file, scanner)
    else:
        scanFile(args, scanner)


def scanFile(args, scanner):
    matchesIt = None
    matches = None
    verifications = None
    fileData = None
    analyzer = None
    analyzerOptions = {}
    augmenter = None

    filenameMatches = args.file + ".matches"
    filenameAugment = args.file + ".augment"

    if args.file.endswith('.ps1'):
        fileData = FilePlain()
        fileData.loadFromFile(args.file)
        analyzer = analyzeFilePlain
        augmenter = None

    elif args.file.endswith('.docm'):  # dotm, xlsm, xltm
        fileData = FileOffice()
        fileData.loadFromFile(args.file)
        analyzer = analyzeFileWord
        augmenter = augmentFileWord 

    elif args.file.endswith('.exe'):
        fileData = FilePe()
        fileData.loadFromFile(args.file)
        analyzer = analyzeFileExe
        augmenter = augmentFilePe

        analyzerOptions["isolate"] = args.isolate
        analyzerOptions["remove"] = args.remove
        analyzerOptions["ignoreText"] = args.ignoreText

    # matches
    if os.path.exists(filenameMatches):
        logging.info("Loading matches from file")
        # load previous matches
        with open(filenameMatches, 'rb') as handle:
            matchesIt = pickle.load(handle)
    else:
        # analyze file on avred server to get matches
        matchesIt = analyzer(fileData, scanner)
        with open(filenameMatches, 'wb') as handle:
            pickle.dump(matchesIt, handle)

    # convert IntervalTree Matches
    matches = []
    idx = 0
    for m in matchesIt:
        match = Match(idx, m.begin, m.end-m.begin)
        matches.append(match)

    # verify our analysis
    verifications = verify(fileData, matches, scanner)
    printVerifyData(verifications)

    # augment information
    augmenter(fileData, matches)
    
    # save
    allData = FileData(matches, verifications, matchesIt)
    with open(filenameAugment, 'wb') as handle:
        pickle.dump(allData, handle)
        logging.info(f"Wrote results to {filenameAugment}")


# Check if file gets detected by the scanner
def checkFile(filepath, scanner):
    data = None
    with open(filepath, 'rb') as file:
        data = file.read()
    detected = scanner.scan(data, os.path.basename(filepath))
    if detected:
        print(f"File is detected")
    else:
        print(f"File is not detected")


def printVerifyData(verifications):
    print("Verification results: ")
    for verification in verifications:
        print(str(verification))

def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))


if __name__ == "__main__":
    main()
    