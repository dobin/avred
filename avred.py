#!/usr/bin/python3

import argparse
from scanner import ScannerRest

import pickle
import os
import sys
import logging

from config import Config
from utils import saveMatchesToFile
from verifier import verify
from model.model import Outcome
from model.model import Match

from plugins.analyzer_office import analyzeFileWord, augmentFileWord
from plugins.analyzer_pe import analyzeFileExe, augmentFilePe
from plugins.analyzer_plain import analyzeFilePlain
from plugins.file_pe import FilePe
from plugins.file_office import FileOffice
from plugins.file_plain import FilePlain

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan", required=True)
    parser.add_argument('-s', "--server", help="Avred Server to use from config.json (default \"amsi\")")

    # --logonly (no saving files)
    parser.add_argument("--logtofile", help="Log everything to <file>.log", default=False, action='store_true')

    # debug
    parser.add_argument("--checkOnly", help="Debug: Only check if AV detects the file as malicious", default=False, action='store_true')
    parser.add_argument("--loadVerify", help="Debug: Load matches from .augmented, and perform augmentation again", default=False, action='store_true')

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
    file = None
    analyzer = None
    analyzerOptions = {}
    augmenter = None

    filenameMatches = args.file + ".matches"
    filenameOutcome = args.file + ".outcome"

    if args.file.endswith('.ps1'):
        file = FilePlain()
        file.loadFromFile(args.file)
        analyzer = analyzeFilePlain
        augmenter = None

    elif args.file.endswith('.docm'):  # dotm, xlsm, xltm
        file = FileOffice()
        file.loadFromFile(args.file)
        analyzer = analyzeFileWord
        augmenter = augmentFileWord 

    elif args.file.endswith('.exe'):
        file = FilePe()
        file.loadFromFile(args.file)
        analyzer = analyzeFileExe
        augmenter = augmentFilePe

        analyzerOptions["isolate"] = args.isolate
        analyzerOptions["remove"] = args.remove
        analyzerOptions["ignoreText"] = args.ignoreText

    else:
        logging.error("File ending not supported")
        os.exit(1)

    # matches
    if os.path.exists(filenameMatches):
        logging.info("Loading matches from file")
        # load previous matches
        with open(filenameMatches, 'rb') as handle:
            matchesIt = pickle.load(handle)
    else:
        # analyze file on avred server to get matches
        matchesIt = analyzer(file, scanner, analyzerOptions)
        with open(filenameMatches, 'wb') as handle:
            pickle.dump(matchesIt, handle)

    # convert IntervalTree Matches
    logging.info("Found {} matches".format(len(matchesIt)))
    matches = []
    idx = 0
    for m in matchesIt:
        match = Match(idx, m.begin, m.end-m.begin)
        matches.append(match)

    verifications = None
    if args.loadVerify:
        # For testing purposes.
        # Basically an offline version if .matches and .augment with verify data exists
        if os.path.exists(filenameOutcome):
            with open(filenameOutcome, 'rb') as handle:
                outcome = pickle.load(handle)
                verifications = outcome.verifications
        else:
            logging.error("--loadVerify given, but no {} file found. Abort.".format(filenameOutcome))
            sys.exit(1)
    else:
        # verify our analysis
        verifications = verify(file, matches, scanner)
        printVerifyData(verifications)

    # augment information
    if augmenter is not None:
        augmenter(file, matches)
    
    # save
    allData = Outcome(matches, verifications, matchesIt)
    with open(filenameOutcome, 'wb') as handle:
        pickle.dump(allData, handle)
        logging.info(f"Wrote results to {filenameOutcome}")


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
    