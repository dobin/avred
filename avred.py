#!/usr/bin/python3

import argparse
from scanner import ScannerRest

import pickle
import os
import sys
import logging

from config import Config
from verifier import verify
from model.model import FileInfo, Outcome
from utils import FileType, GetFileType, convertMatchesIt

from plugins.analyzer_office import analyzeFileWord, augmentFileWord
from plugins.analyzer_pe import analyzeFileExe, augmentFilePe
from plugins.analyzer_dotnet import augmentFileDotnet
from plugins.analyzer_plain import analyzeFilePlain
from plugins.file_pe import FilePe
from plugins.file_office import FileOffice
from plugins.file_plain import FilePlain

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan", required=True)
    parser.add_argument('-s', "--server", help="Avred Server to use from config.json (default \"amsi\")")
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
        exit(1)
    url = config.get("server")[args.server]
    scanner = ScannerRest(url, args.server)

    logging.info("Using file: {}".format(args.file))
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

    # file ident
    filetype = FileType.UNKNOWN
    if args.file.endswith('.ps1'):
        filetype = FileType.PLAIN
    elif args.file.endswith('.docm'):  # dotm, xlsm, xltm
        filetype = FileType.OFFICE
    elif args.file.endswith('.exe'):
        filetype = FileType.EXE
    elif args.file.endswith('.bin'):
        filetype = FileType.PLAIN
    else: 
        filetype = GetFileType(args.file)

    logging.info("Using parser for {}".format(filetype.name))
    if filetype is FileType.PLAIN:
        file = FilePlain()
        file.loadFromFile(args.file)
        analyzer = analyzeFilePlain
        augmenter = None

    elif filetype is FileType.OFFICE:  # dotm, xlsm, xltm
        file = FileOffice()
        file.loadFromFile(args.file)
        analyzer = analyzeFileWord
        augmenter = augmentFileWord 

    elif filetype is FileType.EXE or filetype is FileType.DOTNET:
        file = FilePe()
        file.loadFromFile(args.file)

        analyzer = analyzeFileExe

        if file.isDotNet:
            augmenter = augmentFileDotnet
        else:
            augmenter = augmentFilePe

        analyzerOptions["isolate"] = args.isolate
        analyzerOptions["remove"] = args.remove
        analyzerOptions["ignoreText"] = args.ignoreText

    else:
        logging.error("File ending not supported")
        exit(1)

    # matches
    if os.path.exists(filenameMatches):
        # load previous matches (offline mode)
        logging.info("Loading matches from file")
        with open(filenameMatches, 'rb') as handle:
            matchesIt = pickle.load(handle)
    else:
        # check if its really being detected first
        detected = scanner.scan(file.data, file.filename)
        if not detected:
            logging.error(f"{file.filename} is not detected by {scanner.scanner_name}")
            exit(1)

        # analyze file on avred server to get matches
        matchesIt = analyzer(file, scanner, analyzerOptions)
        with open(filenameMatches, 'wb') as handle:
            pickle.dump(matchesIt, handle)

    # convert IntervalTree Matches
    logging.info("Found {} matches".format(len(matchesIt)))
    matches = convertMatchesIt(matchesIt)

    verification = None
    if args.loadVerify and os.path.exists(filenameOutcome):
        # For testing purposes.
        # Basically an offline version if .matches and .augment with verify data exists
        with open(filenameOutcome, 'rb') as handle:
            outcome = pickle.load(handle)
            verification = outcome.verification
    else:
        # verify our analysis
        verification = verify(file, matches, scanner)

    # augment information
    fileInfo = FileInfo(file.filename, 0, None)
    if augmenter is not None:
        fileStructure = augmenter(file, matches)
        fileInfo.fileStructure = fileStructure
    
    # save
    outcome = Outcome(fileInfo, matches, verification, matchesIt)
    with open(filenameOutcome, 'wb') as handle:
        pickle.dump(outcome, handle)
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


def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))


if __name__ == "__main__":
    main()
    