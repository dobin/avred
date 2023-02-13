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
from utils import FileType, GetFileType, convertMatchesIt, getFileInfo

from plugins.analyzer_office import analyzeFileWord, augmentFileWord
from plugins.analyzer_pe import analyzeFileExe, augmentFilePe
from plugins.analyzer_dotnet import augmentFileDotnet
from plugins.analyzer_plain import analyzeFilePlain, augmentFilePlain
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
    parser.add_argument("--loadVerify", help="Debug: Offline. Only do augmentation, if verifications exist.", default=False, action='store_true')

    # analyzer options
    parser.add_argument("--pe_isolate", help="PE: Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument("--pe_remove", help="PE: Remove some standard sections at the beginning (experimental)", default=False,  action='store_true')
    parser.add_argument("--pe_ignoreText", help="PE: Dont analyze .text section", default=False, action='store_true')

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

    logging.info("Handle file: " + args.file)

    # file ident
    filetype = FileType.UNKNOWN
    uiFileType = 'unknown'
    if args.file.endswith('.ps1'):
        filetype = FileType.PLAIN
        uiFileType = "Powershell"
    elif args.file.endswith('.docm'):  # dotm, xlsm, xltm
        filetype = FileType.OFFICE
        uiFileType = "Word"
    elif args.file.endswith('.exe'):
        filetype = FileType.EXE
        uiFileType = "Executable"
    elif args.file.endswith('.bin'):
        # try to detect it first
        filetype = GetFileType(args.file)
        uiFileType = filetype

        if filetype is FileType.UNKNOWN:
            filetype = FileType.PLAIN
            uiFileType = 'Binary'
    else: 
        filetype = GetFileType(args.file)

    logging.info("Using parser for {}".format(filetype.name))
    if filetype is FileType.PLAIN:
        file = FilePlain()
        file.loadFromFile(args.file)
        analyzer = analyzeFilePlain
        augmenter = augmentFilePlain

    elif filetype is FileType.OFFICE:  # dotm, xlsm, xltm
        file = FileOffice()
        file.loadFromFile(args.file)
        analyzer = analyzeFileWord
        augmenter = augmentFileWord 

    elif filetype is FileType.EXE:
        file = FilePe()
        file.loadFromFile(args.file)

        analyzer = analyzeFileExe

        if file.isDotNet:
            augmenter = augmentFileDotnet
            uiFileType = 'ExeDotNet'
        else:
            augmenter = augmentFilePe
            uiFileType = 'ExePe'

        analyzerOptions["isolate"] = args.pe_isolate
        analyzerOptions["remove"] = args.pe_remove
        analyzerOptions["ignoreText"] = args.pe_ignoreText

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
        if detected:
            logging.info(f"{file.filename} is detected by {scanner.scanner_name}")
        else:
            logging.error(f"{file.filename} is not detected by {scanner.scanner_name}")
            exit(1)

        # analyze file on avred server to get matches
        matchesIt = analyzer(file, scanner, analyzerOptions)
        with open(filenameMatches, 'wb') as handle:
            pickle.dump(matchesIt, handle)

    # convert IntervalTree Matches
    logging.info("Found {} matches".format(len(matchesIt)))
    if len(matchesIt) == 0:
        logging.warning("No matches found. Try some other options?")
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
    fileInfo = getFileInfo(file, uiFileType, '')
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
    