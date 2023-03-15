#!/usr/bin/python3

import argparse
from scanner import ScannerRest

import pickle
import os
import logging
from intervaltree import Interval
from typing import List

from config import Config
from verifier import verify
from model.model import Outcome, FileInfo
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
    parser.add_argument("--checkonly", help="Debug: Only check if AV detects the file as malicious", default=False, action='store_true')
    parser.add_argument("--rescan", help="Debug: Re-do the scanning for matches", default=False, action='store_true')
    parser.add_argument("--reverify", help="Debug: Re-do the verification", default=False, action='store_true')
    parser.add_argument("--noreaugment", help="Debug: Dont Re-do the augmentation", default=False, action='store_true')

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
    if args.checkonly:
        checkFile(args.file, scanner)
    else:
        handleFile(args, scanner)


def handleFile(args, scanner):
    file = None
    analyzer = None
    analyzerOptions = {}
    augmenter = None
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
    elif args.file.endswith('.exe') or args.file.endswith('.dll'):
        filetype = FileType.EXE
        uiFileType = "Executable"
    elif args.file.endswith('.bin') or args.file.endswith('.lnk'):
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
        # write null outcome, to signal "scan over" to the webserver
        file = FilePlain()
        file.loadFromFile(args.file)
        fileInfo = getFileInfo(file, uiFileType, '')
        outcome = Outcome.nullOutcome(fileInfo)
        print(file.filename)
        with open(filenameOutcome, 'wb') as handle:
            pickle.dump(outcome, handle)
            logging.info(f"Wrote results to {filenameOutcome}")
        exit(1)

    fileInfo = getFileInfo(file, uiFileType, '')

    # load existing
    if os.path.exists(filenameOutcome):
        with open(filenameOutcome, 'rb') as handle:
            outcome = pickle.load(handle)
    else:
        outcome = Outcome.nullOutcome(fileInfo)

    if not outcome.isScanned:
        outcome = scanFile(outcome, file, scanner, analyzer, analyzerOptions)
        outcome.saveToFile(file.filepath)

    if not outcome.isVerified:
        outcome = verifyFile(outcome, file, scanner)
        outcome.saveToFile(file.filepath)

    if not outcome.isAugmented:
        outcome = augmentFile(outcome, file, augmenter)
        outcome.saveToFile(file.filepath)

    # output all data
    print(outcome)



def scanFile(outcome, file, scanner, analyzer, analyzerOptions):
    matchesIt: List[Interval]
    # find matches
    # check if its really being detected first as a quick check
    detected = scanner.scan(file.data, file.filename)
    if not detected:
        logging.error(f"QuickCheck: {file.filename} is not detected by {scanner.scanner_name}")
        outcome.isDetected = False
        outcome.isScanned = True
        outcome.matchesIt = []
        return outcome
    
    logging.info(f"QuickCheck: {file.filename} is detected by {scanner.scanner_name}")
    outcome.isDetected = True

    logging.info("Scanning for matches...")
    matchesIt, scannerInfo = analyzer(file, scanner, analyzerOptions)
    outcome.matchesIt = []
    outcome.scannerInfo = scannerInfo

    # convert IntervalTree Matches
    logging.info("Result: {} matches".format(len(matchesIt)))
    matches = convertMatchesIt(matchesIt)
    outcome.matches = matches
    outcome.isScanned = True

    return outcome


def verifyFile(outcome, file, scanner):
    # verify our analysis
    logging.info("Perform verification of matches")
    verification = verify(file, outcome.matches, scanner)
    outcome.verification = verification
    outcome.isVerified = True
    return outcome


def augmentFile(outcome, file, augmenter):
    logging.info("Perform augmentation of matches")
    fileStructure = augmenter(file, outcome.matches)
    outcome.fileStructure = fileStructure
    outcome.isAugmented = True
    return outcome


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
    