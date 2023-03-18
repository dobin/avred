#!/usr/bin/python3

import argparse
import pickle
import os
import logging
from intervaltree import Interval
from typing import List
import magic
import pathlib
import hashlib
import datetime

from config import Config
from verifier import verify
from model.model import Outcome, FileInfo
from utils import FileType, convertMatchesIt, patchData
from scanner import ScannerRest
from model.extensions import PluginFileFormat
from model.testverify import VerifyStatus

from plugins.analyzer_office import analyzeFileWord, augmentFileWord
from plugins.analyzer_pe import analyzeFileExe, augmentFilePe
from plugins.analyzer_dotnet import augmentFileDotnet
from plugins.analyzer_plain import analyzeFilePlain, augmentFilePlain
from plugins.file_pe import FilePe
from plugins.file_office import FileOffice
from plugins.file_plain import FilePlain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-u", "--uploads", help="Scan app/uploads/*", default=False, action='store_true')
    parser.add_argument('-s', "--server", help="Avred Server to use from config.json (default \"amsi\")", default="amsi")
    #parser.add_argument("--logtofile", help="Log everything to <file>.log", default=False, action='store_true')

    # debug
    parser.add_argument("--checkonly", help="Debug: Only check if AV detects the file as malicious", default=False, action='store_true')
    parser.add_argument("--rescan", help="Debug: Re-do the scanning for matches", default=False, action='store_true')
    parser.add_argument("--reverify", help="Debug: Re-do the verification", default=False, action='store_true')
    parser.add_argument("--reaugment", help="Debug: Re-do the augmentation", default=False, action='store_true')

    # analyzer options
    parser.add_argument("--pe_isolate", help="PE: Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument("--pe_remove", help="PE: Remove some standard sections at the beginning (experimental)", default=False,  action='store_true')
    parser.add_argument("--pe_ignoreText", help="PE: Dont analyze .text section", default=False, action='store_true')

    args = parser.parse_args()

    config = Config()
    config.load()

    if args.server not in config.get("server"):
        logging.error(f"Could not find server with name '{args.server}' in config.json")
        exit(1)
    url = config.get("server")[args.server]
    scanner = ScannerRest(url, args.server)
    if args.uploads:
        scanUploads(args, scanner)
    else:
        setupLogging(args.file)
        logging.info("Using file: {}".format(args.file))
        if args.checkonly:
            checkFile(args.file, scanner)
        else:
            handleFile(args.file, args, scanner)


def setupLogging(filename):
    # Setup logging
    # log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'
    logging.root.handlers = []

    log_format = '[%(levelname)-8s][%(asctime)s] %(funcName)s() :: %(message)s'
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler(filename + ".log")
    ]
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers,
    )


def scanUploads(args, scanner):
    root_folder = os.path.dirname(__file__)
    upload_folder = os.path.join(root_folder, 'app', 'upload')
    files = os.listdir(upload_folder)

    for filename in files:
        if not filename.endswith('.outcome') and not filename.endswith('.log') and not filename.endswith('.gitkeep'):
            #handleFile(filename, args, scanner)
            filepath = os.path.join(upload_folder, filename)
            setupLogging(filepath)
            handleFile(filepath, args, scanner)


def handleFile(filename, args, scanner):
    file = None
    analyzer = None
    analyzerOptions = {}
    augmenter = None
    filenameOutcome = filename + ".outcome"
    logging.info("Handle file: " + filename)

    fileScannerType = getFileScannerTypeFor(filename)
    logging.info("Using parser for file type {}".format(fileScannerType.name))
    if fileScannerType is FileType.PLAIN:
        file = FilePlain()
        file.loadFromFile(filename)
        analyzer = analyzeFilePlain
        augmenter = augmentFilePlain
    elif fileScannerType is FileType.OFFICE:
        file = FileOffice()
        file.loadFromFile(filename)
        analyzer = analyzeFileWord
        augmenter = augmentFileWord 
    elif fileScannerType is FileType.EXE:
        file = FilePe()
        file.loadFromFile(filename)
        analyzer = analyzeFileExe
        if file.isDotNet:
            augmenter = augmentFileDotnet
        else:
            augmenter = augmentFilePe
        analyzerOptions["isolate"] = args.pe_isolate
        analyzerOptions["remove"] = args.pe_remove
        analyzerOptions["ignoreText"] = args.pe_ignoreText
    else:
        logging.error("Unknown filetype, aborting")
        exit(1)

    fileInfo = getFileInfo(file)

    # load existing outcome
    if os.path.exists(filenameOutcome):
        with open(filenameOutcome, 'rb') as handle:
            outcome = pickle.load(handle)
    else:
        outcome = Outcome.nullOutcome(fileInfo)

    if not outcome.isScanned or args.rescan:
        scanner.checkOnlineOrExit()
        outcome = scanFile(outcome, file, scanner, analyzer, analyzerOptions)
        outcome.saveToFile(file.filepath)

    if not outcome.isDetected:
        # no need to verify or augment
        return

    if not outcome.isVerified or args.reverify:
        scanner.checkOnlineOrExit()
        outcome = verifyFile(outcome, file, scanner)
        outcome.saveToFile(file.filepath)

    if not outcome.isAugmented or args.reaugment:
        outcome = augmentFile(outcome, file, augmenter)
        outcome.saveToFile(file.filepath)

    # output for cmdline users
    print(outcome)


def scanFile(outcome, file, scanner, analyzer, analyzerOptions):
    matchesIt: List[Interval]

    outcome.scanTime = datetime.datetime.now()
    outcome.scannerName = scanner.scanner_name

    # check if its really being detected first as a quick check
    detected = scanner.scan(file.data, file.filename)
    if not detected:
        logging.error(f"QuickCheck: {file.filename} is not detected by {scanner.scanner_name}")
        outcome.isDetected = False
        outcome.isScanned = True
        outcome.matchesIt = []
        outcome.appraisal = 'Not detected'
        return outcome
    
    # pre check: defeat hash of binary (or scan would take very long for nothing)
    if scanIsHash(file, scanner):
        logging.info("QuickCheck: Signature is hash based")
        outcome.isDetected = True
        outcome.isScanned = True
        outcome.matchesIt = [ ]
        outcome.appraisal = 'Hash based'
        return outcome
    
    logging.info(f"QuickCheck: {file.filename} is detected by {scanner.scanner_name}")
    logging.info("Scanning for matches...")
    outcome.isDetected = True
    matchesIt, scannerInfo = analyzer(file, scanner, analyzerOptions)
    outcome.matchesIt = matchesIt
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

    allCount = len(verification.matchConclusions.verifyStatus)
    badCount = verification.matchConclusions.getCount(VerifyStatus.BAD)
    goodCount = verification.matchConclusions.getCount(VerifyStatus.GOOD)
    okCount = verification.matchConclusions.getCount(VerifyStatus.OK)

    if badCount == allCount:
        outcome.appraisal = 'OR Signature'

    if (goodCount + okCount) == 1:
        outcome.appraisal = 'One match'

    if goodCount > 1:
        outcome.appraisal = 'AND Signature'

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


def getFileInfo(file: PluginFileFormat):
    size = pathlib.Path(file.filepath).stat().st_size
    hash = hashlib.md5(file.fileData).digest()
    time = pathlib.Path(file.filepath).stat().st_ctime
    ident = magic.from_file(file.filepath)

    if 'Mono/.Net assembly' in ident:
        ident = "PE EXE .NET"
    elif 'PE32+ executable' in ident:
        ident = "PE EXE 64"
    elif 'PE32 executable' in ident:
        ident = "PE EXE 32"
    elif 'PDF document' in ident:
        ident = 'PDF'
    elif 'ASCII test' in ident:
        ident = 'ASCII'
    elif file.filename.endswith('.ps1'):
        ident = "Powershell"

    fileInfo = FileInfo(file.filename, size, hash, time, ident)
    return fileInfo


def getFileScannerTypeFor(filename):
    # detection based on file ending (excplicitly tested)
    if filename.endswith('.ps1'):
        fileScannerType = FileType.PLAIN
    elif filename.endswith('.docm'):  # dotm, xlsm, xltm
        fileScannerType = FileType.OFFICE
    elif filename.endswith('.exe') or filename.endswith('.dll'):
        fileScannerType = FileType.EXE
    elif filename.endswith('.lnk'):
        fileScannerType = FileType.PLAIN
    else:
        fileScannerType = FileType.PLAIN

    return fileScannerType


def scanIsHash(file, scanner) -> bool:
    """check if the detection is hash based (complete file)"""
    data = file.getData()
    size = len(data)

    firstOff = int(size//3)
    firstData = patchData(data, firstOff, 1)
    firstFile = file.getFileWithNewData(firstData)
    firstRes = scanner.scan(firstFile, file.filename)

    lastOff = int((size//3) * 2)
    lastData = patchData(data, lastOff, 1)
    lastFile = file.getFileWithNewData(lastData)
    lastRes = scanner.scan(lastFile, file.filename)

    if not firstRes and not lastRes:
        return True
    else:
        return False


def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))


if __name__ == "__main__":
    main()
    