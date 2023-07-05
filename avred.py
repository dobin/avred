#!/usr/bin/python3

import argparse
import pickle
import os
import logging
from filehelper import *
from copy import deepcopy
import pprint

from config import Config
from model.model_base import Outcome
from model.model_data import Data
from model.model_verification import Appraisal
from filehelper import FileType
from scanner import ScannerRest, ScannerYara, hashCache
from model.model_verification import VerifyStatus

from plugins.plain.plugin_plain import PluginPlain
from plugins.dotnet.plugin_dotnet import PluginDotNet
from plugins.pe.plugin_pe import PluginPe
from plugins.office.plugin_office import PluginOffice
from plugins.model import Plugin
from verifier import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-u", "--uploads", help="Scan app/uploads/*", default=False, action='store_true')
    parser.add_argument('-s', "--server", help="Avred Server to use from config.json (default \"amsi\")", default="amsi")
    #parser.add_argument("--logtofile", help="Log everything to <file>.log", default=False, action='store_true')
    parser.add_argument("-C", "--Config", help="Print config location and content", default=False, action='store_true')

    # debug
    parser.add_argument("--checkonly", help="Debug: Only check if AV detects the file as malicious", default=False, action='store_true')
    parser.add_argument("--reinfo", help="Debug: Re-do the file info", default=False, action='store_true')
    parser.add_argument("--rescan", help="Debug: Re-do the scanning for matches", default=False, action='store_true')
    parser.add_argument("--reverify", help="Debug: Re-do the verification", default=False, action='store_true')
    parser.add_argument("--reaugment", help="Debug: Re-do the augmentation", default=False, action='store_true')
    parser.add_argument("--reoutflank", help="Debug: Re-do the Outflanking", default=False, action='store_true')

    # analyzer options
    parser.add_argument("--pe_isolate", help="PE: Isolate sections to be tested (null all other)", default=False,  action='store_true')

    args = parser.parse_args()

    config = Config()
    config.load()

    if args.Config:
        print("Config path: " + config.getConfigPath())
        pprint.pprint(config.getConfig())
        return

    if args.server not in config.get("server"):
        logging.error(f"Could not find server with name '{args.server}' in config.json")
        exit(1)
    url = config.get("server")[args.server]

    if url.startswith("http"):
        scanner = ScannerRest(url, args.server)
    elif url.startswith("yara"):
        scanner = ScannerYara(url.replace("yara://", ""), args.server)
    else:
        logging.error("Not a valid URL, should start with http or yara: " + url)
        return

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
    analyzerOptions = {}
    plugin: Plugin = None

    filenameOutcome = filename + ".outcome"
    logging.info("Handle file: " + filename)

    fileScannerType = getFileScannerTypeFor(filename)
    logging.info("Using parser for file type {}".format(fileScannerType.name))
    if fileScannerType is FileType.PLAIN:
        plugin = PluginPlain()
        file = plugin.makeFile(filename)
    elif fileScannerType is FileType.OFFICE:
        plugin = PluginOffice()
        file = plugin.makeFile(filename)
    elif fileScannerType is FileType.EXE:
        plugin = PluginPe()
        file = plugin.makeFile(filename)
    elif fileScannerType is FileType.DOTNET:
        plugin = PluginDotNet()
        file = plugin.makeFile(filename)
    else:
        logging.error("Unknown filetype, aborting")
        exit(1)

    # load existing outcome
    if os.path.exists(filenameOutcome):
        with open(filenameOutcome, 'rb') as handle:
            outcome = pickle.load(handle)

        if args.reinfo:
            fileInfo = getFileInfo(file)
            outcome.fileInfo = fileInfo
            outcome.saveToFile(file.filepath)
    else:
        fileInfo = getFileInfo(file)
        outcome = Outcome.nullOutcome(fileInfo)

    hashCache.load()

    # scan
    if not outcome.isScanned or args.rescan:
        scanner.checkOnlineOrExit()

        
        # unmodified file detected?
        outcome.isDetected = True
        outcome.isScanned = True
        if not scanIsDetected(file, scanner):
            outcome.isDetected = False
            outcome.appraisal = Appraisal.Undetected
            logging.info("isDetected: {}".format(outcome.isDetected))
            outcome.saveToFile(file.filepath)
            hashCache.save()
            return
        
        # quick check hash
        if scanIsHash(file, scanner):
            outcome.appraisal = Appraisal.Hash
            logging.info("Appraisal: {}".format(outcome.appraisal))
            outcome.saveToFile(file.filepath)
            hashCache.save()
            return
        
        logging.info(f"QuickCheck: {file.filename} is detected by {scanner.scanner_name} and not hash based")
        
        # ready to go
        isDetected = True  # we now know that the file is being detected
        filePlay = deepcopy(file)  # leave original unmodified, apply matches for iterative scanning here
        iteration = 0
        MAX_ITERATIONS = 6
        while isDetected:
            if iteration > MAX_ITERATIONS:
                logging.error("{} iterations deep and still no end.. bailing out".format(MAX_ITERATIONS))
                return

            # get matches
            logging.info("Scanning for matches...")
            matches, scanInfo = plugin.analyzeFile(filePlay, scanner, analyzerOptions)
            outcome.matches += matches
            logging.info("Result: {} matches".format(len(matches)))
            outcome.scanInfo = scanInfo
            outcome.saveToFile(filePlay.filepath)

            # apply matches and verify if it is not detected
            # TODO: will overwrite previously identified matches too, not just new ones
            filePlay.Data().hideMatches(outcome.matches)
            # try to identify matches until it is not detected anymore
            if scanIsDetected(filePlay, scanner):
                logging.info("Still detected on iteration {}, apply {} matches and do again".format(
                    iteration, len(matches)
                ))
            else:
               break

            iteration += 1

    hashCache.save()
    if not outcome.isVerified or args.reverify:
        scanner.checkOnlineOrExit()
        outcome = verifyFile(outcome, file, scanner)
        outcome.saveToFile(file.filepath)

    if not outcome.isAugmented or args.reaugment:
        outcome = augmentFile(outcome, file, plugin.augmentFile)
        outcome.saveToFile(file.filepath)

    #if outflank is not None and (not outcome.isOutflanked or args.reoutflank):
    #if outflanker is not None:
    outcome = outflankFile(plugin.outflankFile, outcome, file, scanner)
    outcome.saveToFile(file.filepath)
    hashCache.save()

    # output for cmdline users
    #print("Result:")
    #print(outcome)


def scanIsDetected(file: BaseFile, scanner):
    detected = scanner.scannerDetectsBytes(file.DataAsBytes(), file.filename)
    return detected


def verifyFile(outcome, file, scanner):
    # verify our analysis
    logging.info("Perform verification of matches")
    verification = verify(file, outcome.matches, scanner)
    outcome.verification = verification
    outcome.isVerified = True

    if len(outcome.matches) == 0:
        return outcome

    allCount = len(verification.matchConclusions.verifyStatus)
    robustCount = verification.matchConclusions.getCount(VerifyStatus.ROBUST)
    dominantCount = verification.matchConclusions.getCount(VerifyStatus.DOMINANT)
    irrelevantCount = verification.matchConclusions.getCount(VerifyStatus.IRRELEVANT)

    if robustCount == allCount:
        outcome.appraisal = Appraisal.Robust
    elif dominantCount == 1:
        outcome.appraisal = Appraisal.One
    elif dominantCount > 1:
        outcome.appraisal = Appraisal.Fragile

    return outcome


def augmentFile(outcome, file, augmenter):
    logging.info("Perform augmentation of matches")
    fileStructure = augmenter(file, outcome.matches)
    outcome.fileStructure = fileStructure
    outcome.isAugmented = True
    return outcome


def outflankFile(outflank, outcome: Outcome, file, scanner):
    logging.info("Attempt to outflank the file")
    outflankPatches = outflank(file, outcome.matches, outcome.verification.matchConclusions, scanner)

    #for p in outflankPatches:
    #    print("patch: " + str(p))

    outcome.outflankPatches = outflankPatches
    outcome.isOutflanked = True
    return outcome


# Check if file gets detected by the scanner
def checkFile(filepath, scanner):
    data = None
    with open(filepath, 'rb') as file:
        data = file.read()
    detected = scanner.scannerDetectsBytes(data, os.path.basename(filepath))
    if detected:
        print(f"File is detected")
    else:
        print(f"File is not detected")


def scanIsHash(file: BaseFile, scanner, start=0, size=0) -> bool:
    """check if the detection is hash based (complete file)"""

    # default is everything
    if start == 0 and size == 0:
        size = file.Data().getLength()

    firstData: Data = file.DataCopy()
    firstOff = int(size//3 * 1)
    firstData.patchDataFill(firstOff, 1)
    firstFileData: Data = file.getFileDataWith(firstData)
    firstRes = scanner.scannerDetectsBytes(firstFileData.getBytes(), file.filename)

    lastOff = int((size//3) * 2)
    lastData: Data = file.DataCopy()
    lastData.patchDataFill(lastOff, 1)
    lastFileData: Data = file.getFileDataWith(lastData)
    lastRes = scanner.scannerDetectsBytes(lastFileData.getBytes(), file.filename)

    if not firstRes and not lastRes:
        return True
    else:
        return False


def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))


if __name__ == "__main__":
    main()
