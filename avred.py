#!/usr/bin/python3

import argparse
from scanner import ScannerRest
from analyzer_office import analyzeFileWord, augmentFileWord
from analyzer_pe import analyzeFileExe, augmentFilePe
from analyzer_plain import analyzeFilePlain
from analyzer import scanFileOnly
from config import Config
import logging
from utils import saveMatchesToFile
from verifier import verify
from file_pe import FilePe
from model import FileData
import pickle
from file_office import FileOffice
import os
from model import Match

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument('-s', "--server", help="Avred Server to use")

    # --logonly (no saving files)
    # --noaugment
    # --noverify

    parser.add_argument("--fromMatches", help="Skip AV, load from matches json", default=False, action='store_true')

    parser.add_argument("--logtofile", help="Log everything to file", default=False, action='store_true')
    parser.add_argument("--checkOnly", help="Check only if AV detects the file", default=False, action='store_true')
    parser.add_argument("--verify", help="Verify results at the end", default=False, action='store_true')
    parser.add_argument("--save", help="Save results", default=False, action='store_true')

    # analyzer options
    parser.add_argument("--isolate", help="PE: Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument("--remove", help="PE: Remove some standard sections at the beginning (experimental)", default=False,  action='store_true')
    parser.add_argument("--ignoreText", help="PE: Dont analyze .text section", default=False, action='store_true')

    args = parser.parse_args()

    if not args.file or not args.server:
        print("Give at least --file and --server")
        return

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
    url = config.get("server")[args.server]
    scanner = ScannerRest(url, args.server)

    if args.checkOnly:
        scanFileOnly(args.file, scanner)

        
    else:
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


def printVerifyData(verifications):
    print("Verification: " + str(len(verifications)))
    for verification in verifications:
        print(str(verification))
        #for test in verification.testEntries:
        #    print("A: " + str(test))


def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))


if __name__ == "__main__":
    main()
    