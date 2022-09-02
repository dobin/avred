#!/usr/bin/python3

import argparse
from scanner import ScannerRest
from analyzer_office import analyzeFileWord
from analyzer_pe import analyzeFileExe
from analyzer_plain import analyzeFilePlain
from analyzer import scanFileOnly
from config import Config
import logging
from utils import saveMatchesToFile
from verifier import verify
from file_pe import FilePe
from model import Scanner, Packer, Match, Verification, FileData
import pickle
from file_office import FileOffice

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-s', "--server", help="Server")

    parser.add_argument("--logtofile", help="Log everything to file", default=False, action='store_true')
    parser.add_argument("--checkOnly", help="Check only if AV detects the file", default=False, action='store_true')
    parser.add_argument("--verify", help="Verify results at the end", default=False, action='store_true')
    parser.add_argument("--save", help="Save results", default=False, action='store_true')

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
        matches = None
        verifications = None

        if args.file.endswith('.ps1'):
            data, matches = analyzeFilePlain(args.file, scanner)
            
        elif args.file.endswith('.docm'):  # dotm, xlsm, xltm
            fileOffice = FileOffice()
            fileOffice.loadFromFile(args.file)
            matches = analyzeFileWord(fileOffice, scanner)

        elif args.file.endswith('.exe'):
            filePe = FilePe(args.file)
            filePe.load()
            filePe.printSections()

            matches = analyzeFileExe(filePe, scanner, 
                isolate=args.isolate, remove=args.remove, ignoreText=args.ignoreText)

            if args.verify:
                verifications = verify(filePe, matches, scanner)
                printVerifyData(verifications)

        if args.save:
            fileData = FileData(matches, verifications)
            with open(args.file + '.pickle', 'wb') as handle:
                pickle.dump(fileData, handle)


def printVerifyData(verificationRuns):
    for verificationRun in verificationRuns:
        print(str(verificationRun))

        for test in verificationRun.testEntries:
            print("A: " + str(test))

def printMatches(matches):
    for match in matches:
        print("Match: " + str(match))

if __name__ == "__main__":
    main()
    