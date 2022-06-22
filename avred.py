#!/usr/bin/python3

import argparse
from scanner import ScannerRest
from test import testMain
from analyzer import *
from config import Config
from intervaltree import IntervalTree, Interval
import logging

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-s', "--server", help="Server")

    parser.add_argument("--isolate", help="Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument("--remove", help="Remove some standard sections at the beginning (experimental)", default=False,  action='store_true')
    parser.add_argument("--checkOnly", help="Check only if AV detects the file", default=False, action='store_true')
    parser.add_argument("--verify", help="Verify results at the end", default=False, action='store_true')
    parser.add_argument("--saveMatches", help="Save matches", default=False, action='store_true')
    parser.add_argument("--ignoreText", help="Dont analyze .text section", default=False, action='store_true')
    parser.add_argument("--test", help="Perform simple test with index 0, 1, 2, ...")
    parser.add_argument("--logtofile", help="Log everything to file")

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)
    if args.logtofile:
        print(f"Logging to file: {args.logtofile}")
        logging.basicConfig(filename=args.logtofile,
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


    if args.test:
        testMain(args.test)
    else:
        if not args.file or not args.server:
            print("Give at least --file and --server")
            return

        config = Config()
        config.load()
        url = config.get("server")[args.server]
        scanner = ScannerRest(url, args.server)

        if args.checkOnly:
            scanFileOnly(args.file, scanner)
        else:
            matches = None
            if args.file.endswith('.ps1'):
                data, matches = analyzeFilePlain(args.file, scanner)
            elif args.file.endswith('.docx'):
                data, matches = analyzeFileWord(args.file, scanner)
            elif args.file.endswith('.exe'):
                pe, matches = analyzeFileExe(args.file, scanner, 
                    newAlgo=True, isolate=args.isolate, remove=args.remove, verify=args.verify, 
                    saveMatches=args.saveMatches, ignoreText=args.ignoreText)

            if args.saveMatches:
                saveMatchesToFile(pe.filename + ".matches.json", matches)

if __name__ == "__main__":
    main()
    