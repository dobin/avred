import os
import pickle
import argparse
import pstats

from scanner import *
from model.model_base import *
from model.model_code import *
from utils import getOutcomesFromDir, OutcomesToCsv

HASHCACHE_FILE = "hashcache.pickle"


def hashcache():
    if not os.path.exists(HASHCACHE_FILE):
        print("HashCache file does not exist: {}".format(HASHCACHE_FILE))

    with open(HASHCACHE_FILE, "rb") as file:
        cache = pickle.load(file)
        print("TimeRounded;Time;Filename;Scanner;Result")
        for entry in cache.values():
            if entry.scanTime > 1:
                scantime = round(entry.scanTime, 1)
                scantime = str(scantime).replace('.', ',')
                print("{};{};{};{};{}".format(scantime,entry.scanTime, entry.scannerName, entry.filename, entry.result))


def printoutcome(filename: str):
    with open(filename, "rb") as input_file:
        outcome = pickle.load(input_file)
        print(str(outcome))


def patchfile(fname: str, pos: int, data: bytes):
    print( f"Writing {len} bytes to file {fname} at position {pos} ")

    fp = open(fname, "r+b")

    fp.seek(pos)
    fp.write(data)

    fp.close()
    

def printperf():
    # python3 -m cProfile -s time -o perf.txt nkeyrollover.py
    p = pstats.Stats('perf.txt')
    p.sort_stats('cumulative').print_stats() 


def printcsv(dir: str):
    outcomes = getOutcomesFromDir(dir)
    print(OutcomesToCsv(outcomes))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--hashcache", help="Print HashCache content", default=False, action='store_true')
    parser.add_argument("-o", "--outcome", help="Print HashCache content")
    parser.add_argument("-c", "--csv", help="Print csv of all outcome files in this directory")
    args = parser.parse_args()

    if args.hashcache:
        hashcache()
    if args.outcome is not None:
        printoutcome(args.outcome)
    if args.csv is not None:
        printcsv(args.csv)


if __name__ == "__main__":
    main()
