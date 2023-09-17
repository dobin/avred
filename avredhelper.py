import os
import pickle
import argparse
import pstats
import r2pipe

from scanner import *
from model.model_base import *
from model.model_code import *
from plugins.pe.file_pe import FilePe
from plugins.pe.augment_pe import DataReferor
from myutils import getOutcomesFromDir, OutcomesToCsv

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


def printFileInfo(filepath):
    filePe = FilePe()
    filePe.loadFromFile(filepath)

    print("Sections:")
    for section in filePe.peSectionsBag.sections:
        print(section)

    print("")
    print("Regions:")
    for region in filePe.regionsBag.sections:
        print(region)


def printFileDataInfo(filepath):
    filePe = FilePe()
    filePe.loadFromFile(filepath)

    r2 = r2pipe.open(filePe.filepath)
    r2.cmd("aaa")  # aaaa
    dataReferor = DataReferor(r2)
    dataReferor.init()
    for s in dataReferor.stringsIt:
        print(s[2])

    disasmLines = dataReferor.query(30144, 28)
    for disasmLine in disasmLines:
        print(disasmLine.text)
    

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
    parser.add_argument("-i", "--info", help="PE File Info")
    parser.add_argument("-d", "--data", help="PE File Data Info")
    parser.add_argument("-c", "--csv", help="Print csv of all outcome files in this directory")
    args = parser.parse_args()

    if args.hashcache:
        hashcache()
    if args.outcome is not None:
        printoutcome(args.outcome)
    if args.csv is not None:
        printcsv(args.csv)
    if args.info is not None:
        printFileInfo(args.info)
    if args.data is not None:
        printFileDataInfo(args.data)

if __name__ == "__main__":
    main()
