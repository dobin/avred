#!/usr/bin/python3

import argparse
import test_pe
import test_office

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", help="Perform simple test with index 0, 1, 2, ...")
    args = parser.parse_args()

    idx = args.test

    if idx == "0":
        pe, matches = test_pe.test0()
    elif idx == "1":
        pe, matches = test_pe.test1()
    elif idx == "2":
        pe, matches = test_pe.test2()
    elif idx == "3":
        pe, matches = test_pe.test3()
    elif idx == "4":
        pe, matches = test_pe.test4()
    elif idx == "docx":
        pe, matches = test_office.testDocx()


if __name__ == "__main__":
    main()
    