#!/usr/bin/env python

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
import os
import sys
import argparse

from file import *

__description__ = 'A VBA p-code disassembler'
__license__ = 'GPL'
__uri__ = 'https://github.com/bontchev/pcodedmp'
__VERSION__ = '1.2.6'
__author__ = 'Vesselin Bontchev'
__email__ = 'vbontchev@yahoo.com'


def main():
    parser = argparse.ArgumentParser(description='Dumps the p-code of VBA-containing documents.')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s version {}'.format(__VERSION__))
    parser.add_argument('-n', '--norecurse', action='store_true',
                        help="Don't recurse into directories")
    parser.add_argument('-d', '--disasmonly', dest='disasmOnly', action='store_true',
                        help='Only disassemble, no stream dumps')
    parser.add_argument('-b', '--verbose', action='store_true',
                        help='Dump the stream contents')
    parser.add_argument('-o', '--output', dest='outputfile', default=None,
                        help='Output file name')
    parser.add_argument('fileOrDir', nargs='+', help='File or dir')
    args = parser.parse_args()
    errorLevel = 0
    try:
        output_file = sys.stdout
        if args.outputfile is not None:
            output_file = open(args.outputfile, 'w')
        for name in args.fileOrDir:
            if os.path.isdir(name):
                for name, subdirList, fileList in os.walk(name):
                    for fname in fileList:
                        fullName = os.path.join(name, fname)
                        results = processFile(fullName)
                        mprint(results)
                    if args.norecurse:
                        while len(subdirList) > 0:
                            del(subdirList[0])
            elif os.path.isfile(name):
                results = processFile(name)
                mprint(results)
            else:
                print('{} does not exist.'.format(name), file=sys.stderr)
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)
        errorLevel = -1
    if args.outputfile is not None:
        output_file.close()
    sys.exit(errorLevel)

def mprint(results):
    print("Results:")
    for result in results:
        for ite in sorted(result):
            print("{} {} {} \n{}".format(ite.begin, ite.end, ite.data.lineNr, ite.data.text))

if __name__ == '__main__':
    main()