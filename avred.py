import argparse
from pe_utils import *
from scanner import ScannerRest, ScannerTest
from test import testMain
from analyzer import *

log_format = '[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s'
logging.basicConfig(filename='debug.log',
                            filemode='a',
                            format=format,
                            datefmt='%Y/%m/%d %H:%M',
                            level=logging.DEBUG
                    )
rootLogger = logging.getLogger()
logFormatter = logging.Formatter(log_format)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)


if __name__ == "__main__":
    default_scanner = "Rest"
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--test", help="Test")
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-c', '--section', help="Analyze provided section")
    parser.add_argument('-S', "--scanner", help="Antivirus engine", default=default_scanner)
    args = parser.parse_args()

    if args.scanner == default_scanner:
        scanner = ScannerRest()

    if args.test:
        testMain(args.test)
    else:
        analyzeFile(args.file, scanner, newAlgo=True)
        #pe = parse_pe(args.file)
        #investigate(pe, scanner)

