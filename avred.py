import argparse
from scanner import ScannerRest
from test import testMain
from analyzer import *
from config import Config

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--test", help="Test 0, 1, 2, ...")
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-s', "--server", help="Server")
    args = parser.parse_args()

    if args.test:
        testMain(args.test)
    else:
        if not args.file or not args.server:
            print("GIFE")
            return

        config = Config()
        config.load()
        url = config.get("server")[args.server]
        scanner = ScannerRest(url, args.server)

        analyzeFile(args.file, scanner, newAlgo=True)


if __name__ == "__main__":
    main()
    