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
                            level=logging.INFO
                    )
rootLogger = logging.getLogger()
logFormatter = logging.Formatter(log_format)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)
logging.getLogger().setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--test", help="Test 0, 1, 2, ...")
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-s', "--server", help="Server")

    parser.add_argument('-i', "--isolate", help="Isolate sections to be tested (null all other)", default=False,  action='store_true')
    parser.add_argument('-r', "--remove", help="Remove some standard sections at the beginning", default=False,  action='store_true')
    parser.add_argument('-c', "--checkOnly", help="Check only", default=False, action='store_true')
    parser.add_argument('-y', "--verify", help="Verify result", default=False, action='store_true')
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

        if args.checkOnly:
            pe = parse_pe(args.file)
            detected = scanner.scan(pe.data)
            if detected:
                print("File is detected")
            else:
                print("File is not detected")
            
        else:
            pe, matches = analyzeFile(args.file, scanner, 
                newAlgo=True, isolate=args.isolate, remove=args.remove, verify=args.verify)


if __name__ == "__main__":
    main()
    