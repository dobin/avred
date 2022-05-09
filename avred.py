import argparse
import sys
from tempfile import NamedTemporaryFile

from find import bytes_detection
from find_bad_strings import bissect
from pe_utils import *
from scanner import ScannerRest, ScannerTest

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

BINARY = ""
g_args = None


"""
attempts to locate the part in a PE file that causes the antivirus detection
"""
def findDetectedSections(pe, scanner):
    nb_section_detected = 0
    detected_sections = []

    for section in pe.sections:
        # copy the binary
        new_name = NamedTemporaryFile().name
        shutil.copyfile(pe.filename, new_name)

        # hide the section
        new_pe = deepcopy(pe)
        new_pe.filename = new_name
        hide_section(new_pe, section.name)
        new_pe.md5 = md5(new_name)

        #logging.debug(f"Scanning {new_name} md5 = {new_pe.md5}")
        # scan it
        status = not scanner.scan(new_pe.filename)

        # record the result
        section.detected = not status

        if status:
            logging.info(f"Section {section.name} triggers the antivirus")
            nb_section_detected += 1
            detected_sections += [section]

    print(f"{nb_section_detected} section(s) trigger the antivirus")
    for section in detected_sections:
        print(f"  section: {section.name}")

    return nb_section_detected, detected_sections


def investigate(pe, scanner):
    detected = scanner.scan(pe.filename)
    if not detected:
        logging.error(f"{pe.filename} is not detected by {scanner.scanner_name}")
        return

    # identify which sections get detected
    _, detected_sections = findDetectedSections(pe, scanner)

    # analyze each section
    matches = []
    for section in detected_sections:
        logging.info(f"Launching bytes analysis on section {section.name}")
        match = bytes_detection(pe.filename, scanner, section.addr, section.addr+section.size)
        matches.append(match)

    return matches


def parse_pe(sample_file):
    pe = PE()
    pe.filename = sample_file
    pe.sections = get_sections(pe)
    #pe.strings = parse_strings(sample_file, g_args.extensive, g_args.length)
    pe.md5 = md5(sample_file)
    return pe


class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

def test():
    test1()
    #test2()

def test1():
    # one string in .rodata
    filename = "files/test.exe"
    detections = []
    detections.append( TestDetection(29824, b"Unknown error") )
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)

    matches = investigate(pe, scanner)
    for match in matches:
        for i in sorted(match):
            print(f"[*] Signature between {i.begin} and {i.end}: ")
            data = b"AAAA"
            print(hexdump.hexdump(data, result='return'))


def test2():
    # one string in .rodata
    filename = "files/test.exe"
    detections = []
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(29824, b"Unknown error") )
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)
    investigate(pe, scanner)


if __name__ == "__main__":
    default_scanner = "Rest"
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--test", help="Test")
    parser.add_argument("-f", "--file", help="path to file")
    parser.add_argument('-c', '--section', help="Analyze provided section")
    parser.add_argument('-S', "--scanner", help="Antivirus engine", default=default_scanner)
    g_args = parser.parse_args()

    if g_args.scanner == default_scanner:
        scanner = ScannerRest()

    if g_args.test:
        test()
    else:
        pe = parse_pe(g_args.file)
        investigate(pe, scanner)

