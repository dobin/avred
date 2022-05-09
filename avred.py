import argparse
from find import bytes_detection
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
    detected_sections = []

    for section in pe.sections:
        new_pe = deepcopy(pe)
        hide_section(new_pe, section.name)

        status = scanner.scan(new_pe.data)
        section.detected =  status

        if not status:
            logging.info(f"Section {section.name} triggers the antivirus")
            detected_sections += [section]

    sectionCount = len(detected_sections)
    print(f"{sectionCount} section(s) trigger the antivirus")
    for section in detected_sections:
        print(f"  section: {section.name}")

    return detected_sections


def investigate(pe, scanner):
    detected = scanner.scan(pe.data)
    if not detected:
        logging.error(f"{pe.filename} is not detected by {scanner.scanner_name}")
        return

    # identify which sections get detected
    detected_sections = findDetectedSections(pe, scanner)

    # analyze each section
    matches = []
    for section in detected_sections:
        logging.info(f"Launching bytes analysis on section {section.name}")
        match = bytes_detection(pe.filename, scanner, section.addr, section.addr+section.size)
        matches.append(match)

    return matches


def parse_pe(path):
    pe = PE()
    pe.filename = path
    pe.sections = get_sections(pe)

    if False:
        for section in pe.sections:
            print(f"Section {section.name}  addr: {section.addr}   size: {section.size} ")

    #pe.strings = parse_strings(sample_file, g_args.extensive, g_args.length)
    with open(path, "rb") as f:
        pe.data = f.read()
    return pe


class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

def test():
    #pe, matches = test1()
    pe, matches = test2()
    for match in matches:
            for i in sorted(match):
                print(f"[*] Signature between {i.begin} and {i.end}: ")
                data = pe.data[i.begin:i.end]
                print(hexdump.hexdump(data, result='return'))
                

def test1():
    filename = "files/test.exe"
    detections = []

    # one string in .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)

    matches = investigate(pe, scanner)
    return pe, matches


def test2():
    filename = "files/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )

    # .text
    detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)
    matches = investigate(pe, scanner)
    return pe, matches


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

