
from scanner import ScannerTest, ScannerTestWeighted
from analyzer import *
from pe_utils import *


class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

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


def test3():
    filename = "files/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(31850, b" 10.2.0") )

    # .text
    detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    scanner = ScannerTestWeighted(detections)

    pe = parse_pe(filename)
    matches = investigate(pe, scanner)
    return pe, matches

