
from scanner import ScannerTest, ScannerTestWeighted
from pe_utils import *

#from analyzer import *
from analyzer import parse_pe
from dobin import investigate

class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

def test1():
    # simple
    filename = "files/test.exe"
    detections = []

    # one string in .rodata
    #detections.append( TestDetection(29824, b"Unknown error") )
    
    # TODO PROBLEM with this one
    #detections.append( TestDetection(30810, b"\xff\xff\x10\xb1\xff\xff\xc2\xb2\xff\xff") )
    
    # WORKS
    detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
    
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)
    matches = investigate(pe, scanner)
    return pe, matches


def test2():
    # two sections
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
    # two in one section
    filename = "files/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(31850, b" 10.2.0") )
    # .text
    #detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    
    scanner = ScannerTest(detections)
    pe = parse_pe(filename)
    matches = investigate(pe, scanner)
    return pe, matches


def test4():
    # weighted
    filename = "files/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
    detections.append( TestDetection(31850, b" 10.2.0") )

    # .text
    #detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    
    scanner = ScannerTestWeighted(detections)
    pe = parse_pe(filename)
    matches = investigate(pe, scanner)
    return pe, matches

