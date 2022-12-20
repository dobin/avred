from plugins.analyzer_pe import analyzeFileExe
from model import TestDetection, Scanner
from pprint import pprint

def test0():
    # simple, 1
    filename = "test/test.exe"
    detections = []

    # one string in .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    scanner = ScannerTest(detections)
    
    pe, matches = analyzeFileExe(filename, scanner)
    return pe, matches

def test1():
    # simple, merge 2-OR
    filename = "test/test.exe"
    detections = []
    
    # TODO PROBLEM with this one
    detections.append( TestDetection(30810, b"\xff\xff\x10\xb1\xff\xff\xc2\xb2\xff\xff") )
    # WORKS
    detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
    scanner = ScannerTest(detections)
    
    pe, matches = analyzeFileExe(filename, scanner)
    return pe, matches


def test2():
    # 2 sections OR
    filename = "test/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    # .text
    detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    scanner = ScannerTest(detections)

    pe, matches = analyzeFileExe(filename, scanner)
    return pe, matches


def test3():
    # two in one section OR
    filename = "test/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(31850, b" 10.2.0") )
    # .text
    #detections.append( TestDetection(1664, b"\xf4\x63\x00\x00\xe8\x87\x6a\x00\x00\x48\x8b\x15\x40") )
    scanner = ScannerTest(detections)

    pe, matches = analyzeFileExe(filename, scanner)
    return pe, matches


def test4():
    # weighted (at least half)
    filename = "test/test.exe"
    detections = []
    # .rodata
    detections.append( TestDetection(29824, b"Unknown error") )
    detections.append( TestDetection(30823, b"\xff\x98\xb0\xff\xff\xdb\xb1\xff") )
    detections.append( TestDetection(31850, b" 10.2.0") )
    detections.append( TestDetection(33150, b"\x00\x00\x47\x43\x43\x3a\x20") )

    scanner = ScannerTestWeighted(detections)

    pe, matches = analyzeFileExe(filename, scanner)
    return pe, matches


class ScannerTest(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)

    def scan(self, data, filename):
        for detection in self.detections:
            fileData = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData != detection.refData:
                return False

        return True    


class ScannerTestWeighted(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)

    def scan(self, data, filename):
        n = 0
        for detection in self.detections:
            fileData = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData == detection.refData:
                n += 1

        if n > int(len(self.detections) // 2):
            return True
        else:
            return False

