from plugins.analyzer_office import analyzeFileWord
from model.model import TestDetection, Scanner
from pprint import pprint
from plugins.file_office import FileOffice
from scanner import ScannerRest

def testDocx():
    filename = "test/word.docm"
    detections = []
    detections.append( TestDetection(10656, b"e VB_Nam\x00e = ") )

    scanner = ScannerTestDocx(detections)
    pe, matches = analyzeFileWord(filename, scanner)
    return pe, matches


class ScannerTestDocx(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)


    def scan(self, data, filename):
        # make an office file of it again
        fileOfficeSend = self.packer.pack(data)

        # unpack office file
        fileOffice = FileOffice()
        fileOffice.loadFromMem(fileOfficeSend)

        for detection in self.detections:
            fileData = fileOffice.data[detection.refPos:detection.refPos+len(detection.refData)] 
            if fileData != detection.refData:
                return False

        return True


def testWordMain():
    scanner = ScannerRest("http://192.168.88.127:8001/", "Defender")
    analyzeFileWord("testing/office/word.docm", scanner)


if __name__ == "__main__":
    testWordMain()
