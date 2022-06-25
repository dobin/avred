from analyzer_office import analyzeFileWord
from scanner import ScannerRest

def testWordMain():
    scanner = ScannerRest("http://192.168.88.127:8001/", "Defender")
    analyzeFileWord("testing/office/word.docm", scanner)


if __name__ == "__main__":
    testWordMain()

    