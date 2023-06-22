from pprint import pprint

from model.model import Scanner


class ScannerTest(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)

    def scannerDetectsBytes(self, data, filename):
        for detection in self.detections:
            dataSnippet = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if dataSnippet != detection.refData:
                return False

        return True


class ScannerTestOr(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)

    def scannerDetectsBytes(self, data, filename):
        for detection in self.detections:
            dataSnippet = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if dataSnippet == detection.refData:
                return True

        return False
    

class ScannerTestWeighted(Scanner):
    def __init__(self, detections):
        self.detections = detections
        pprint(detections, indent=4)

    def scannerDetectsBytes(self, data, filename):
        n = 0
        for detection in self.detections:
            dataSnippet = data[detection.refPos:detection.refPos+len(detection.refData)] 
            if dataSnippet == detection.refData:
                n += 1

        if n > int(len(self.detections) // 2):
            return True
        else:
            return False

