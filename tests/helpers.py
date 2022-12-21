

class TestDetection():
    def __init__(self, refPos, refData):
        self.refPos = refPos
        self.refData = refData

    def __str__(self):
        return f"{self.refPos} {self.refData}"
    def __repr__(self):
        return f"{self.refPos} {self.refData}"
