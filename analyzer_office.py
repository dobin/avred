import os
from reducer_rutd import scanData
from packers import PackerWord

def analyzeFileWord(filepath, scanner):
    dataZip = None
    with open(filepath, "rb") as file:
        dataZip = file.read()

    packer = PackerWord(dataZip)
    scanner.setPacker(packer)

    makroData = packer.getMakroData()
    match = scanData(scanner, makroData, os.path.basename(filepath), 0, len(makroData))
    return makroData, match