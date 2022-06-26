
import copy
import logging

from reducer_rutd import scanData
from packers import PackerWord
from utils import patchData, FillType
from file_office import FileOffice


def analyzeFileWord(filepath, scanner, verify=True):
    fileOffice = FileOffice(filepath)
    fileOffice.load()
    makroData = fileOffice.data

    packer = PackerWord(fileOffice)
    scanner.setPacker(packer)

    matches = scanData(scanner, makroData, fileOffice.filename, 0, len(makroData))

    if verify: 
        verifyFile(fileOffice, matches, scanner)

    return makroData, matches


def verifyFile(officeFile, matches, scanner):
    print("Patching file with results...")
    logging.info("Patching file with results...")

    officeFile = copy.deepcopy(officeFile)
    data = copy.copy(officeFile.data)

    for i in matches:
        size = i.end - i.begin
        print(f"Patch: {i.begin}-{i.end} size {size}")
        logging.info(f"Patch: {i.begin}-{i.end} size {size}")

        data = patchData(data, i.begin, size)

        if not scanner.scan(officeFile.getPatchedByReplacement(data), officeFile.filename):
            print("Success, not detected!")
            logging.info("Success, not detected!")
            return

    print("Still detected? :-(")
    logging.info("Still detected? :-(")

