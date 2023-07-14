from model.model_data import Data
from plugins.model import BaseFile


def scanIsHash(file: BaseFile, scanner, start=0, size=0) -> bool:
    """check if the detection is hash based (complete file)"""

    # default is everything
    if start == 0 and size == 0:
        size = file.Data().getLength()

    offsets = [
        #512,            # begin
        size // 4,       # 1/4
        size // 2,       # 1/2
        (size // 4) * 3, # 3/4
        size - 1         # end
    ]

    scanResults = []
    for offset in offsets:
        d = file.DataCopy()
        d.patchDataFill(offset, 1)
        detected = scanner.scannerDetectsBytes(d.getBytes(), file.filename)
        scanResults.append(detected)

    # if all modifications result in not-detected, its hash based
    for res in scanResults:
        if res:
            return False
    return True
