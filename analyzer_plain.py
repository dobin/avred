import os
from reducer_rutd import scanData

# no PE file, just check its content
def analyzeFilePlain(filename, scanner):
    data = None
    with open(filename, "rb") as file:
        data = file.read()
    match = scanData(scanner, data, os.path.basename(filename), 0, len(data))
    return data, match
