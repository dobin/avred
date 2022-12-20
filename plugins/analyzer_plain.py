from reducer import scanData

# no PE file, just check its content
def analyzeFilePlain(filePlain, scanner):
    matchesIntervalTree = scanData(scanner, filePlain.data, filePlain.filename, 0, len(filePlain.data))
    return matchesIntervalTree
