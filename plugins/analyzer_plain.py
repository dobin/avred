from reducer import Reducer

# no PE file, just check its content
def analyzeFilePlain(filePlain, scanner, analyzerOptions):
    reducer = Reducer(filePlain, scanner)
    matchesIntervalTree = reducer.scan(0, len(filePlain.data))
    return matchesIntervalTree
