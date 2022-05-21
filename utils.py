

def saveMatchesToFile(pe, matches):
    newFilename = pe.filename + ".matches.json"
    with open(newFilename, 'w') as outfile:
        json.dump(matches, outfile)

