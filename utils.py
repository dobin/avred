import json

def saveMatchesToFile(pe, matches):
    # convert first
    results = []
    for match in matches: 
        result = {
            "start": match.begin,
            "end": match.end,
        }
        results.append(result)

    newFilename = pe.filename + ".matches.json"
    with open(newFilename, 'w') as outfile:
        json.dump(results, outfile)

