import json

#def saveInfoToFile(filename, pe, matches):
#    with open(filename, 'w') as outfile:
        


def saveMatchesToFile(filename, matches):
    # convert first
    results = []
    for match in matches: 
        result = {
            "start": match.begin,
            "end": match.end,
        }
        results.append(result)

    with open(filename, 'w') as outfile:
        json.dump(results, outfile)

