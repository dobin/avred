import logging
import json
import random
import os
from enum import Enum
import base64
import hexdump

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


class FillType(Enum):
    null = 1
    space = 2
    highentropy = 3
    lowentropy = 4


def patchData(data: bytes, base: int, size: int, fillType: FillType=FillType.null) -> bytes:
    fill = None # has to be exactly <size> bytes
    if fillType is FillType.null:
        fill = b"\x00" * size
    elif fillType is FillType.space:
        fill = b" " * size
    elif fillType is FillType.highentropy:
        #fill = random.randbytes(size) # 3.9..
        fill = os.urandom(size)
    elif fillType is FillType.lowentropy:
        #temp = random.randbytes(size) # 3.9..
        temp = os.urandom(size)
        temp = base64.b64encode(temp)
        fill = temp[:size]

    d = bytearray(data)
    d[base:base+size] = fill
    data = bytes(d)

    return data


def printMatches(data, matches):
    for i in matches:
        size = i.end - i.begin
        dataDump = data[i.begin:i.end]

        print(f"[*] Signature between {i.begin} and {i.end} size {size}: ")
        print(hexdump.hexdump(dataDump, result='return'))

        logging.info(f"[*] Signature between {i.begin} and {i.end} size {size}: " + "\n" + hexdump.hexdump(dataDump, result='return'))
