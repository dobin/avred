import logging
import json
import os
import base64

from model.model import Match, FileInfo, FileType
from model.testverify import FillType


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
        print(hexdmp(dataDump, offset=i.begin))

        logging.info(f"[*] Signature between {i.begin} and {i.end} size {size}: " + "\n" + hexdmp(dataDump, offset=i.begin))


def convertMatchesIt(matchesIt):
    matches = []
    idx = 0
    for m in matchesIt:
        match = Match(idx, m.begin, m.end-m.begin)
        matches.append(match)
        idx += 1
    return matches

MAX_HEXDUMP_SIZE = 2048

def hexdmp(src, offset=0, length=16):
    if len(src) > 2048:
        return "Match too large ({} > {} max, do not show".format(len(src), MAX_HEXDUMP_SIZE)

    result = []
    digits = 4 if isinstance(src, str) else 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%0*X" % (digits, x)  for x in s])
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.'  for x in s])
        result.append("%08X   %-*s   %s" % (i+offset, length*(digits + 1), hexa, text) )
    return('\n'.join(result))
