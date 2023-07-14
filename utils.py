import logging
import json
import re
from typing import List
from intervaltree import IntervalTree

from model.model_data import Match
from config import MAX_HEXDUMP_SIZE


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


def printMatches(data, matches: List[Match]):
    for i in matches:
        size = i.end - i.begin
        dataDump = data[i.begin:i.end]

        print(f"[*] Signature between {i.begin} and {i.end} size {size}: ")
        print(hexdmp(dataDump, offset=i.begin))

        logging.info(f"[*] Signature between {i.begin} and {i.end} size {size}: " + "\n" + hexdmp(dataDump, offset=i.begin))


def convertMatchesIt(matchesIt: IntervalTree, iteration: int = 0, baseIdx: int = 0) -> List[Match]:
    matches: List[Match] = []
    idx = 0 + baseIdx
    for m in sorted(matchesIt):
        match = Match(idx, m.begin, m.end-m.begin, iteration)
        matches.append(match)
        idx += 1
    return matches


def hexdmp(src, offset=0, length=16):
    if len(src) > MAX_HEXDUMP_SIZE:
        return "Match too large ({} > {} max, do not show".format(len(src), MAX_HEXDUMP_SIZE)

    result = []
    digits = 4 if isinstance(src, str) else 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%0*X" % (digits, x)  for x in s])
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.'  for x in s])
        result.append("%08X   %-*s   %s" % (i+offset, length*(digits + 1), hexa, text) )
    return('\n'.join(result))


def hexstr(src: bytes, offset=0, length=0):
    if length == 0:
        length = len(src)
    byte_buffer = src[offset:offset+length]
    hex_string = ' '.join([f'{x:02x}' for x in byte_buffer])
    return hex_string


# https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def removeAnsi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)
