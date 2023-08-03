from dataclasses import dataclass
import json
import pprint
import r2pipe
from ansi2html import Ansi2HTMLConverter
from myutils import *

PREV = 16
POST = 16

def convertMatches(fileContent: bytes, matches, filename):
    conv = Ansi2HTMLConverter()
    r2 = r2pipe.open(filename)
    r2.cmd("e scr.color=2") # enable terminal color output
    r2.cmd("aaa")

    baddr = r2.cmd("e bin.baddr")
    baseAddr = int(baddr, 16)

    full = ""
    for idx, match in enumerate(matches):
        match['idx'] = str(idx)

        data = fileContent[match['start']:match['end']]
        match['textHex'] = hexdmp(data, offset=match['start'])

        match['startHex'] = str(hex(baseAddr + match['start']))
        match['endHex'] = str(hex(baseAddr + match['end']))
        size = match['end'] - match['start'] + PREV + POST
        addr = baseAddr + match['start'] - PREV

        # r2: Print Dissabled (by bytes)
        asm = r2.cmd("pDJ {} @{}".format(size, addr))
        asm = json.loads(asm)

        for a in asm:
            relOffset = a['offset'] - baseAddr

            if relOffset >= match['start'] and relOffset < match['end']:
                a['part'] = True

            a['textHtml'] = conv.convert(a['text'], full=False)
            full += a["text"]

        match['asm'] = asm

    return matches
