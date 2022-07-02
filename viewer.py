import r2pipe
import json
from ansi2html import Ansi2HTMLConverter
import pprint

PREV = 16
POST = 16

def GetViewData(fileContent: bytes, matches, filename):
    conv = Ansi2HTMLConverter()
    r2 = r2pipe.open(filename)
    r2.cmd("aaa")

    baddr = r2.cmdj("e bin.baddr")
    baseAddr = int(baddr, 16)

    for match in matches:
        print(str(match))
        match['startHex'] = str(hex(baseAddr + match['start']))
        match['endHex'] = str(hex(baseAddr + match['end']))
        size = match['end'] - match['start'] + PREV + POST
        addr = baseAddr + match['start'] - PREV

        # r2: Print Dissabled (by bytes)
        asm = r2.cmdj("pDJ {} @{}".format(size, addr))
        pprint.pprint(asm)
        asm = json.loads(asm)

        for a in asm:
            a['textHtml'] = conv.convert(a['text'], full=False)

        match['asm'] = asm
        
    return matches

