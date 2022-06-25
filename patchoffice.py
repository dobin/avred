#!/usr/bin/env python3
import sys
from packers import PackerWord

def patch(data, offset, patch):
    goat = data[:offset] + patch + data[offset+len(patch):]
    return goat


fname = sys.argv[1]
pos = int(sys.argv[2], 0)
dataNew = str.encode(sys.argv[3])

print( f"Writing {dataNew} to file {fname} at position {pos} ")


fp = open(fname, "r+b")
data = fp.read()
fp.close()

packer = PackerWord(data)
makroData = packer.getMakroData()

makroData = patch(makroData, pos, dataNew)

data = packer.pack(makroData)


fp = open(fname, "w+b")
fp.write(data)
fp.close()

