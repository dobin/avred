#!/usr/bin/env python3
import sys
from analyzer_office import FileOffice

# args
fname = sys.argv[1]
pos = int(sys.argv[2], 0)
dataNew = str.encode(sys.argv[3])
print( f"Writing {dataNew} to file {fname} at position {pos} ")

# load
fo = FileOffice(fname)
fo.load()

# get patched
newZip = fo.getPatchedByOffset(pos, dataNew)

# write
fp = open(fname, "w+b")
fp.write(newZip)
fp.close()
