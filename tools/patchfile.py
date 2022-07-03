#!/usr/bin/env python3
import sys

fname = sys.argv[1]
pos = int(sys.argv[2], 0)
data = str.encode(sys.argv[3])

print( f"Writing {data} to file {fname} at position {pos} ")

fp = open(fname, "r+b")

fp.seek(pos)
fp.write(data)

fp.close()