#!/usr/bin/env python3
import sys

fname = sys.argv[1]
pos = int(sys.argv[2], 0)

#data = str.encode(sys.argv[3])
data = bytes.fromhex(sys.argv[3])
#len = int(sys.argv[3])

#data = b"A" * len

print( f"Writing {len} bytes to file {fname} at position {pos} ")

fp = open(fname, "r+b")

fp.seek(pos)
fp.write(data)

fp.close()