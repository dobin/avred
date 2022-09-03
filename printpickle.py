#!/usr/bin/python3

import pickle
import sys

filename: str = sys.argv[1]
fileData = None
with open(filename, "rb") as input_file:
    fileData = pickle.load(input_file)

print(str(fileData))
