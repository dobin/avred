import sys
from struct import unpack_from

codec = 'latin1'    # Assume 'latin1' unless redefined by the 'dir' stream

PYTHON2 = sys.version_info[0] < 3

if PYTHON2:
    def decode(x):
        return x.decode(codec, errors='replace').encode('utf-8')
else:
    xrange = range
    def ord(x):
        return x
    def decode(x):
        return x.decode(codec, errors='replace')

def hexdump(buffer, length=16):
    theHex = lambda data: ' '.join('{:02X}'.format(ord(i)) for i in data)
    theStr = lambda data: ''.join(chr(ord(i)) if (31 < ord(i) < 127) else '.' for i in data)
    result = ''
    for offset in xrange(0, len(buffer), length):
        data = buffer[offset:offset + length]
        result += '{:08X}   {:{}}    {}\n'.format(offset, theHex(data), length * 3 - 1, theStr(data))
    return result

def getWord(buffer, offset, endian):
    return unpack_from(endian + 'H', buffer, offset)[0]

def getDWord(buffer, offset, endian):
    return unpack_from(endian + 'L', buffer, offset)[0]

def skipStructure(buffer, offset, endian, isLengthDW, elementSize, checkForMinusOne):
    if isLengthDW:
        length = getDWord(buffer, offset, endian)
        offset += 4
        skip = checkForMinusOne and (length == 0xFFFFFFFF)
    else:
        length = getWord(buffer, offset, endian)
        offset += 2
        skip = checkForMinusOne and (length == 0xFFFF)
    if not skip:
        offset += length * elementSize
    return offset

def getVar(buffer, offset, endian, isDWord):
    if isDWord:
        value = getDWord(buffer, offset, endian)
        offset += 4
    else:
        value = getWord(buffer, offset, endian)
        offset += 2
    return offset, value

def getTypeAndLength(buffer, offset, endian):
    if endian == '>':
        return ord(buffer[offset]), ord(buffer[offset + 1])
    else:
        return ord(buffer[offset + 1]), ord(buffer[offset])
