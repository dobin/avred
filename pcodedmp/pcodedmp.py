#!/usr/bin/env python

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
import os
import sys
import argparse
import itertools
from intervaltree import Interval, IntervalTree
import pprint

try:
    import win_unicode_console
    WIN_UNICODE_CONSOLE = True
except ImportError:
    WIN_UNICODE_CONSOLE = False
from struct import unpack_from
from oletools.olevba import VBA_Parser, decompress_stream
from oletools.common import codepages

PYTHON2 = sys.version_info[0] < 3
codec = 'latin1'    # Assume 'latin1' unless redefined by the 'dir' stream
if PYTHON2:
    def decode(x):
        return x.decode(codec, errors='replace').encode('utf-8')
else:
    xrange = range
    def ord(x):
        return x
    def decode(x):
        return x.decode(codec, errors='replace')

__description__ = 'A VBA p-code disassembler'
__license__ = 'GPL'
__uri__ = 'https://github.com/bontchev/pcodedmp'
__VERSION__ = '1.2.6'
__author__ = 'Vesselin Bontchev'
__email__ = 'vbontchev@yahoo.com'

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

def processDir(vbaParser, dirPath, disasmOnly, verbose, output_file=sys.stdout):
    tags = {
	 1 : 'PROJ_SYSKIND',	# 0 - Win16, 1 - Win32, 2 - Mac, 3 - Win64
	 2 : 'PROJ_LCID',
	 3 : 'PROJ_CODEPAGE',
	 4 : 'PROJ_NAME',
	 5 : 'PROJ_DOCSTRING',
	 6 : 'PROJ_HELPFILE',
	 7 : 'PROJ_HELPCONTEXT',
	 8 : 'PROJ_LIBFLAGS',
	 9 : 'PROJ_VERSION',
	10 : 'PROJ_GUID',
	11 : 'PROJ_PROPERTIES',
	12 : 'PROJ_CONSTANTS',
	13 : 'PROJ_LIBID_REGISTERED',
	14 : 'PROJ_LIBID_PROJ',
	15 : 'PROJ_MODULECOUNT',
	16 : 'PROJ_EOF',
	17 : 'PROJ_TYPELIB_VERSION',
	18 : 'PROJ_COMPAT_EXE',
	19 : 'PROJ_COOKIE',
	20 : 'PROJ_LCIDINVOKE',
	21 : 'PROJ_COMMAND_LINE',
	22 : 'PROJ_REFNAME_PROJ',

	25 : 'MOD_NAME',
	26 : 'MOD_STREAM',

	28 : 'MOD_DOCSTRING',
	29 : 'MOD_HELPFILE',
	30 : 'MOD_HELPCONTEXT',

	32 : 'MOD_PROPERTIES',
	33 : 'MOD_FBASMOD_StdMods',
	34 : 'MOD_FBASMOD_Classes',
	35 : 'MOD_FBASMOD_Creatable',
	36 : 'MOD_FBASMOD_NoDisplay',
	37 : 'MOD_FBASMOD_NoEdit',
	38 : 'MOD_FBASMOD_RefLibs',
	39 : 'MOD_FBASMOD_NonBasic',
	40 : 'MOD_FBASMOD_Private',
	41 : 'MOD_FBASMOD_Internal',
	42 : 'MOD_FBASMOD_AllModTypes',
	43 : 'MOD_END',
	44 : 'MOD_COOKIETYPE',
	45 : 'MOD_BASECLASSNULL',
	46 : 'MOD_BASECLASS',
	47 : 'PROJ_LIBID_TWIDDLED',
	48 : 'PROJ_LIBID_EXTENDED',
	49 : 'MOD_TEXTOFFSET',
	50 : 'MOD_UNICODESTREAM',

	60 : 'PROJ_UNICODE_CONSTANTS',
	61 : 'PROJ_UNICODE_HELPFILE',
	62 : 'PROJ_UNICODE_REFNAME_PROJ',
	63 : 'PROJ_UNICODE_COMMAND_LINE',
	64 : 'PROJ_UNICODE_DOCSTRING',

	71 : 'MOD_UNICODE_NAME',
	72 : 'MOD_UNICODE_DOCSTRING',
	73 : 'MOD_UNICODE_HELPFILE'
    }
    global codec
    if not disasmOnly:
        print('-' * 79, file=output_file)
        print('dir stream after decompression:', file=output_file)
    is64bit = False
    dirDataCompressed = vbaParser.ole_file.openstream(dirPath).read()
    dirData = decompress_stream(dirDataCompressed)
    streamSize = len(dirData)
    codeModules = []
    if not disasmOnly:
        print('{:d} bytes'.format(streamSize), file=output_file)
        if verbose:
            print(hexdump(dirData), file=output_file)
        print('dir stream parsed:', file=output_file)
    offset = 0
    # The "dir" stream is ALWAYS in little-endian format, even on a Mac
    while offset < streamSize:
        try:
            tag = getWord(dirData, offset, '<')
            wLength = getWord(dirData, offset + 2, '<')
            # The following idiocy is because Microsoft can't stick
            # to their own format specification
            if tag == 9:
                wLength = 6
            elif tag == 3:
                wLength = 2
            # End of the idiocy
            if not tag in tags:
                tagName = 'UNKNOWN'
            else:
                tagName = tags[tag]
            if not disasmOnly:
                print('{:08X}:  {}'.format(offset, tagName), end='', file=output_file)
            offset += 6
            if wLength:
                if not disasmOnly:
                    print(':', file=output_file)
                    print(hexdump(dirData[offset:offset + wLength]), file=output_file)
                if tagName == 'PROJ_CODEPAGE':
                    codepage = getWord(dirData, offset, '<')
                    codec = codepages.codepage2codec(codepage)
                elif tagName == 'MOD_UNICODESTREAM':
                    # Convert the stream name from UTF-16-LE to Unicode:
                    stream_name_unicode = dirData[offset:offset + wLength].decode('utf_16_le', errors='replace')
                    if PYTHON2:
                        # On Python 2 only, convert it to bytes in UTF-8, so that it is a native str:
                        stream_name = stream_name_unicode.encode('utf8', errors='replace')
                    else:
                        # On Python 3, native str are unicode
                        stream_name = stream_name_unicode
                    codeModules.append(stream_name)
                elif tagName == 'PROJ_SYSKIND':
                    sysKind = getDWord(dirData, offset, '<')
                    is64bit = sysKind == 3
                offset += wLength
            elif not disasmOnly:
                print('', file=output_file)
        except:
            break
    return dirData, codeModules, is64bit

def process_VBA_PROJECT(vbaParser, vbaProjectPath, disasmOnly, verbose, output_file=sys.stdout):
    vbaProjectData = vbaParser.ole_file.openstream(vbaProjectPath).read()
    if disasmOnly:
        return vbaProjectData
    print('-' * 79, file=output_file)
    print('_VBA_PROJECT stream:', file=output_file)
    print('{:d} bytes'.format(len(vbaProjectData)), file=output_file)
    if verbose:
        print(hexdump(vbaProjectData), file=output_file)
    return vbaProjectData

def getTheIdentifiers(vbaProjectData):
    identifiers = []
    try:
        magic = getWord(vbaProjectData, 0, '<')
        if magic != 0x61CC:
            return identifiers
        version = getWord(vbaProjectData, 2, '<')
        unicodeRef  = (version >= 0x5B) and (not version in [0x60, 0x62, 0x63]) or (version == 0x4E)
        unicodeName = (version >= 0x59) and (not version in [0x60, 0x62, 0x63]) or (version == 0x4E)
        nonUnicodeName = ((version <= 0x59) and (version != 0x4E)) or (0x5F > version > 0x6B)
        word = getWord(vbaProjectData, 5, '<')
        if word == 0x000E:
            endian = '>'
        else:
            endian = '<'
        offset = 0x1E
        offset, numRefs = getVar(vbaProjectData, offset, endian, False)
        offset += 2
        for _ in itertools.repeat(None, numRefs):
            offset, refLength = getVar(vbaProjectData, offset, endian, False)
            if refLength == 0:
                offset += 6
            else:
                if ((unicodeRef and (refLength < 5)) or ((not unicodeRef) and (refLength < 3))):
                    offset += refLength
                else:
                    if unicodeRef:
                        c = vbaProjectData[offset + 4]
                    else:
                        c = vbaProjectData[offset + 2]
                    offset += refLength
                    if chr(ord(c)) in ['C', 'D']:
                        offset = skipStructure(vbaProjectData, offset, endian, False, 1, False)
            offset += 10
            offset, word = getVar(vbaProjectData, offset, endian, False)
            if word:
                offset = skipStructure(vbaProjectData, offset, endian, False, 1, False)
                offset, wLength = getVar(vbaProjectData, offset, endian, False)
                if wLength:
                    offset += 2
                offset += wLength + 30
        # Number of entries in the class/user forms table
        offset = skipStructure(vbaProjectData, offset, endian, False, 2, False)
        # Number of compile-time identifier-value pairs
        offset = skipStructure(vbaProjectData, offset, endian, False, 4, False)
        offset += 2
        # Typeinfo typeID
        offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
        # Project description
        offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
        # Project help file name
        offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
        offset += 0x64
        # Skip the module descriptors
        offset, numProjects = getVar(vbaProjectData, offset, endian, False)
        for _ in itertools.repeat(None, numProjects):
            offset, wLength = getVar(vbaProjectData, offset, endian, False)
            # Code module name
            if unicodeName:
                offset += wLength
            if nonUnicodeName:
                if wLength:
                    offset, wLength = getVar(vbaProjectData, offset, endian, False)
                offset += wLength
            # Stream time
            offset = skipStructure(vbaProjectData, offset, endian, False, 1, False)
            offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
            offset, _ = getVar(vbaProjectData, offset, endian, False)
            if version >= 0x6B:
                offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
            offset = skipStructure(vbaProjectData, offset, endian, False, 1, True)
            offset += 2
            if version != 0x51:
                offset += 4
            offset = skipStructure(vbaProjectData, offset, endian, False, 8, False)
            offset += 11
        offset += 6
        offset = skipStructure(vbaProjectData, offset, endian, True, 1, False)
        offset += 6
        offset, w0 = getVar(vbaProjectData, offset, endian, False)
        offset, numIDs = getVar(vbaProjectData, offset, endian, False)
        offset, w1 = getVar(vbaProjectData, offset, endian, False)
        offset += 4
        numJunkIDs = numIDs + w1 - w0
        numIDs = w0 - w1
        # Skip the junk IDs
        for _ in itertools.repeat(None, numJunkIDs):
            offset += 4
            idType, idLength = getTypeAndLength(vbaProjectData, offset, endian)
            offset += 2
            if idType > 0x7F:
                offset += 6
            offset += idLength
        # Now offset points to the start of the variable names area
        for _ in itertools.repeat(None, numIDs):
            isKwd = False
            ident = ''
            idType, idLength = getTypeAndLength(vbaProjectData, offset, endian)
            offset += 2
            if (idLength == 0) and (idType == 0):
                offset += 2
                idType, idLength = getTypeAndLength(vbaProjectData, offset, endian)
                offset += 2
                isKwd = True
            if idType & 0x80:
                offset += 6
            if idLength:
                ident = decode(vbaProjectData[offset:offset + idLength])
                identifiers.append(ident)
                offset += idLength
            if not isKwd:
                offset += 4
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)
    return identifiers

#'name', '0x', 'imp_', 'func_', 'var_', 'rec_', 'type_', 'context_'
#    2,     2,      2,       4,      4,      4,       4,         4

# VBA7 opcodes; VBA3, VBA5 and VBA6 will be upconverted to these.
opcodes = {
  0 : { 'mnem' : 'Imp',                   'args' : [],                       'varg' : False },
  1 : { 'mnem' : 'Eqv',                   'args' : [],                       'varg' : False },
  2 : { 'mnem' : 'Xor',                   'args' : [],                       'varg' : False },
  3 : { 'mnem' : 'Or',                    'args' : [],                       'varg' : False },
  4 : { 'mnem' : 'And',                   'args' : [],                       'varg' : False },
  5 : { 'mnem' : 'Eq',                    'args' : [],                       'varg' : False },
  6 : { 'mnem' : 'Ne',                    'args' : [],                       'varg' : False },
  7 : { 'mnem' : 'Le',                    'args' : [],                       'varg' : False },
  8 : { 'mnem' : 'Ge',                    'args' : [],                       'varg' : False },
  9 : { 'mnem' : 'Lt',                    'args' : [],                       'varg' : False },
 10 : { 'mnem' : 'Gt',                    'args' : [],                       'varg' : False },
 11 : { 'mnem' : 'Add',                   'args' : [],                       'varg' : False },
 12 : { 'mnem' : 'Sub',                   'args' : [],                       'varg' : False },
 13 : { 'mnem' : 'Mod',                   'args' : [],                       'varg' : False },
 14 : { 'mnem' : 'IDiv',                  'args' : [],                       'varg' : False },
 15 : { 'mnem' : 'Mul',                   'args' : [],                       'varg' : False },
 16 : { 'mnem' : 'Div',                   'args' : [],                       'varg' : False },
 17 : { 'mnem' : 'Concat',                'args' : [],                       'varg' : False },
 18 : { 'mnem' : 'Like',                  'args' : [],                       'varg' : False },
 19 : { 'mnem' : 'Pwr',                   'args' : [],                       'varg' : False },
 20 : { 'mnem' : 'Is',                    'args' : [],                       'varg' : False },
 21 : { 'mnem' : 'Not',                   'args' : [],                       'varg' : False },
 22 : { 'mnem' : 'UMi',                   'args' : [],                       'varg' : False },
 23 : { 'mnem' : 'FnAbs',                 'args' : [],                       'varg' : False },
 24 : { 'mnem' : 'FnFix',                 'args' : [],                       'varg' : False },
 25 : { 'mnem' : 'FnInt',                 'args' : [],                       'varg' : False },
 26 : { 'mnem' : 'FnSgn',                 'args' : [],                       'varg' : False },
 27 : { 'mnem' : 'FnLen',                 'args' : [],                       'varg' : False },
 28 : { 'mnem' : 'FnLenB',                'args' : [],                       'varg' : False },
 29 : { 'mnem' : 'Paren',                 'args' : [],                       'varg' : False },
 30 : { 'mnem' : 'Sharp',                 'args' : [],                       'varg' : False },
 31 : { 'mnem' : 'LdLHS',                 'args' : ['name'],                 'varg' : False },
 32 : { 'mnem' : 'Ld',                    'args' : ['name'],                 'varg' : False },
 33 : { 'mnem' : 'MemLd',                 'args' : ['name'],                 'varg' : False },
 34 : { 'mnem' : 'DictLd',                'args' : ['name'],                 'varg' : False },
 35 : { 'mnem' : 'IndexLd',               'args' : ['0x'],                   'varg' : False },
 36 : { 'mnem' : 'ArgsLd',                'args' : ['name',   '0x'],         'varg' : False },
 37 : { 'mnem' : 'ArgsMemLd',             'args' : ['name',   '0x'],         'varg' : False },
 38 : { 'mnem' : 'ArgsDictLd',            'args' : ['name',   '0x'],         'varg' : False },
 39 : { 'mnem' : 'St',                    'args' : ['name'],                 'varg' : False },
 40 : { 'mnem' : 'MemSt',                 'args' : ['name'],                 'varg' : False },
 41 : { 'mnem' : 'DictSt',                'args' : ['name'],                 'varg' : False },
 42 : { 'mnem' : 'IndexSt',               'args' : ['0x'],                   'varg' : False },
 43 : { 'mnem' : 'ArgsSt',                'args' : ['name',   '0x'],         'varg' : False },
 44 : { 'mnem' : 'ArgsMemSt',             'args' : ['name',   '0x'],         'varg' : False },
 45 : { 'mnem' : 'ArgsDictSt',            'args' : ['name',   '0x'],         'varg' : False },
 46 : { 'mnem' : 'Set',                   'args' : ['name'],                 'varg' : False },
 47 : { 'mnem' : 'Memset',                'args' : ['name'],                 'varg' : False },
 48 : { 'mnem' : 'Dictset',               'args' : ['name'],                 'varg' : False },
 49 : { 'mnem' : 'Indexset',              'args' : ['0x'],                   'varg' : False },
 50 : { 'mnem' : 'ArgsSet',               'args' : ['name',   '0x'],         'varg' : False },
 51 : { 'mnem' : 'ArgsMemSet',            'args' : ['name',   '0x'],         'varg' : False },
 52 : { 'mnem' : 'ArgsDictSet',           'args' : ['name',   '0x'],         'varg' : False },
 53 : { 'mnem' : 'MemLdWith',             'args' : ['name'],                 'varg' : False },
 54 : { 'mnem' : 'DictLdWith',            'args' : ['name'],                 'varg' : False },
 55 : { 'mnem' : 'ArgsMemLdWith',         'args' : ['name',   '0x'],         'varg' : False },
 56 : { 'mnem' : 'ArgsDictLdWith',        'args' : ['name',   '0x'],         'varg' : False },
 57 : { 'mnem' : 'MemStWith',             'args' : ['name'],                 'varg' : False },
 58 : { 'mnem' : 'DictStWith',            'args' : ['name'],                 'varg' : False },
 59 : { 'mnem' : 'ArgsMemStWith',         'args' : ['name',   '0x'],         'varg' : False },
 60 : { 'mnem' : 'ArgsDictStWith',        'args' : ['name',   '0x'],         'varg' : False },
 61 : { 'mnem' : 'MemSetWith',            'args' : ['name'],                 'varg' : False },
 62 : { 'mnem' : 'DictSetWith',           'args' : ['name'],                 'varg' : False },
 63 : { 'mnem' : 'ArgsMemSetWith',        'args' : ['name',   '0x'],         'varg' : False },
 64 : { 'mnem' : 'ArgsDictSetWith',       'args' : ['name',   '0x'],         'varg' : False },
 65 : { 'mnem' : 'ArgsCall',              'args' : ['name',   '0x'],         'varg' : False },
 66 : { 'mnem' : 'ArgsMemCall',           'args' : ['name',   '0x'],         'varg' : False },
 67 : { 'mnem' : 'ArgsMemCallWith',       'args' : ['name',   '0x'],         'varg' : False },
 68 : { 'mnem' : 'ArgsArray',             'args' : ['name',   '0x'],         'varg' : False },
 69 : { 'mnem' : 'Assert',                'args' : [],                       'varg' : False },
 70 : { 'mnem' : 'BoS',                   'args' : ['0x'],                   'varg' : False },
 71 : { 'mnem' : 'BoSImplicit',           'args' : [],                       'varg' : False },
 72 : { 'mnem' : 'BoL',                   'args' : [],                       'varg' : False },
 73 : { 'mnem' : 'LdAddressOf',           'args' : ['name'],                 'varg' : False },
 74 : { 'mnem' : 'MemAddressOf',          'args' : ['name'],                 'varg' : False },
 75 : { 'mnem' : 'Case',                  'args' : [],                       'varg' : False },
 76 : { 'mnem' : 'CaseTo',                'args' : [],                       'varg' : False },
 77 : { 'mnem' : 'CaseGt',                'args' : [],                       'varg' : False },
 78 : { 'mnem' : 'CaseLt',                'args' : [],                       'varg' : False },
 79 : { 'mnem' : 'CaseGe',                'args' : [],                       'varg' : False },
 80 : { 'mnem' : 'CaseLe',                'args' : [],                       'varg' : False },
 81 : { 'mnem' : 'CaseNe',                'args' : [],                       'varg' : False },
 82 : { 'mnem' : 'CaseEq',                'args' : [],                       'varg' : False },
 83 : { 'mnem' : 'CaseElse',              'args' : [],                       'varg' : False },
 84 : { 'mnem' : 'CaseDone',              'args' : [],                       'varg' : False },
 85 : { 'mnem' : 'Circle',                'args' : ['0x'],                   'varg' : False },
 86 : { 'mnem' : 'Close',                 'args' : ['0x'],                   'varg' : False },
 87 : { 'mnem' : 'CloseAll',              'args' : [],                       'varg' : False },
 88 : { 'mnem' : 'Coerce',                'args' : [],                       'varg' : False },
 89 : { 'mnem' : 'CoerceVar',             'args' : [],                       'varg' : False },
 90 : { 'mnem' : 'Context',               'args' : ['context_'],             'varg' : False },
 91 : { 'mnem' : 'Debug',                 'args' : [],                       'varg' : False },
 92 : { 'mnem' : 'DefType',               'args' : ['0x', '0x'],             'varg' : False },
 93 : { 'mnem' : 'Dim',                   'args' : [],                       'varg' : False },
 94 : { 'mnem' : 'DimImplicit',           'args' : [],                       'varg' : False },
 95 : { 'mnem' : 'Do',                    'args' : [],                       'varg' : False },
 96 : { 'mnem' : 'DoEvents',              'args' : [],                       'varg' : False },
 97 : { 'mnem' : 'DoUnitil',              'args' : [],                       'varg' : False },
 98 : { 'mnem' : 'DoWhile',               'args' : [],                       'varg' : False },
 99 : { 'mnem' : 'Else',                  'args' : [],                       'varg' : False },
100 : { 'mnem' : 'ElseBlock',             'args' : [],                       'varg' : False },
101 : { 'mnem' : 'ElseIfBlock',           'args' : [],                       'varg' : False },
102 : { 'mnem' : 'ElseIfTypeBlock',       'args' : ['imp_'],                 'varg' : False },
103 : { 'mnem' : 'End',                   'args' : [],                       'varg' : False },
104 : { 'mnem' : 'EndContext',            'args' : [],                       'varg' : False },
105 : { 'mnem' : 'EndFunc',               'args' : [],                       'varg' : False },
106 : { 'mnem' : 'EndIf',                 'args' : [],                       'varg' : False },
107 : { 'mnem' : 'EndIfBlock',            'args' : [],                       'varg' : False },
108 : { 'mnem' : 'EndImmediate',          'args' : [],                       'varg' : False },
109 : { 'mnem' : 'EndProp',               'args' : [],                       'varg' : False },
110 : { 'mnem' : 'EndSelect',             'args' : [],                       'varg' : False },
111 : { 'mnem' : 'EndSub',                'args' : [],                       'varg' : False },
112 : { 'mnem' : 'EndType',               'args' : [],                       'varg' : False },
113 : { 'mnem' : 'EndWith',               'args' : [],                       'varg' : False },
114 : { 'mnem' : 'Erase',                 'args' : ['0x'],                   'varg' : False },
115 : { 'mnem' : 'Error',                 'args' : [],                       'varg' : False },
116 : { 'mnem' : 'EventDecl',             'args' : ['func_'],                'varg' : False },
117 : { 'mnem' : 'RaiseEvent',            'args' : ['name', '0x'],           'varg' : False },
118 : { 'mnem' : 'ArgsMemRaiseEvent',     'args' : ['name', '0x'],           'varg' : False },
119 : { 'mnem' : 'ArgsMemRaiseEventWith', 'args' : ['name', '0x'],           'varg' : False },
120 : { 'mnem' : 'ExitDo',                'args' : [],                       'varg' : False },
121 : { 'mnem' : 'ExitFor',               'args' : [],                       'varg' : False },
122 : { 'mnem' : 'ExitFunc',              'args' : [],                       'varg' : False },
123 : { 'mnem' : 'ExitProp',              'args' : [],                       'varg' : False },
124 : { 'mnem' : 'ExitSub',               'args' : [],                       'varg' : False },
125 : { 'mnem' : 'FnCurDir',              'args' : [],                       'varg' : False },
126 : { 'mnem' : 'FnDir',                 'args' : [],                       'varg' : False },
127 : { 'mnem' : 'Empty0',                'args' : [],                       'varg' : False },
128 : { 'mnem' : 'Empty1',                'args' : [],                       'varg' : False },
129 : { 'mnem' : 'FnError',               'args' : [],                       'varg' : False },
130 : { 'mnem' : 'FnFormat',              'args' : [],                       'varg' : False },
131 : { 'mnem' : 'FnFreeFile',            'args' : [],                       'varg' : False },
132 : { 'mnem' : 'FnInStr',               'args' : [],                       'varg' : False },
133 : { 'mnem' : 'FnInStr3',              'args' : [],                       'varg' : False },
134 : { 'mnem' : 'FnInStr4',              'args' : [],                       'varg' : False },
135 : { 'mnem' : 'FnInStrB',              'args' : [],                       'varg' : False },
136 : { 'mnem' : 'FnInStrB3',             'args' : [],                       'varg' : False },
137 : { 'mnem' : 'FnInStrB4',             'args' : [],                       'varg' : False },
138 : { 'mnem' : 'FnLBound',              'args' : ['0x'],                   'varg' : False },
139 : { 'mnem' : 'FnMid',                 'args' : [],                       'varg' : False },
140 : { 'mnem' : 'FnMidB',                'args' : [],                       'varg' : False },
141 : { 'mnem' : 'FnStrComp',             'args' : [],                       'varg' : False },
142 : { 'mnem' : 'FnStrComp3',            'args' : [],                       'varg' : False },
143 : { 'mnem' : 'FnStringVar',           'args' : [],                       'varg' : False },
144 : { 'mnem' : 'FnStringStr',           'args' : [],                       'varg' : False },
145 : { 'mnem' : 'FnUBound',              'args' : ['0x'],                   'varg' : False },
146 : { 'mnem' : 'For',                   'args' : [],                       'varg' : False },
147 : { 'mnem' : 'ForEach',               'args' : [],                       'varg' : False },
148 : { 'mnem' : 'ForEachAs',             'args' : ['imp_'],                 'varg' : False },
149 : { 'mnem' : 'ForStep',               'args' : [],                       'varg' : False },
150 : { 'mnem' : 'FuncDefn',              'args' : ['func_'],                'varg' : False },
151 : { 'mnem' : 'FuncDefnSave',          'args' : ['func_'],                'varg' : False },
152 : { 'mnem' : 'GetRec',                'args' : [],                       'varg' : False },
153 : { 'mnem' : 'GoSub',                 'args' : ['name'],                 'varg' : False },
154 : { 'mnem' : 'GoTo',                  'args' : ['name'],                 'varg' : False },
155 : { 'mnem' : 'If',                    'args' : [],                       'varg' : False },
156 : { 'mnem' : 'IfBlock',               'args' : [],                       'varg' : False },
157 : { 'mnem' : 'TypeOf',                'args' : ['imp_'],                 'varg' : False },
158 : { 'mnem' : 'IfTypeBlock',           'args' : ['imp_'],                 'varg' : False },
159 : { 'mnem' : 'Implements',            'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
160 : { 'mnem' : 'Input',                 'args' : [],                       'varg' : False },
161 : { 'mnem' : 'InputDone',             'args' : [],                       'varg' : False },
162 : { 'mnem' : 'InputItem',             'args' : [],                       'varg' : False },
163 : { 'mnem' : 'Label',                 'args' : ['name'],                 'varg' : False },
164 : { 'mnem' : 'Let',                   'args' : [],                       'varg' : False },
165 : { 'mnem' : 'Line',                  'args' : ['0x'],                   'varg' : False },
166 : { 'mnem' : 'LineCont',              'args' : [],                       'varg' :  True },
167 : { 'mnem' : 'LineInput',             'args' : [],                       'varg' : False },
168 : { 'mnem' : 'LineNum',               'args' : ['name'],                 'varg' : False },
169 : { 'mnem' : 'LitCy',                 'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
170 : { 'mnem' : 'LitDate',               'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
171 : { 'mnem' : 'LitDefault',            'args' : [],                       'varg' : False },
172 : { 'mnem' : 'LitDI2',                'args' : ['0x'],                   'varg' : False },
173 : { 'mnem' : 'LitDI4',                'args' : ['0x', '0x'],             'varg' : False },
174 : { 'mnem' : 'LitDI8',                'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
175 : { 'mnem' : 'LitHI2',                'args' : ['0x'],                   'varg' : False },
176 : { 'mnem' : 'LitHI4',                'args' : ['0x', '0x'],             'varg' : False },
177 : { 'mnem' : 'LitHI8',                'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
178 : { 'mnem' : 'LitNothing',            'args' : [],                       'varg' : False },
179 : { 'mnem' : 'LitOI2',                'args' : ['0x'],                   'varg' : False },
180 : { 'mnem' : 'LitOI4',                'args' : ['0x', '0x'],             'varg' : False },
181 : { 'mnem' : 'LitOI8',                'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
182 : { 'mnem' : 'LitR4',                 'args' : ['0x', '0x'],             'varg' : False },
183 : { 'mnem' : 'LitR8',                 'args' : ['0x', '0x', '0x', '0x'], 'varg' : False },
184 : { 'mnem' : 'LitSmallI2',            'args' : [],                       'varg' : False },
185 : { 'mnem' : 'LitStr',                'args' : [],                       'varg' :  True },
186 : { 'mnem' : 'LitVarSpecial',         'args' : [],                       'varg' : False },
187 : { 'mnem' : 'Lock',                  'args' : [],                       'varg' : False },
188 : { 'mnem' : 'Loop',                  'args' : [],                       'varg' : False },
189 : { 'mnem' : 'LoopUntil',             'args' : [],                       'varg' : False },
190 : { 'mnem' : 'LoopWhile',             'args' : [],                       'varg' : False },
191 : { 'mnem' : 'LSet',                  'args' : [],                       'varg' : False },
192 : { 'mnem' : 'Me',                    'args' : [],                       'varg' : False },
193 : { 'mnem' : 'MeImplicit',            'args' : [],                       'varg' : False },
194 : { 'mnem' : 'MemRedim',              'args' : ['name', '0x', 'type_'],  'varg' : False },
195 : { 'mnem' : 'MemRedimWith',          'args' : ['name', '0x', 'type_'],  'varg' : False },
196 : { 'mnem' : 'MemRedimAs',            'args' : ['name', '0x', 'type_'],  'varg' : False },
197 : { 'mnem' : 'MemRedimAsWith',        'args' : ['name', '0x', 'type_'],  'varg' : False },
198 : { 'mnem' : 'Mid',                   'args' : [],                       'varg' : False },
199 : { 'mnem' : 'MidB',                  'args' : [],                       'varg' : False },
200 : { 'mnem' : 'Name',                  'args' : [],                       'varg' : False },
201 : { 'mnem' : 'New',                   'args' : ['imp_'],                 'varg' : False },
202 : { 'mnem' : 'Next',                  'args' : [],                       'varg' : False },
203 : { 'mnem' : 'NextVar',               'args' : [],                       'varg' : False },
204 : { 'mnem' : 'OnError',               'args' : ['name'],                 'varg' : False },
205 : { 'mnem' : 'OnGosub',               'args' : [],                       'varg' :  True },
206 : { 'mnem' : 'OnGoto',                'args' : [],                       'varg' :  True },
207 : { 'mnem' : 'Open',                  'args' : ['0x'],                   'varg' : False },
208 : { 'mnem' : 'Option',                'args' : [],                       'varg' : False },
209 : { 'mnem' : 'OptionBase',            'args' : [],                       'varg' : False },
210 : { 'mnem' : 'ParamByVal',            'args' : [],                       'varg' : False },
211 : { 'mnem' : 'ParamOmitted',          'args' : [],                       'varg' : False },
212 : { 'mnem' : 'ParamNamed',            'args' : ['name'],                 'varg' : False },
213 : { 'mnem' : 'PrintChan',             'args' : [],                       'varg' : False },
214 : { 'mnem' : 'PrintComma',            'args' : [],                       'varg' : False },
215 : { 'mnem' : 'PrintEoS',              'args' : [],                       'varg' : False },
216 : { 'mnem' : 'PrintItemComma',        'args' : [],                       'varg' : False },
217 : { 'mnem' : 'PrintItemNL',           'args' : [],                       'varg' : False },
218 : { 'mnem' : 'PrintItemSemi',         'args' : [],                       'varg' : False },
219 : { 'mnem' : 'PrintNL',               'args' : [],                       'varg' : False },
220 : { 'mnem' : 'PrintObj',              'args' : [],                       'varg' : False },
221 : { 'mnem' : 'PrintSemi',             'args' : [],                       'varg' : False },
222 : { 'mnem' : 'PrintSpc',              'args' : [],                       'varg' : False },
223 : { 'mnem' : 'PrintTab',              'args' : [],                       'varg' : False },
224 : { 'mnem' : 'PrintTabComma',         'args' : [],                       'varg' : False },
225 : { 'mnem' : 'PSet',                  'args' : ['0x'],                   'varg' : False },
226 : { 'mnem' : 'PutRec',                'args' : [],                       'varg' : False },
227 : { 'mnem' : 'QuoteRem',              'args' : ['0x'],                   'varg' :  True },
228 : { 'mnem' : 'Redim',                 'args' : ['name', '0x', 'type_'],  'varg' : False },
229 : { 'mnem' : 'RedimAs',               'args' : ['name', '0x', 'type_'],  'varg' : False },
230 : { 'mnem' : 'Reparse',               'args' : [],                       'varg' :  True },
231 : { 'mnem' : 'Rem',                   'args' : [],                       'varg' :  True },
232 : { 'mnem' : 'Resume',                'args' : ['name'],                 'varg' : False },
233 : { 'mnem' : 'Return',                'args' : [],                       'varg' : False },
234 : { 'mnem' : 'RSet',                  'args' : [],                       'varg' : False },
235 : { 'mnem' : 'Scale',                 'args' : ['0x'],                   'varg' : False },
236 : { 'mnem' : 'Seek',                  'args' : [],                       'varg' : False },
237 : { 'mnem' : 'SelectCase',            'args' : [],                       'varg' : False },
238 : { 'mnem' : 'SelectIs',              'args' : ['imp_'],                 'varg' : False },
239 : { 'mnem' : 'SelectType',            'args' : [],                       'varg' : False },
240 : { 'mnem' : 'SetStmt',               'args' : [],                       'varg' : False },
241 : { 'mnem' : 'Stack',                 'args' : ['0x', '0x'],             'varg' : False },
242 : { 'mnem' : 'Stop',                  'args' : [],                       'varg' : False },
243 : { 'mnem' : 'Type',                  'args' : ['rec_'],                 'varg' : False },
244 : { 'mnem' : 'Unlock',                'args' : [],                       'varg' : False },
245 : { 'mnem' : 'VarDefn',               'args' : ['var_'],                 'varg' : False },
246 : { 'mnem' : 'Wend',                  'args' : [],                       'varg' : False },
247 : { 'mnem' : 'While',                 'args' : [],                       'varg' : False },
248 : { 'mnem' : 'With',                  'args' : [],                       'varg' : False },
249 : { 'mnem' : 'WriteChan',             'args' : [],                       'varg' : False },
250 : { 'mnem' : 'ConstFuncExpr',         'args' : [],                       'varg' : False },
251 : { 'mnem' : 'LbConst',               'args' : ['name'],                 'varg' : False },
252 : { 'mnem' : 'LbIf',                  'args' : [],                       'varg' : False },
253 : { 'mnem' : 'LbElse',                'args' : [],                       'varg' : False },
254 : { 'mnem' : 'LbElseIf',              'args' : [],                       'varg' : False },
255 : { 'mnem' : 'LbEndIf',               'args' : [],                       'varg' : False },
256 : { 'mnem' : 'LbMark',                'args' : [],                       'varg' : False },
257 : { 'mnem' : 'EndForVariable',        'args' : [],                       'varg' : False },
258 : { 'mnem' : 'StartForVariable',      'args' : [],                       'varg' : False },
259 : { 'mnem' : 'NewRedim',              'args' : [],                       'varg' : False },
260 : { 'mnem' : 'StartWithExpr',         'args' : [],                       'varg' : False },
261 : { 'mnem' : 'SetOrSt',               'args' : ['name'],                 'varg' : False },
262 : { 'mnem' : 'EndEnum',               'args' : [],                       'varg' : False },
263 : { 'mnem' : 'Illegal',               'args' : [],                       'varg' : False }
}

def translateOpcode(opcode, vbaVer, is64bit):
    if   vbaVer == 3:
        if     0 <= opcode <=  67:
            return opcode
        elif  68 <= opcode <=  70:
            return opcode +  2
        elif  71 <= opcode <= 111:
            return opcode +  4
        elif 112 <= opcode <= 150:
            return opcode +  8
        elif 151 <= opcode <= 164:
            return opcode +  9
        elif 165 <= opcode <= 166:
            return opcode + 10
        elif 167 <= opcode <= 169:
            return opcode + 11
        elif 170 <= opcode <= 238:
            return opcode + 12
        else:	# opcode == 239
            return opcode + 24
    elif vbaVer == 5:
        if     0 <= opcode <=  68:
            return opcode
        elif  69 <= opcode <=  71:
            return opcode +  1
        elif  72 <= opcode <= 112:
            return opcode +  3
        elif 113 <= opcode <= 151:
            return opcode +  7
        elif 152 <= opcode <= 165:
            return opcode +  8
        elif 166 <= opcode <= 167:
            return opcode +  9
        elif 168 <= opcode <= 170:
            return opcode + 10
        else:	# 171 <= opcode <= 252
            return opcode + 11
    #elif vbaVer == 6:
    #elif vbaVer in [6, 7]:
    elif not is64bit:
        if     0 <= opcode <= 173:
            return opcode
        elif 174 <= opcode <= 175:
            return opcode +  1
        elif 176 <= opcode <= 178:
            return opcode +  2
        else:	# 179 <= opcode <= 260
            return opcode +  3
    else:
        return opcode

def getID(idCode, identifiers, vbaVer, is64bit):
    internalNames = [
	'<crash>', '0', 'Abs', 'Access', 'AddressOf', 'Alias', 'And', 'Any',
	'Append', 'Array', 'As', 'Assert', 'B', 'Base', 'BF', 'Binary',
	'Boolean', 'ByRef', 'Byte', 'ByVal', 'Call', 'Case', 'CBool', 'CByte',
	'CCur', 'CDate', 'CDec', 'CDbl', 'CDecl', 'ChDir', 'CInt', 'Circle',
	'CLng', 'Close', 'Compare', 'Const', 'CSng', 'CStr', 'CurDir', 'CurDir$',
	'CVar', 'CVDate', 'CVErr', 'Currency', 'Database', 'Date', 'Date$', 'Debug',
	'Decimal', 'Declare', 'DefBool', 'DefByte', 'DefCur', 'DefDate', 'DefDec', 'DefDbl',
	'DefInt', 'DefLng', 'DefObj', 'DefSng', 'DefStr', 'DefVar', 'Dim', 'Dir',
	'Dir$', 'Do', 'DoEvents', 'Double', 'Each', 'Else', 'ElseIf', 'Empty',
	'End', 'EndIf', 'Enum', 'Eqv', 'Erase', 'Error', 'Error$', 'Event',
	'WithEvents', 'Explicit', 'F', 'False', 'Fix', 'For', 'Format',
	'Format$', 'FreeFile', 'Friend', 'Function', 'Get', 'Global', 'Go', 'GoSub',
	'Goto', 'If', 'Imp', 'Implements', 'In', 'Input', 'Input$', 'InputB',
	'InputB', 'InStr', 'InputB$', 'Int', 'InStrB', 'Is', 'Integer', 'Left',
	'LBound', 'LenB', 'Len', 'Lib', 'Let', 'Line', 'Like', 'Load',
	'Local', 'Lock', 'Long', 'Loop', 'LSet', 'Me', 'Mid', 'Mid$',
	'MidB', 'MidB$', 'Mod', 'Module', 'Name', 'New', 'Next', 'Not',
	'Nothing', 'Null', 'Object', 'On', 'Open', 'Option', 'Optional', 'Or',
	'Output', 'ParamArray', 'Preserve', 'Print', 'Private', 'Property', 'PSet', 'Public',
	'Put', 'RaiseEvent', 'Random', 'Randomize', 'Read', 'ReDim', 'Rem', 'Resume',
	'Return', 'RGB', 'RSet', 'Scale', 'Seek', 'Select', 'Set', 'Sgn',
	'Shared', 'Single', 'Spc', 'Static', 'Step', 'Stop', 'StrComp', 'String',
	'String$', 'Sub', 'Tab', 'Text', 'Then', 'To', 'True', 'Type',
	'TypeOf', 'UBound', 'Unload', 'Unlock', 'Unknown', 'Until', 'Variant', 'WEnd',
	'While', 'Width', 'With', 'Write', 'Xor', '#Const', '#Else', '#ElseIf',
	'#End', '#If', 'Attribute', 'VB_Base', 'VB_Control', 'VB_Creatable', 'VB_Customizable', 'VB_Description',
	'VB_Exposed', 'VB_Ext_Key', 'VB_HelpID', 'VB_Invoke_Func', 'VB_Invoke_Property', 'VB_Invoke_PropertyPut', 'VB_Invoke_PropertyPutRef', 'VB_MemberFlags',
	'VB_Name', 'VB_PredecraredID', 'VB_ProcData', 'VB_TemplateDerived', 'VB_VarDescription', 'VB_VarHelpID', 'VB_VarMemberFlags', 'VB_VarProcData',
	'VB_UserMemID', 'VB_VarUserMemID', 'VB_GlobalNameSpace', ',', '.', '"', '_', '!',
	'#', '&', "'", '(', ')', '*', '+', '-',
	' /', ':', ';', '<', '<=', '<>', '=', '=<',
	'=>', '>', '><', '>=', '?', '\\', '^', ':='
    ]

    origCode = idCode
    idCode >>= 1
    try:
        if idCode >= 0x100:
            idCode -= 0x100
            if vbaVer >= 7:
                idCode -= 4
                if is64bit:
                    idCode -= 3
                if idCode > 0xBE:
                    idCode -= 1
            return identifiers[idCode]
        else:
            if vbaVer >= 7:
                if idCode >= 0xC3:
                    idCode -= 1
            return internalNames[idCode]
    except:
        return 'id_{:04X}'.format(origCode)

def getName(buffer, identifiers, offset, endian, vbaVer, is64bit):
    objectID = getWord(buffer, offset, endian)
    objectName = getID(objectID, identifiers, vbaVer, is64bit)
    return objectName

def disasmName(word, identifiers, mnemonic, opType, vbaVer, is64bit):
    varTypes = ['', '?', '%', '&', '!', '#', '@', '?', '$', '?', '?', '?', '?', '?']
    varName = getID(word, identifiers, vbaVer, is64bit)
    if opType < len(varTypes):
        strType = varTypes[opType]
    else:
        strType = ''
        if opType == 32:
            varName = '[' + varName + ']'
    if   mnemonic == 'OnError':
        strType = ''
        if   opType == 1:
            varName = '(Resume Next)'
        elif opType == 2:
            varName = '(GoTo 0)'
    elif mnemonic == 'Resume':
        strType = ''
        if   opType == 1:
            varName = '(Next)'
        elif opType != 0:
            varName = ''
    return varName + strType + ' '

def disasmImp(objectTable, identifiers, arg, word, mnemonic, endian, vbaVer, is64bit):
    if mnemonic != 'Open':
        if arg == 'imp_' and (len(objectTable) >= word + 8):
            impName = getName(objectTable, identifiers, word + 6, endian, vbaVer, is64bit)
        else:
            impName = '{}{:04X} '.format(arg, word)
    else:
        accessMode = ['Read', 'Write', 'Read Write']
        lockMode   = ['Read Write', 'Write', 'Read']
        mode = word & 0x00FF
        access = (word & 0x0F00) >>  8
        lock   = (word & 0xF000) >> 12
        impName = '(For '
        if   mode & 0x01:
            impName += 'Input'
        elif mode & 0x02:
            impName += 'Output'
        elif mode & 0x04:
            impName += 'Random'
        elif mode & 0x08:
            impName += 'Append'
        elif mode == 0x20:
            impName += 'Binary'
        if access and (access <= len(accessMode)):
            impName += ' Access ' + accessMode[access - 1]
        if lock:
            if lock & 0x04:
                impName += ' Shared'
            elif lock <= len(accessMode):
                impName += ' Lock ' + lockMode[lock - 1]
        impName += ')'
    return impName

def disasmRec(indirectTable, identifiers, dword, endian, vbaVer, is64bit):
    objectName = getName(indirectTable, identifiers, dword + 2, endian, vbaVer, is64bit)
    options = getWord(indirectTable, dword + 18, endian)
    if (options & 1) == 0:
        objectName = '(Private) ' + objectName
    return objectName

def getTypeName(typeID):
    dimTypes = ['', 'Null', 'Integer', 'Long', 'Single', 'Double', 'Currency', 'Date', 'String', 'Object', 'Error', 'Boolean', 'Variant', '', 'Decimal', '', '', 'Byte']
    typeFlags = typeID & 0xE0
    typeID &= ~0xE0
    if typeID < len(dimTypes):
        typeName = dimTypes[typeID]
    else:
        typeName = ''
    if typeFlags & 0x80:
        typeName += 'Ptr'
    return typeName

def disasmType(indirectTable, dword):
    dimTypes = ['', 'Null', 'Integer', 'Long', 'Single', 'Double', 'Currency', 'Date', 'String', 'Object', 'Error', 'Boolean', 'Variant', '', 'Decimal', '', '', 'Byte']
    typeID = ord(indirectTable[dword + 6])
    if typeID < len(dimTypes):
        typeName = dimTypes[typeID]
    else:
        typeName = 'type_{:08X}'.format(dword)
    return typeName

def disasmObject(indirectTable, objectTable, identifiers, offset, endian, vbaVer, is64bit):
    # TODO - Dim declarations in 64-bit Office documents
    if is64bit:
        return ''
    typeDesc = getDWord(indirectTable, offset, endian)
    flags = getWord(indirectTable, typeDesc, endian)
    if flags & 0x02:
        typeName = disasmType(indirectTable, typeDesc)
    else:
        word = getWord(indirectTable, typeDesc + 2, endian)
        if word == 0:
            typeName = ''
        else:
            offs = (word >> 2) * 10
            if offs + 4 > len(objectTable):
                return ''
            flags  = getWord(objectTable, offs, endian)
            hlName = getWord(objectTable, offs + 6, endian)
            # TODO - The following logic is flawed and doesn't always work. Disabling it for now
            #if flags & 0x02:
            #    theNames = []
            #    numNames = getWord(objectTable, hlName, endian)
            #    offs = hlName + 2
            #    for myName in range(numNames):
            #        theNames.append(getName(objectTable, identifiers, offs, endian, vbaVer, is64bit))
            #        offs += 2
            #    typeName = ' '.join(theNames)
            #else:
            #    typeName = getID(hlName, identifiers, vbaVer, is64bit)
            # Using the following line instead:
            typeName = getID(hlName, identifiers, vbaVer, is64bit)
    return typeName

def disasmVar(indirectTable, objectTable, identifiers, dword, endian, vbaVer, is64bit):
    bFlag1 = ord(indirectTable[dword])
    bFlag2 = ord(indirectTable[dword + 1])
    hasAs  = (bFlag1 & 0x20) != 0
    hasNew = (bFlag2 & 0x20) != 0
    varName = getName(indirectTable, identifiers, dword + 2, endian, vbaVer, is64bit)
    if hasNew or hasAs:
        varType = ''
        if hasNew:
            varType += 'New'
            if hasAs:
                varType += ' '
        if hasAs:
            if is64bit:
                offs = 16
            else:
                offs = 12
            word = getWord(indirectTable, dword + offs + 2, endian)
            if word == 0xFFFF:
                typeID = ord(indirectTable[dword + offs])
                typeName = getTypeName(typeID)
            else:
                typeName = disasmObject(indirectTable, objectTable, identifiers, dword + offs, endian, vbaVer, is64bit)
            if len(typeName) > 0:
                varType += 'As ' + typeName
        if len(varType) > 0:
            varName += ' (' + varType + ')'
    return varName

def disasmArg(indirectTable, identifiers, argOffset, endian, vbaVer, is64bit):
    flags = getWord(indirectTable, argOffset, endian)
    if is64bit:
        offs = 4
    else:
        offs = 0
    argName = getName(indirectTable, identifiers, argOffset + 2, endian, vbaVer, is64bit)
    argType = getDWord(indirectTable, argOffset + offs + 12, endian)
    argOpts = getWord(indirectTable, argOffset + offs + 24, endian)
    if argOpts & 0x0004:
        argName = 'ByVal ' + argName
    if argOpts & 0x0002:
        argName = 'ByRef ' + argName
    if argOpts & 0x0200:
        argName = 'Optional ' + argName
    # TODO - ParamArray arguments aren't disassebled properly
    #if (flags & 0x0040) == 0:
    #    argName = 'ParamArray ' + argName + '()'
    if flags  & 0x0020:
        argName += ' As '
        argTypeName = ''
        if argType & 0xFFFF0000:
            argTypeID = argType & 0x000000FF
            argTypeName = getTypeName(argTypeID)
        # TODO - Custom type arguments aren't disassembled properly
        #else:
        #    argTypeName = getName(indirectTable, identifiers, argType + 6, endian, vbaVer, is64bit)
        argName += argTypeName
    return argName

def disasmFunc(indirectTable, declarationTable, identifiers, dword, opType, endian, vbaVer, is64bit):
    funcDecl = '('
    flags = getWord(indirectTable, dword, endian)
    subName = getName(indirectTable, identifiers, dword + 2, endian, vbaVer, is64bit)
    if vbaVer > 5:
        offs2 = 4
    else:
        offs2 = 0
    if is64bit:
        offs2 += 16
    argOffset = getDWord(indirectTable, dword + offs2 + 36, endian)
    retType   = getDWord(indirectTable, dword + offs2 + 40, endian)
    declOffset = getWord(indirectTable, dword + offs2 + 44, endian)
    cOptions = ord(indirectTable[dword + offs2 + 54])
    #argCount = ord(indirectTable[dword + offs2 + 55])
    newFlags = ord(indirectTable[dword + offs2 + 57])
    hasDeclare = False
    # TODO - 'Private' and 'Declare' for 64-bit Office
    if vbaVer > 5:
        if ((newFlags & 0x0002) == 0) and not is64bit:
            funcDecl += 'Private '
        if newFlags & 0x0004:
            funcDecl += 'Friend '
    else:
        if (flags & 0x0008) == 0:
            funcDecl += 'Private '
    if opType & 0x04:
        funcDecl += 'Public '
    if flags & 0x0080:
        funcDecl += 'Static '
    if ((cOptions & 0x90) == 0) and (declOffset != 0xFFFF) and not is64bit:
        hasDeclare = True
        funcDecl += 'Declare '
    if vbaVer > 5:
        if newFlags & 0x20:
            funcDecl += 'PtrSafe '
    hasAs = (flags & 0x0020) != 0
    if flags & 0x1000:
        if opType in [2, 6]:
            funcDecl += 'Function '
        else:
            funcDecl += 'Sub '
    elif flags & 0x2000:
        funcDecl += 'Property Get '
    elif flags & 0x4000:
        funcDecl += 'Property Let '
    elif flags & 0x8000:
        funcDecl += 'Property Set '
    funcDecl += subName
    if hasDeclare:
        libName = getName(declarationTable, identifiers, declOffset + 2, endian, vbaVer, is64bit)
        funcDecl += ' Lib "' + libName + '" '
    argList = []
    while (argOffset != 0xFFFFFFFF) and (argOffset != 0) and (argOffset + 26 < len(indirectTable)):
        argName = disasmArg(indirectTable, identifiers, argOffset, endian, vbaVer, is64bit)
        argList.append(argName)
        argOffset = getDWord(indirectTable, argOffset + 20, endian)
    funcDecl += '(' + ', '.join(argList) + ')'
    if hasAs:
        funcDecl += ' As '
        typeName = ''
        if (retType & 0xFFFF0000) == 0xFFFF0000:
            typeID = retType & 0x000000FF
            typeName = getTypeName(typeID)
        else:
            typeName = getName(indirectTable, identifiers, retType + 6, endian, vbaVer, is64bit)
        funcDecl += typeName
    funcDecl += ')'
    return funcDecl

def disasmVarArg(moduleData, identifiers, offset, wLength, mnemonic, endian, vbaVer, is64bit):
    substring = moduleData[offset:offset + wLength]
    varArgName = '0x{:04X} '.format(wLength)
    if mnemonic in ['LitStr', 'QuoteRem', 'Rem', 'Reparse']:
        varArgName += '"' + decode(substring) + '"'
    elif mnemonic in ['OnGosub', 'OnGoto']:
        offset1 = offset
        vars = []
        for _ in itertools.repeat(None, int(wLength / 2)):
            offset1, word = getVar(moduleData, offset1, endian, False)
            vars.append(getID(word, identifiers, vbaVer, is64bit))
        varArgName += ', '.join(v for v in vars) + ' '
    else:
        hexdump = ' '.join('{:02X}'.format(ord(c)) for c in substring)
        varArgName += hexdump
    return varArgName

def myPrint(append, file=None, end="\n"):
    return append + end

def dumpLine(it, moduleData, lineStart, lineLength, endian, vbaVer, is64bit,
             identifiers, objectTable, indirectTable, declarationTable, verbose, line, output_file=sys.stdout):
    varTypesLong = ['Var', '?', 'Int', 'Lng', 'Sng', 'Dbl', 'Cur', 'Date', 'Str', 'Obj', 'Err', 'Bool', 'Var']
    specials = ['False', 'True', 'Null', 'Empty']
    options = ['Base 0', 'Base 1', 'Compare Text', 'Compare Binary', 'Explicit', 'Private Module']

    #if verbose and (lineLength > 0):
    #    print('{:04X}: '.format(lineStart), end='', file=output_file)
    #print('Line #{:d}:'.format(line), file=output_file)
    if lineLength <= 0:
        return
    #if verbose:
    #    print(hexdump(moduleData[lineStart:lineStart + lineLength]), file=output_file)

    offset = lineStart
    endOfLine = lineStart + lineLength
    disasmEntry = ''
    while offset < endOfLine:
        offset, opcode = getVar(moduleData, offset, endian, False)
        opType = (opcode & ~0x03FF) >> 10
        opcode &= 0x03FF
        translatedOpcode = translateOpcode(opcode, vbaVer, is64bit)
        if not translatedOpcode in opcodes:
            disasmEntry += myPrint('Unrecognized opcode 0x{:04X} at offset 0x{:08X}.'.format(opcode, offset), file=output_file)
            print(disasmEntry)
            return
        instruction = opcodes[translatedOpcode]
        mnemonic = instruction['mnem']
        disasmEntry += myPrint('\t', end='', file=output_file)
        if verbose:
            disasmEntry += myPrint('{:04X} '.format(opcode), end='', file=output_file)
        disasmEntry += myPrint('{} '.format(mnemonic), end='', file=output_file)
        if mnemonic in ['Coerce', 'CoerceVar', 'DefType']:
            if opType < len(varTypesLong):
                disasmEntry += myPrint('({}) '.format(varTypesLong[opType]), end='', file=output_file)
            elif opType == 17:
                disasmEntry += myPrint('(Byte) ', end='', file=output_file)
            else:
                disasmEntry += myPrint('({:d}) '.format(opType), end='', file=output_file)
        elif mnemonic in ['Dim', 'DimImplicit', 'Type']:
            dimType = []
            if   opType & 0x04:
                dimType.append('Global')
            elif opType & 0x08:
                dimType.append('Public')
            elif opType & 0x10:
                dimType.append('Private')
            elif opType & 0x20:
                dimType.append('Static')
            if (opType & 0x01) and (mnemonic != 'Type'):
                dimType.append('Const')
            if len(dimType):
                disasmEntry += myPrint('({}) '.format(' '.join(dimType)), end='', file=output_file)
        elif mnemonic == 'LitVarSpecial':
            disasmEntry += myPrint('({})'.format(specials[opType]), end='', file=output_file)
        elif mnemonic in ['ArgsCall', 'ArgsMemCall', 'ArgsMemCallWith']:
            if opType < 16:
                disasmEntry += myPrint('(Call) ', end='', file=output_file)
            else:
                opType -= 16
        elif mnemonic == 'Option':
            disasmEntry += myPrint(' ({})'.format(options[opType]), end='', file=output_file)
        elif mnemonic in ['Redim', 'RedimAs']:
            if opType & 16:
                disasmEntry += myPrint('(Preserve) ', end='', file=output_file)
        for arg in instruction['args']:
            if arg == 'name':
                offset, word = getVar(moduleData, offset, endian, False)
                theName = disasmName(word, identifiers, mnemonic, opType, vbaVer, is64bit)
                disasmEntry += myPrint('{}'.format(theName), end='', file=output_file)
            elif arg in ['0x', 'imp_']:
                offset, word = getVar(moduleData, offset, endian, False)
                theImp = disasmImp(objectTable, identifiers, arg, word, mnemonic, endian, vbaVer, is64bit)
                disasmEntry += myPrint('{}'.format(theImp), end='', file=output_file)
            elif arg in ['func_', 'var_', 'rec_', 'type_', 'context_']:
                offset, dword = getVar(moduleData, offset, endian, True)
                if   (arg == 'rec_') and (len(indirectTable) >= dword + 20):
                    theRec = disasmRec(indirectTable, identifiers, dword, endian, vbaVer, is64bit)
                    disasmEntry += myPrint('{}'.format(theRec), end='', file=output_file)
                elif (arg == 'type_') and (len(indirectTable) >= dword + 7):
                    theType = disasmType(indirectTable, dword)
                    disasmEntry += myPrint('(As {})'.format(theType), end='', file=output_file)
                elif (arg == 'var_') and (len(indirectTable) >= dword + 16):
                    if opType & 0x20:
                        disasmEntry += myPrint('(WithEvents) ', end='', file=output_file)
                    theVar = disasmVar(indirectTable, objectTable, identifiers, dword, endian, vbaVer, is64bit)
                    disasmEntry += myPrint('{}'.format(theVar), end='', file=output_file)
                    if opType & 0x10:
                        word = getWord(moduleData, offset, endian)
                        offset += 2
                        disasmEntry += myPrint(' 0x{:04X}'.format(word), end='', file=output_file)
                elif (arg == 'func_') and (len(indirectTable) >= dword + 61):
                    theFunc = disasmFunc(indirectTable, declarationTable, identifiers, dword, opType, endian, vbaVer, is64bit)
                    disasmEntry += myPrint('{}'.format(theFunc), end='', file=output_file)
                else:
                    disasmEntry += myPrint('{}{:08X} '.format(arg, dword), end='', file=output_file)
                if is64bit and (arg == 'context_'):
                    offset, dword = getVar(moduleData, offset, endian, True)
                    disasmEntry += myPrint('{:08X} '.format(dword), end='', file=output_file)
        if instruction['varg']:
            offset, wLength = getVar(moduleData, offset, endian, False)
            theVarArg = disasmVarArg(moduleData, identifiers, offset, wLength, mnemonic, endian, vbaVer, is64bit)
            disasmEntry += myPrint('{}'.format(theVarArg), end='', file=output_file)
            offset += wLength
            if wLength & 1:
                offset += 1
        disasmEntry += "\n"

    entry = DisasmEntry(line, lineStart, lineStart+lineLength, disasmEntry)
    it.add(Interval(lineStart, lineStart+lineLength, entry))
    #print("{}-{}: {}".format(lineStart, lineStart+lineLength, disasmEntry))


class DisasmEntry():
    def __init__(self, line, lineStart, lineEnd, text):
        self.lineNr = line
        self.begin = lineStart
        self.end = lineEnd
        self.text = text


def pcodeDump(moduleData, vbaProjectData, dirData, identifiers, is64bit, disasmOnly, verbose, output_file = sys.stdout):
    it = IntervalTree()

    if verbose and not disasmOnly:
        print(hexdump(moduleData), file=output_file)
    # Determine endinanness: PC (little-endian) or Mac (big-endian)
    if getWord(moduleData, 2, '<') > 0xFF:
        endian = '>'
    else:
        endian = '<'
    # TODO - Handle VBA3 modules
    vbaVer = 3
    try:
        version = getWord(vbaProjectData, 2, endian)
        if verbose:
            print('Internal Office version: 0x{:04X}.'.format(version), file=output_file)
        # Office 2010 is 0x0097; Office 2013 is 0x00A3;
        # Office 2016 PC 32-bit is 0x00B2, 64-bit is 0x00D7, Mac is 0x00D9
        if version >= 0x6B:
            if version >= 0x97:
                vbaVer = 7
            else:
                vbaVer = 6
            if is64bit:
                dwLength = getDWord(moduleData, 0x0043, endian)
                declarationTable = moduleData[0x0047:0x0047 + dwLength]
                dwLength = getDWord(moduleData, 0x0011, endian)
                tableStart = dwLength + 12
            else:
                dwLength = getDWord(moduleData, 0x003F, endian)
                declarationTable = moduleData[0x0043:0x0043 + dwLength]
                dwLength = getDWord(moduleData, 0x0011, endian)
                tableStart = dwLength + 10
            dwLength = getDWord(moduleData, tableStart, endian)
            tableStart += 4
            indirectTable = moduleData[tableStart:tableStart + dwLength]
            dwLength = getDWord(moduleData, 0x0005, endian)
            dwLength2 = dwLength + 0x8A
            dwLength = getDWord(moduleData, dwLength2, endian)
            dwLength2 += 4
            objectTable = moduleData[dwLength2:dwLength2 + dwLength]
            offset = 0x0019
        else:
            # VBA5
            vbaVer = 5
            offset = 11
            dwLength = getDWord(moduleData, offset, endian)
            offs = offset + 4
            declarationTable = moduleData[offs:offs + dwLength]
            offset = skipStructure(moduleData, offset, endian,  True,  1, False)
            offset += 64
            offset = skipStructure(moduleData, offset, endian, False, 16, False)
            offset = skipStructure(moduleData, offset, endian,  True,  1, False)
            offset += 6
            offset = skipStructure(moduleData, offset, endian,  True,  1, False)
            offs = offset + 8
            dwLength = getDWord(moduleData, offs, endian)
            tableStart = dwLength + 14
            offs = dwLength + 10
            dwLength = getDWord(moduleData, offs, endian)
            indirectTable = moduleData[tableStart:tableStart + dwLength]
            dwLength = getDWord(moduleData, offset, endian)
            offs = dwLength + 0x008A
            dwLength = getDWord(moduleData, offs, endian)
            offs += 4
            objectTable = moduleData[offs:offs + dwLength]
            offset += 77
        if verbose:
            if len(declarationTable):
                print('Declaration table:', file=output_file)
                print(hexdump(declarationTable), file=output_file)
            if len(indirectTable):
                print('Indirect table:', file=output_file)
                print(hexdump(indirectTable), file=output_file)
            if len(objectTable):
                print('Object table:', file=output_file)
                print(hexdump(objectTable), file=output_file)
        dwLength = getDWord(moduleData, offset, endian)
        offset = dwLength + 0x003C
        offset, magic = getVar(moduleData, offset, endian, False)
        if magic != 0xCAFE:
            return
        offset += 2
        offset, numLines = getVar(moduleData, offset, endian, False)
        pcodeStart = offset + numLines * 12 + 10
        for line in range(numLines):
            offset += 4
            offset, lineLength = getVar(moduleData, offset, endian, False)
            offset += 2
            offset, lineOffset = getVar(moduleData, offset, endian, True)
            dumpLine(it, moduleData, pcodeStart + lineOffset, lineLength, endian, vbaVer, is64bit, identifiers,
                     objectTable, indirectTable, declarationTable, verbose, line, output_file=output_file)
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)
    return it

def processProject(vbaParser, disasmOnly=False, verbose=False, output_file=sys.stdout):
    results = []
    try:
        vbaProjects = vbaParser.find_vba_projects()
        if vbaProjects is None:
            return
        if output_file.isatty() and WIN_UNICODE_CONSOLE:
            win_unicode_console.enable()
        for vbaRoot, _, dirPath in vbaProjects:
            print('=' * 79, file=output_file)
            if not disasmOnly:
                print('dir stream: {}'.format(dirPath), file=output_file)
            dirData, codeModules, is64bit = processDir(vbaParser, dirPath, disasmOnly, verbose, output_file=output_file)
            vbaProjectPath = vbaRoot + 'VBA/_VBA_PROJECT'
            vbaProjectData = process_VBA_PROJECT(vbaParser, vbaProjectPath, disasmOnly, verbose, output_file=output_file)
            identifiers = getTheIdentifiers(vbaProjectData)
            if not disasmOnly:
                print('Identifiers:', file=output_file)
                print('', file=output_file)
                i = 0
                for identifier in identifiers:
                    print('{:04X}: {}'.format(i, identifier), file=output_file)
                    i += 1
                print('', file=output_file)
                print('_VBA_PROJECT parsing done.', file=output_file)
                print('-' * 79, file=output_file)
            print('Module streams:', file=output_file)
            for module in codeModules:
                modulePath = vbaRoot + 'VBA/' + module
                # make sure it is unicode, because that is what vbaParser expects:
                if PYTHON2:
                    # modulePath is UTF8 bytes (see processDir)
                    modulePath_unicode = modulePath.decode('utf8', errors='replace')
                else:
                    # modulePath is already unicode
                    modulePath_unicode = modulePath
                moduleData = vbaParser.ole_file.openstream(modulePath_unicode).read()
                #print ('{} - {:d} bytes'.format(modulePath, len(moduleData)), file=output_file)
                result = pcodeDump(moduleData, vbaProjectData, dirData, identifiers, is64bit, disasmOnly, verbose, output_file=output_file)
                if len(result) > 0:
                    results.append(result)
        if output_file.isatty() and WIN_UNICODE_CONSOLE:
            win_unicode_console.disable()
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)

    return results

def processFile(fileName):
    output_file=sys.stdout
    result = None
    # TODO - Handle VBA3 documents
    print('Processing file: {}'.format(fileName), file=output_file)
    vbaParser = None
    try:
        vbaParser = VBA_Parser(fileName)
        if vbaParser.ole_file is None:
            for subFile in vbaParser.ole_subfiles:
                result = processProject(subFile, output_file=output_file)
        else:
            result = processProject(vbaParser, output_file=output_file)
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)
    if vbaParser:
        vbaParser.close()
    return sorted(result)

def main():
    parser = argparse.ArgumentParser(description='Dumps the p-code of VBA-containing documents.')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s version {}'.format(__VERSION__))
    parser.add_argument('-n', '--norecurse', action='store_true',
                        help="Don't recurse into directories")
    parser.add_argument('-d', '--disasmonly', dest='disasmOnly', action='store_true',
                        help='Only disassemble, no stream dumps')
    parser.add_argument('-b', '--verbose', action='store_true',
                        help='Dump the stream contents')
    parser.add_argument('-o', '--output', dest='outputfile', default=None,
                        help='Output file name')
    parser.add_argument('fileOrDir', nargs='+', help='File or dir')
    args = parser.parse_args()
    errorLevel = 0
    try:
        output_file = sys.stdout
        if args.outputfile is not None:
            output_file = open(args.outputfile, 'w')
        for name in args.fileOrDir:
            if os.path.isdir(name):
                for name, subdirList, fileList in os.walk(name):
                    for fname in fileList:
                        fullName = os.path.join(name, fname)
                        results = processFile(fullName)
                        mprint(results)
                    if args.norecurse:
                        while len(subdirList) > 0:
                            del(subdirList[0])
            elif os.path.isfile(name):
                results = processFile(name)
                mprint(results)
            else:
                print('{} does not exist.'.format(name), file=sys.stderr)
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)
        errorLevel = -1
    if args.outputfile is not None:
        output_file.close()
    sys.exit(errorLevel)

def mprint(results):
    print("Results:")
    for result in results:
        for ite in sorted(result):
            print("{} {} {} \n{}".format(ite.begin, ite.end, ite.data.lineNr, ite.data.text))

if __name__ == '__main__':
    main()