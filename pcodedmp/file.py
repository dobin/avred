from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
import sys
import itertools

from oletools.olevba import VBA_Parser, decompress_stream
from oletools.common import codepages

from utils import *
from constants import *
from disasm import *

try:
    import win_unicode_console
    WIN_UNICODE_CONSOLE = True
except ImportError:
    WIN_UNICODE_CONSOLE = False

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
                result = pcodeDump(moduleData, vbaProjectData, modulePath_unicode, identifiers, is64bit, disasmOnly, verbose, output_file=output_file)
                if len(result) > 0:
                    results.append(result)
        if output_file.isatty() and WIN_UNICODE_CONSOLE:
            win_unicode_console.disable()
    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)

    return results

def processDir(vbaParser, dirPath, disasmOnly, verbose, output_file=sys.stdout):
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