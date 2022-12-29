import sys
from intervaltree import Interval, IntervalTree
from lowlevel import *


class DisasmEntry():
    def __init__(self, line, lineStart, lineEnd, text):
        self.lineNr = line
        self.begin = lineStart
        self.end = lineEnd
        self.text = text


def myPrint(append, file=None, end="\n"):
    return append + end


def dumpLine(moduleData, lineStart, lineLength, endian, vbaVer, is64bit,
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

    #print("{}-{}: {}".format(lineStart, lineStart+lineLength, disasmEntry))
    entry = DisasmEntry(line, lineStart, lineStart+lineLength, disasmEntry)
    return entry


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
            disasmEntry = dumpLine(moduleData, pcodeStart + lineOffset, lineLength, endian, vbaVer, is64bit, identifiers,
                     objectTable, indirectTable, declarationTable, verbose, line, output_file=output_file)

            it.add(Interval(disasmEntry.begin, disasmEntry.end, disasmEntry))


    except Exception as e:
        print('Error: {}.'.format(e), file=sys.stderr)

    return it
