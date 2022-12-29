import itertools

from constants import *
from utils import *

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
