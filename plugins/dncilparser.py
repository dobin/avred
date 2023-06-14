from typing import TYPE_CHECKING, Any, Union, Optional
from dnfile import dnPE
from dnfile.mdtable import MethodDefRow
import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase
import struct
from intervaltree import Interval, IntervalTree
from typing import List
import logging
import struct
from bitstring import Bits, BitArray, BitStream, pack


# key token indexes to dotnet meta tables
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}

class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnPE, row: MethodDefRow):
        """ """
        self.pe: dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        """ """
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        """ """
        return self.offset

    def seek(self, offset: int) -> int:
        """ """
        self.offset = offset
        return self.offset

def read_dotnet_user_string(pe: dnfile.dnPE, token: StringToken) -> Union[str, InvalidToken]:
    """read user string from #US stream"""
    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get_us(token.rid)
    except UnicodeDecodeError as e:
        return InvalidToken(token.value)

    if user_string is None:
        return InvalidToken(token.value)

    return user_string.value


def resolve_token(pe: dnPE, token: Token) -> Any:
    """ """
    if isinstance(token, StringToken):
        return read_dotnet_user_string(pe, token)

    table_name: str = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
    if not table_name:
        # table_index is not valid
        return InvalidToken(token.value)

    table: Any = getattr(pe.net.mdtables, table_name, None)
    if table is None:
        # table index is valid but table is not present
        return InvalidToken(token.value)

    try:
        return table.rows[token.rid - 1]
    except IndexError:
        # table index is valid but row index is not valid
        return InvalidToken(token.value)

def read_method_body(pe: dnPE, row: MethodDefRow) -> CilMethodBody:
    """ """
    return CilMethodBody(DnfileMethodBodyReader(pe, row))

def format_operand(pe: dnPE, operand: Any) -> str:
    """ """
    if isinstance(operand, Token):
        operand = resolve_token(pe, operand)

    if isinstance(operand, str):
        return f'"{operand}"'
    elif isinstance(operand, int):
        return hex(operand)
    elif isinstance(operand, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
    elif isinstance(operand, dnfile.mdtable.MemberRefRow):
        if isinstance(operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
            return f"{str(operand.Class.row.TypeNamespace)}.{operand.Class.row.TypeName}::{operand.Name}"
    elif isinstance(operand, dnfile.mdtable.TypeRefRow):
        return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
    elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{operand.Name}"
    elif operand is None:
        return ""

    return str(operand)


class IlInstruction():
    def __init__(self, fileOffset, methodOffset, rva, text):
        self.fileOffset = fileOffset
        self.methodOffset = methodOffset
        self.rva = rva
        self.text = text

    def __str__(self):
        s = "FileOffset: {}  methodOffset: {}  rva: {}  text: {}".format(
            self.fileOffset,
            self.methodOffset,
            self.rva,
            self.text
        )
        return s


class IlMethodHeaderFat():
    def __init__(self, headerBytes: bytes, methodOffset: int):
        self.headerBytes = headerBytes
        self.offset = methodOffset

        self.hdrOther = None
        self.size = None
        self.flags = None
        self.type = None
        self.maxStack = None
        self.codeSize = None
        self.localVarSigTok = None

        self.parse(headerBytes)


    def parse(self, headerBytes: bytes):
        # swap first two bytes
        #c = struct.unpack('<H', a[0:2])[0]
        c = headerBytes[1:2] + headerBytes[0:1]
        cc = BitStream(c)
        self.size = cc.read('uint4')
        self.flags = cc.read('uint10')
        self.type = cc.read('uint2')
        self.maxStack = struct.unpack('<H', headerBytes[2:4])[0]
        self.codeSize = struct.unpack('<I', headerBytes[4:8])[0]
        self.localVarSigTok = struct.unpack('<I', headerBytes[8:12])[0]


    def toIlMethod(self):
        ret = []

        # first two bytes
        ilText = '  '
        ilText += f"{' '.join('{:02x}'.format(b) for b in self.headerBytes[:2]) : <20}"
        ilText += f"MethodHeader: Size:{self.size}  Flags:{self.flags}  Type:{self.type}"
        ilInstruction = IlInstruction(self.offset, 0, 0, ilText)
        ret.append(ilInstruction)

        # maxStack
        ilText = '  '
        ilText += f"{' '.join('{:02x}'.format(b) for b in self.headerBytes[2:4]) : <20}"
        ilText += f"MethodHeader: maxStack: {self.maxStack}"
        ilInstruction = IlInstruction(self.offset+2, 2, 0, ilText)
        ret.append(ilInstruction)
        
        # codesize
        ilText = '  '
        ilText += f"{' '.join('{:02x}'.format(b) for b in self.headerBytes[4:8]) : <20}"
        ilText += f"MethodHeader: codeSize: {self.codeSize}"
        ilInstruction = IlInstruction(self.offset+4, 4, 0, ilText)
        ret.append(ilInstruction)

        # localvar
        ilText = '  '
        ilText += f"{' '.join('{:02x}'.format(b) for b in self.headerBytes[8:12]) : <20}"
        ilText += f"MethodHeader: localVarSigTok: {self.localVarSigTok}"
        ilInstruction = IlInstruction(self.offset+8, 8, 0, ilText)
        ret.append(ilInstruction)

        return ret


    def __str__(self):
        s = ''
        s += "Fat Header: size:{} flags:{} maxStack:{} codeSize:{} localVarSigTok:{}".format(
            self.size, self.flags, self.maxStack, self.codeSize, self.localVarSigTok
        )
        return s


class IlMethod():
    def __init__(self, offset, rva, codeSize, name):
        self.name = name
        self.offset = offset
        self.rva = rva
        self.codeSize = codeSize
        self.headerSize = None
        self.className = ''
        self.instructions = []
        self.ilMethodHeaderFat = None  # None if MethodHeader is not fat

    def setName(self, name, className=''):
        self.name = name
        self.className = className

    def getName(self):
        return self.className + '::' + self.name

    def setOffset(self, offset):
        self.offset = offset

    def getOffset(self):
        return self.offset
        
    def getRva(self):
        return self.rva
    
    def setRva(self, rva):
        self.rva = rva

    def setCodeSize(self, size):
        self.codeSize = size

    def getCodeSize(self):
        return self.codeSize

    def setHeaderSize(self, size):
        self.headerSize = size

    def getHeaderSize(self):
        return self.headerSize

    def getSize(self):
        return self.codeSize + self.headerSize

    def addInstruction(self, ilInstruction: IlInstruction):
        self.instructions.append(ilInstruction)

    def setIlMethodHeaderFat(self, ilMethodHeaderFat: IlMethodHeaderFat):
        self.ilMethodHeaderFat = ilMethodHeaderFat

    def __str__(self):
        s = ''
        s += "Func {}::{} at offset {} with size {}\n".format(
            self.className, self.name, self.offset, self.getSize())
        #for instruction in self.instructions:
        #    s += "  {}\n".format(instruction)
        return s

    def __lt__(self, other):
        if self.offset < other.offset:
            return True
        return False


class DncilParser():
    def __init__(self, path):
        self.methods: List[IlMethod] = []
        self.methodsIt = IntervalTree()

        pe: dnPE = dnfile.dnPE(path)

        # dncil works on methods
        row: MethodDefRow
        for row in pe.net.mdtables.MethodDef:
            if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
                # skip methods that do not have a method body
                continue
            try:
                body: CilMethodBody = read_method_body(pe, row)
            except MethodBodyFormatError as e:
                logging.error(e)
                continue
            if not body.instructions:
                continue

            # method file offset
            methodOffset = pe.get_offset_from_rva(row.Rva)
            ilMethod = IlMethod(methodOffset, row.Rva, body.code_size, row.Name)

            logging.debug(f"\nMethod: {row.Name}")
            logging.debug("  RVA: _{:X}_  Offset: {:X}".format(row.Rva, methodOffset))
            logging.debug("   codeSize: {}".format(ilMethod.getCodeSize))

            # method header parsing
            headerIlMethodFat = self.parseDotNetHeader(body.raw_bytes[:12], methodOffset)
            ilMethod.setIlMethodHeaderFat(headerIlMethodFat)
            if ilMethod.ilMethodHeaderFat is None:
                ilMethod.setHeaderSize(1)
            if ilMethod.ilMethodHeaderFat is not None:
                ilMethod.setHeaderSize(12)
                headerIlMethods = ilMethod.ilMethodHeaderFat.toIlMethod()
                for m in headerIlMethods:
                    ilMethod.addInstruction(m)

            for insn in body.instructions:
                offset = pe.get_rva_from_offset(insn.offset) - row.Rva
                rva = row.Rva + insn.offset

                ilText = '  '
                ilText += f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                ilText += f"{str(insn.opcode) : <15}"
                ilText += format_operand(pe, insn.operand)
                ilInstruction = IlInstruction(insn.offset, offset, rva, ilText)

                ilMethod.addInstruction(ilInstruction)
            
            self.methods.append(ilMethod)
                
        # convert method list to method intervals
        for method in self.methods:
            if method.getOffset() is None or method.getCodeSize is None or method.getHeaderSize is None:
                #logging.error("Error in parsing: " + str(method))
                pass
            else:
                methodIt = Interval(
                    method.getOffset(), 
                    method.getOffset()+method.getSize(), 
                    method)
                self.methodsIt.add(methodIt)


    def getMethods(self, begin, end) -> List[IlMethod]:
        res = self.methodsIt.overlap(begin, end)
        if len(res) == 0:
            return None
        res = [r[2] for r in res]
        return res


    def parseDotNetHeader(self, headerBytes: bytes, methodOffset:int):
        b = BitStream(headerBytes)
        hdrOther = b.read('uint6')
        hdrType = b.read('uint2')

        if hdrType == 0x2:
            #print("Tiny header, size: {} bytes".format(hdrOther))
            self.ilMethodHeaderFat = None
            return None

        if hdrType == 0x3:
            return IlMethodHeaderFat(headerBytes, methodOffset)
                

