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


class IlMethod():
    def __init__(self):
        self.name = None
        self.addr = None
        self.codeSize = None
        self.headerSize = None
        self.className = None
        self.instructions = {}

    def setName(self, name, className=''):
        self.name = name
        self.instructions[0] = "Function: {}".format(name)
        self.className = className

    def getName(self):
        return self.className + '::' + self.name

    def setAddr(self, addr):
        self.addr = addr

    def getAddr(self):
        return self.addr

    def setCodeSize(self, size):
        self.codeSize = size

    def setHeaderSize(self, size):
        self.headerSize = size
        self.instructions[1] = "Header (size {})".format(size)

    def getSize(self):
        return self.codeSize + self.headerSize

    def addInstruction(self, nrInt, instructionLine):
        self.instructions[nrInt] = instructionLine

    def __str__(self):
        s = ''
        s += "Func {}::{} at {} with size {}\n".format(
            self.className, self.name, self.addr, self.getSize())
        #for instruction in self.instructions:
        #    s += "  {}\n".format(instruction)
        return s

    def __lt__(self, other):
        if self.addr < other.addr:
            return True
        return False


class DncilParser():
    def __init__(self, path):
        self.methods = []
        self.methodsIt = IntervalTree()

        pe: dnPE = dnfile.dnPE(path)

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
            ilMethod = IlMethod()
            ilMethod.setName(row.Name)
            ilMethod.setAddr(methodOffset)

            headerSize = 1
            codeSize = body.code_size

            logging.debug(f"\nMethod: {row.Name}")
            logging.debug("  RVA: _{:X}_  Offset: {:X}".format(row.Rva, methodOffset))
            logging.debug("   HeaderSize: {} codeSize: {}".format(headerSize, codeSize))

            ilMethod.setHeaderSize(headerSize)
            ilMethod.setCodeSize(codeSize)

            for insn in body.instructions:
                offset = pe.get_rva_from_offset(insn.offset) - row.Rva

                il = "{:04X}".format(offset)
                il += "    "
                il + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                il += f"{str(insn.opcode) : <15}"
                il += format_operand(pe, insn.operand)

                logging.debug(il)

                ilMethod.addInstruction(offset, il)
            
            self.methods.append(ilMethod)
                
        # convert
        for method in self.methods:
            if method.addr is None or method.codeSize is None or method.headerSize is None:
                #logging.error("Error in parsing: " + str(method))
                pass
            else:
                methodIt = Interval(
                    method.addr, 
                    method.addr+method.getSize(), 
                    method)
                self.methodsIt.add(methodIt)


    def query(self, begin, end) -> List[IlMethod]:
        res = self.methodsIt.overlap(begin, end)
        if len(res) == 0:
            return None

        res = [r[2] for r in res]
        return res
