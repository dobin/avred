"""
Part of dotnetfile

Copyright (c) 2016, 2021-2022 - Bob Jung, Yaron Samuel, Dominik Reichel
"""

from __future__ import annotations

import binascii
import struct

from typing import Optional, Union, Dict, Tuple

REASONABLE_CHARACTER_BYTES = (b'0123456789'
                              b'abcdefghijklmnopqrstuvwxyz'
                              b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                              b'!"#$%&\'()*+,-./\\\\:;<=>?@[\\]^_`{|}~ ')

# http://stackoverflow.com/questions/1715772/best-way-to-decode-unknown-unicoding-encoding-in-python-2-5
# Needed for the UserStrings stream in .NET which malware famously abuses
UTF8_ENCODINGS = ['ascii', 'utf_8', 'big5', 'big5hkscs', 'cp037', 'cp424', 'cp437', 'cp500', 'cp737', 'cp775', 'cp850',
                  'cp852', 'cp855', 'cp856', 'cp857', 'cp860', 'cp861', 'cp862', 'cp863', 'cp864', 'cp865', 'cp866',
                  'cp869', 'cp874', 'cp875', 'cp932', 'cp949', 'cp950', 'cp1006', 'cp1026', 'cp1140', 'cp1250',
                  'cp1251', 'cp1252', 'cp1253', 'cp1254', 'cp1255', 'cp1256', 'cp1257', 'cp1258', 'euc_jp',
                  'euc_jis_2004', 'euc_jisx0213', 'euc_kr', 'gb2312', 'gbk', 'gb18030', 'hz', 'iso2022_jp',
                  'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr',
                  'latin_1', 'iso8859_2', 'iso8859_3', 'iso8859_4', 'iso8859_5', 'iso8859_6', 'iso8859_7',
                  'iso8859_8', 'iso8859_9', 'iso8859_10', 'iso8859_13', 'iso8859_14', 'iso8859_15', 'johab', 'koi8_r',
                  'koi8_u', 'mac_cyrillic', 'mac_greek', 'mac_iceland', 'mac_latin2', 'mac_roman', 'mac_turkish',
                  'ptcp154', 'shift_jis', 'shift_jis_2004', 'shift_jisx0213', 'utf_32', 'utf_32_be', 'utf_32_le',
                  'utf_16', 'utf_16_be', 'utf_16_le', 'utf_7', 'utf_8_sig']


def convert_to_unicode(byte_string: bytes) -> Optional[str]:
    # check for utf-16 first
    if all(b == 0 for b in byte_string[1:min(len(byte_string), 8):2]):
        try:
            return byte_string.decode('utf-16')
        except UnicodeDecodeError:
            pass

    for encoding in UTF8_ENCODINGS:
        try:
            unicode_string = str(byte_string, encoding)

            if encoding not in ['ascii', 'utf_8']:
                # small optimization in case we run into a bunch of a single language
                # this will make that encoding float towards the top, but we leave ascii and utf_8 at the top
                encoding_index = UTF8_ENCODINGS.index(encoding)
                UTF8_ENCODINGS.pop(encoding_index)
                UTF8_ENCODINGS.insert(2, encoding)

            return unicode_string

        except UnicodeDecodeError:
            pass

    return None


def get_reasonable_display_string_for_bytes(string_bytes: bytes) -> str:
    """
    Wrapper for when we encounter string in memory and need to just display it somehow.
    """
    display_string = convert_to_unicode(string_bytes)

    if display_string is None:
        display_string = f'(hex){binascii.hexlify(string_bytes)}'

    return display_string


def read_null_terminated_byte_string(byte_buffer, limit: int = 128):
    """
    This attempts to read a string of any arbitrary bytes until it encounters a terminating null char.
    """
    null_terminated_string = bytearray()
    search_buffer = byte_buffer[:limit]

    for b in search_buffer:
        if b == 0:
            return null_terminated_string

        null_terminated_string.append(b)

    return None


def read_reasonable_string(byte_buffer, limit: int = 128):
    """
    This attempts to read a null terminated ascii string from the supplied buffer. This is useful parsing strings from
    PE headers that should be well formed.
    """
    null_terminated_string = bytes()
    search_buffer = byte_buffer[:limit]

    for b in search_buffer:

        if b == 0:
            return null_terminated_string.decode('utf-8')

        if b not in REASONABLE_CHARACTER_BYTES:
            return None

        null_terminated_string += bytes(chr(b), 'utf-8')


def bytes_to_ascii(byte_str: Union[str, bytes]) -> Union[str, bytes]:
    """
    Helper function to convert the supplied byte string to a python string.
    """
    ascii_str = ''
    for b in byte_str:
        # if 32 <= b and b < 176:
        if b in REASONABLE_CHARACTER_BYTES:
            ascii_str += chr(b)
        else:
            ascii_str += '.'
    return ascii_str


def bytes_to_annotated_hex_string(byte_buffer: Union[str, bytes]) -> Union[str, bytes]:
    """
    Supplies the string buffer used for json dumps, etc... when we have weird strings.
    """
    hex_string = ''.join([f'{ord(x):02x}' for x in byte_buffer])
    ascii_string = bytes_to_ascii(byte_buffer)
    annotated_hex_string = f'0x{len(byte_buffer):x} bytes: (HEX){hex_string} - (ASCII){ascii_string}\n'
    return annotated_hex_string


def make_string_readable(field_string: Union[str, bytes]) -> Union[str, bytes]:
    """
    Helper for when we want to print various structure field values in .json and we don't want crazy byte values
    sneaking in.
    """
    # trim off any strings that are all nulls
    trimmed_field_string = field_string.replace('\x00', '').replace('\\u0000', '').replace('\\u0000', '')

    try:
        ascii_field_string = trimmed_field_string.encode('ascii')

    except (UnicodeDecodeError, UnicodeEncodeError):
        ascii_field_string = bytes_to_annotated_hex_string(trimmed_field_string)

    return ascii_field_string


def read_7bit_encoded_uint32(byte_input: bytes) -> Tuple[int, int]:
    """
    Get the dynamically encoded length from a UInt32 value for the subsequent data bytes.
    """
    result = 0
    shift = 0

    for i in range(0, 5):
        current = byte_input[i]
        result |= (current & 0x7F) << shift

        if (current & 0x80) == 0:
            return i + 1, result
        shift += 7

    return 0, 0


def read_7bit_encoded_int32(byte_input: bytes) -> Tuple[int, int]:
    """
    Get the dynamically encoded length from a Int32 value for the subsequent data bytes.
    """
    result = 0
    shift = 0

    for i in range(0, 5):
        current = byte_input[i]
        result |= (current & 0x7F) << shift

        if not (shift > 28) and (current & 0x80) == 0:
            return i + 1, result
        shift += 7

    return 0, 0


class FileLocation(object):
    """
    A class that defines a location in the file. If t's defining a result string from a search for strings it can hold
    the ascii/unicode string that was found.
    """
    def __init__(self, address: int = None, string_representation: Union[str, bytes, Dict] = None, size: int = None) -> None:

        self.address: int = address

        # we always want to have a length of at least one byte right? this gets existential
        self.size: int = 1
        if size is not None:
            self.size = size

        # lazy evaluated
        self.__string_representation_arg = string_representation
        self.__string_representation = None

    @property
    def string_representation(self) -> str:
        if self.__string_representation is None:
            given_argument = self.__string_representation_arg
            if isinstance(given_argument, bytes):
                try:
                    self.__string_representation: str = given_argument.decode('utf-8')
                except UnicodeDecodeError:
                    self.__string_representation = str(given_argument)
            elif isinstance(given_argument, str):
                self.__string_representation = given_argument
            else:
                self.__string_representation = ''

        return self.__string_representation

    @string_representation.setter
    def string_representation(self, value):
        self.__string_representation = value

    def __str__(self) -> str:
        if self.string_representation is not None:
            return f'{self.string_representation} (0x{self.address:x})'
        else:
            return f'(0x{self.address:x})'


class BinaryStructure(object):
    """
    Helper class that defines a binary structure with one or more fields. This is helpful for parsing C struct like
    blobs in memory. It is expected to have one or more BinaryStructureField objects defined within it.

    See the PE header examples at the bottom of windows_memory.py to see how this can be conveniently used to turn
    memory blobs into nicely accessible python objects.
    """
    def __init__(self, addr: int, display_name: Optional[str], byte_buffer: bytes):
        self.buffer = byte_buffer
        self.current_field_offset = 0
        self.structure_fields = []
        self.display_name = display_name
        self.address = addr
        self.size = 0

        try:
            self.string_representation: str = byte_buffer.decode('utf-8')
        except UnicodeDecodeError:
            self.string_representation = str(byte_buffer)

    def create_field_value(self, display_name: str, length: int, format_str: str) -> BinaryStructureField:
        """
        Helper to add a field value to the struct. This will create a new BinaryStructureField object.
        """
        if self.buffer is None:
            value_bytes = str.encode('\x00' * length)
        else:
            value_bytes = self.buffer[self.current_field_offset:self.current_field_offset + length]

        if self.address is not None:
            addr = self.address + self.current_field_offset
        else:
            addr = None

        structure_field = BinaryStructureField(addr, display_name, format_str, value_bytes, self.current_field_offset)
        self.current_field_offset += length
        self.size += length
        self.structure_fields.append(structure_field)

        return structure_field

    def set_byte_buffer_size(self, byte_buffer_size: int) -> None:
        """
        Removes excess bytes from byte_buffer.
        """
        temp_buffer = self.buffer[:byte_buffer_size]
        self.buffer = temp_buffer

    def trim_byte_buffer(self) -> None:
        """
        This is useful for trimming down the size of a structure byte buffer after it is done parsing. This is sometimes
        useful for when we dont know how big something is until after we parse it, i.e. .NET table rows.
        """
        byte_buffer_size = self.size
        self.set_byte_buffer_size(byte_buffer_size)


class BinaryStructureField(FileLocation):
    """
    Fields for the BinaryStructure class. It inherits from the FileLocation class which makes it convenient to pass
    around with any function that can deal with those.
    """

    def __init__(self, addr: Optional[int], display_name: str, format_str: str, value_bytes: bytes, offset: int) -> None:
        super(BinaryStructureField, self).__init__(addr)

        self.format_str = format_str
        self.offset = offset

        self.display_name = display_name
        self.address = addr

        # we lazily evaluate small fields, we immediately evaluate larger fields
        self.__value = None
        self.__value_bytes = value_bytes

        # lazy evaluated
        self.__field_text = None

    @property
    def value(self):
        if self.__value is None:
            self.__value = struct.unpack(self.format_str, self.__value_bytes)[0]

        return self.__value

    @property
    def field_text(self) -> str:
        if self.__field_text is None:
            if isinstance(self.value, str):
                self.__field_text = {self.value}
            elif isinstance(self.value, bytes):
                self.__field_text = self.value.decode(errors='ignore').rstrip('\x00')
            else:
                self.__field_text = f'0x{self.value:x}'

        return self.__field_text
