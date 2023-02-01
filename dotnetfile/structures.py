"""
Part of dotnetfile

Copyright (c) 2016, 2021-2022 - Bob Jung, Yaron Samuel, Dominik Reichel
"""

from enum import IntEnum

from .util import BinaryStructure, read_reasonable_string
from .constants import METADATA_TABLE_FLAGS


class DOTNET_CLR_HEADER(BinaryStructure):
    def __init__(self, addr: int = None, byte_buffer: bytes = None):
        BinaryStructure.__init__(self, addr, 'CLR Header', byte_buffer)

        self.HeaderSize = self.create_field_value('HeaderSize', 4, 'I')
        self.MajorRuntimeVersion = self.create_field_value('MajorRuntimeVersion', 2, 'H')
        self.MinorRuntimeVersion = self.create_field_value('MinorRuntimeVersion', 2, 'H')
        self.MetaDataDirectoryAddress = self.create_field_value('MetaDataDirectoryAddress', 4, 'I')
        self.MetaDataDirectorySize = self.create_field_value('MetaDataDirectorySize', 4, 'I')
        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.EntryPointToken = self.create_field_value('EntryPointToken', 4, 'I')
        self.ResourcesDirectoryAddress = self.create_field_value('ResourcesDirectoryAddress', 4, 'I')
        self.ResourcesDirectorySize = self.create_field_value('ResourcesDirectorySize', 4, 'I')
        self.StrongNameSignatureAddress = self.create_field_value('StrongNameSignatureAddress', 4, 'I')
        self.StrongNameSignatureSize = self.create_field_value('StrongNameSignatureSize', 4, 'I')
        self.CodeManagerTableAddress = self.create_field_value('CodeManagerTableAddress', 4, 'I')
        self.CodeManagerTableSize = self.create_field_value('CodeManagerTableSize', 4, 'I')
        self.VTableFixupsAddress = self.create_field_value('VTableFixupsAddress', 4, 'I')
        self.VTableFixupsSize = self.create_field_value('VTableFixupsSize', 4, 'I')
        self.ExportAddressTableJumpsAddress = self.create_field_value('ExportAddressTableJumpsAddress', 4, 'I')
        self.ExportAddressTableJumpsSize = self.create_field_value('ExportAddressTableJumpsSize', 4, 'I')
        self.ManagedNativeHeaderAddress = self.create_field_value('ManagedNativeHeaderAddress', 4, 'I')
        self.ManagedNativeHeaderSize = self.create_field_value('ManagedNativeHeaderSize', 4, 'I')


class DOTNET_METADATA_HEADER(BinaryStructure):
    def __init__(self, addr: int = None, byte_buffer: bytes = None):
        BinaryStructure.__init__(self, addr, 'Metadata Header', byte_buffer)

        self.Signature = self.create_field_value('Signature', 4, 'I')
        self.MajorVersion = self.create_field_value('MajorVersion', 2, 'H')
        self.MinorVersion = self.create_field_value('MinorVersion', 2, 'H')
        self.Reserved1 = self.create_field_value('Reserved1', 4, 'I')
        self.VersionStringLength = self.create_field_value('VersionStringLength', 4, 'I')

        if self.VersionStringLength.value > 0x100:
            raise Exception(f'Invalid .NET metadata Version String '
                            f'length: 0x{self.VersionStringLength.value:x}', addr)

        version_string_struct_string = f'{self.VersionStringLength.value:d}s'
        self.VersionString = self.create_field_value('VersionString', self.VersionStringLength.value,
                                                     version_string_struct_string)

        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.NumberOfStreams = self.create_field_value('NumberOfStreams', 2, 'H')


class DOTNET_STREAM_HEADER(BinaryStructure):
    def __init__(self, addr: int = None, byte_buffer: bytes = None):
        BinaryStructure.__init__(self, addr, None, byte_buffer)

        self.Offset = self.create_field_value('Offset', 4, 'I')
        self.Size = self.create_field_value('Size', 4, 'I')

        name = read_reasonable_string(byte_buffer[8:])

        name_len = len(name)
        name_len_padding = 4 - (name_len % 4)
        name_len += name_len_padding

        name_struct_string = f'{name_len:d}s'

        self.Name = self.create_field_value('Name', name_len, name_struct_string)

        self.string_representation = f'{name} Stream Header'


class StreamOffsetSizeFlags(IntEnum):
    String = 0x01
    GUID = 0x02
    Blob = 0x04
    ExtraData = 0x40  # Not documented in ECMA-335


class DOTNET_METADATA_STREAM_HEADER(BinaryStructure):
    def __init__(self, addr: int = None, byte_buffer: bytes = None):
        BinaryStructure.__init__(self, addr, 'Metadata Stream Header', byte_buffer)

        self.Reserved1 = self.create_field_value('Reserved1', 4, 'I')
        self.MajorVersion = self.create_field_value('MajorVersion', 1, 'B')
        self.MinorVersion = self.create_field_value('MinorVersion', 1, 'B')
        self.OffsetSizeFlags = self.create_field_value('OffsetSizeFlags', 1, 'B')

        self.string_offset_size = 2
        self.string_offset_struct_string = 'H'
        if (self.OffsetSizeFlags.value & StreamOffsetSizeFlags.String) == StreamOffsetSizeFlags.String:
            self.string_offset_size = 4
            self.string_offset_struct_string = 'I'

        self.guid_offset_size = 2
        self.guid_offset_struct_string = 'H'
        if (self.OffsetSizeFlags.value & StreamOffsetSizeFlags.GUID) == StreamOffsetSizeFlags.GUID:
            self.guid_offset_size = 4
            self.guid_offset_struct_string = 'I'

        self.blob_offset_size = 2
        self.blob_offset_struct_string = 'H'
        if (self.OffsetSizeFlags.value & StreamOffsetSizeFlags.Blob) == StreamOffsetSizeFlags.Blob:
            self.blob_offset_size = 4
            self.blob_offset_struct_string = 'I'

        # Check if metadata table has extra bytes at the end added by .NET protectors like ConfuserEx to confuse parsers
        self.table_has_extra_data = False
        if (self.OffsetSizeFlags.value & StreamOffsetSizeFlags.ExtraData) == StreamOffsetSizeFlags.ExtraData:
            self.table_has_extra_data = True

        self.Reserved2 = self.create_field_value('Reserved2', 1, 'B')

        self.TablesFlags = self.create_field_value('TablesFlags', 8, 'Q')

        self.metadata_table_flags = {}

        for metadata_table_flag in list(METADATA_TABLE_FLAGS.keys()):
            if self.TablesFlags.value & metadata_table_flag:
                self.metadata_table_flags[metadata_table_flag] = METADATA_TABLE_FLAGS[metadata_table_flag]

        self.SortedTablesFlags = self.create_field_value('SortedTablesFlags', 8, 'Q')

        self.table_names = []
        self.table_size_lookup = {}

        self.table_size_locations = []
        for metadata_table_flag in sorted(self.metadata_table_flags.keys()):
            table_name = self.metadata_table_flags[metadata_table_flag]
            table_size_location = self.create_field_value(f'TableSize_{table_name}', 4, 'I')

            table_size = table_size_location.value

            self.table_size_locations.append(table_size_location)

            self.table_names.append(table_name)
            self.table_size_lookup[table_name] = table_size
