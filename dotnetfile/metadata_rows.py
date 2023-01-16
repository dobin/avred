"""
Part of dotnetfile

Copyright (c) 2016, 2021-2022 - Bob Jung, Yaron Samuel, Dominik Reichel
"""

import binascii

from math import log, floor
from typing import Dict, Optional, Any

from .logger import get_logger
from .util import BinaryStructure, FileLocation
from .constants import TABLE_ROW_VARIABLE_LENGTH_FIELDS


def get_blob_location_for_offset(pe, offset: int):
    """
    This sort of just cheats and returns a DWORD for now since we haven't done the extra legwork in figuring out the
    lengths of every single variable
    """
    # I'm just going to go with 4 bytes for now...
    blob_location_size = 4

    blob_stream = pe.dotnet_stream_lookup.get(b'#Blob', None)
    if blob_stream is not None:
        blob_stream_rva = blob_stream.address - pe.address
        blob_location_rva = blob_stream_rva + offset
        blob_location_addr = blob_stream.address + offset
        blob_location_bytes = pe.executable_bytes[blob_location_rva:blob_location_rva + blob_location_size]

        if offset < blob_stream.size:
            blob_location = FileLocation(blob_location_addr, blob_location_bytes, blob_location_size)
            blob_location.string_representation = binascii.hexlify(blob_location_bytes)
            return blob_location

    return None


def get_guid_location_for_offset(pe, offset: int):
    """
    """
    # I'm just going to go with 4 bytes for now...
    guid_location_size = 4
    guid_stream = pe.dotnet_stream_lookup.get(b'#GUID', None)
    if guid_stream is not None:
        guid_location_rva = guid_stream.address + offset
        guid_location_bytes = pe.get_data(guid_location_rva, guid_location_size)

        if offset < guid_stream.size:
            guid_location = FileLocation(guid_location_rva, guid_location_bytes, guid_location_size)
            guid_location.string_representation = binascii.hexlify(guid_location_bytes)
            return guid_location

    return None


def get_table_row_location(pe, table_name: str, table_index: int):
    """
    given an index and a table name, this returns the metadata table row object
    """
    if table_name in pe.metadata_tables_lookup:

        metadata_table = pe.metadata_tables_lookup[table_name]

        if table_index < len(metadata_table.table_rows):
            metadata_row = metadata_table.table_rows[table_index]
            # print 'got table row: %s 0x%x' % (table_name, table_index)
            return metadata_row

    return None


class METADATA_TABLE_ROW(BinaryStructure):
    """
    This class represents a single metadata table row. It's a memory location that has fields.
    """

    def __init__(self, pe, addr: int = None, string_representation: str = None, byte_buffer: bytes = None):
        BinaryStructure.__init__(self, addr, string_representation, byte_buffer)
        self.pe = pe
        self.logger = get_logger('extended_pe_logger')

        # Lookup of field name to the index in these streams
        self.string_stream_references = {}
        self.guid_stream_references = {}
        self.blob_stream_references = {}

        # Lookup of field name to the table name to the index in that table
        self.table_references = {}

    def create_string_stream_field_value(self, field_name: str):
        """
        Used to define a reference to a string at an offset in the strings stream
        """
        field_value = self.create_field_value(field_name, self.pe.dotnet_metadata_stream_header.string_offset_size,
                                              self.pe.dotnet_metadata_stream_header.string_offset_struct_string)

        self.string_stream_references[field_name] = field_value.value

        return field_value

    def create_guid_stream_field_value(self, field_name: str):
        """
        Used to define a reference to a string at an offset in the guid stream
        """
        field_value = self.create_field_value(field_name, self.pe.dotnet_metadata_stream_header.guid_offset_size,
                                              self.pe.dotnet_metadata_stream_header.guid_offset_struct_string)

        self.guid_stream_references[field_name] = field_value.value

        return field_value

    def create_blob_stream_field_value(self, field_name: str):
        """
        Used to define a reference to a string at an offset in the blob stream
        """
        field_value = self.create_field_value(field_name, self.pe.dotnet_metadata_stream_header.blob_offset_size,
                                              self.pe.dotnet_metadata_stream_header.blob_offset_struct_string)

        self.blob_stream_references[field_name] = field_value.value

        return field_value

    def create_table_reference(self, field_name: str, table_name: str):
        """
        Creates a reference to a row in another table
        """
        if table_name not in self.pe.dotnet_metadata_stream_header.table_size_lookup:
            self.logger.debug(f'Table: {table_name} not defined in .NET header')
            return None

        field_size = 2
        struct_string = 'H'
        num_rows = self.pe.dotnet_metadata_stream_header.table_size_lookup[table_name]
        if num_rows >= 65536:
            field_size = 4
            struct_string = 'I'

        field_value = self.create_field_value(field_name, field_size, struct_string)

        self.table_references[field_name] = (table_name, field_value.value)

        return field_value

    def create_variable_length_table_reference(self, field_name: str, type_name_param: Optional[str] = None):
        """
        Go read ntcore's .NET tutorial and pay attention to "coded indexes"
        """
        if type_name_param:
            type_name = type_name_param
        else:
            type_name = field_name

        field_size_info_tuple = self.pe.dotnet_field_size_info[type_name]
        field_size = field_size_info_tuple[0]
        struct_string = field_size_info_tuple[1]

        table_names = TABLE_ROW_VARIABLE_LENGTH_FIELDS[type_name]
        num_bits = int(floor(log(len(table_names) - 1, 2))) + 1

        # print 'num bits: 0x%x' % num_bits
        bit_mask = pow(2, num_bits) - 1

        # print 'bitmask: 0x%x' % bit_mask
        field_value = self.create_field_value(field_name, field_size, struct_string)

        table_name_index = field_value.value & bit_mask
        table_index = field_value.value >> num_bits

        # print 'field_name: %s, type_name: %s, table_name_index: 0x%x table_index: 0x%x field_value: 0x%x
        # bit_mask: 0x%x' % (field_name, type_name, table_name_index, table_index, field_value.value, bit_mask)
        # print table_names

        if table_name_index < len(table_names):
            table_name = table_names[table_name_index]
        else:
            table_name = table_names[-1]

        self.table_references[field_name] = (table_name, table_index)

        return field_value


class MODULE_TABLE_ROW(METADATA_TABLE_ROW):
    """
    00 - Module Table
        It's officially a one-row table, but there are ITW files with more than one row. It is representing the current
        assembly. It is documented in ECMA-335.

    Columns:
        Generation (2-byte value, reserved, shall be zero)
        Name (index into String heap)
        Mvid (index into Guid heap; simply a Guid used to distinguish between two versions of the same module)
        EncId (index into Guid heap, reserved, shall be zero)
        EncBaseId (index into Guid heap, reserved, shall be zero)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Module', byte_buffer)

        self.Generation = self.create_field_value('Generation', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')
        self.Mvid = self.create_guid_stream_field_value('Mvid')
        self.EncId = self.create_guid_stream_field_value('EncId')
        self.EncBaseId = self.create_guid_stream_field_value('EncBaseId')


class TYPE_REF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    01 - TypeRef Table
        Each row represents an imported class, its namespace and the assembly which contains it. It is documented in
        ECMA-335.

    Columns:
        ResolutionScope (index into Module, ModuleRef, AssemblyRef or TypeRef tables, or null; more precisely, a
            ResolutionScope coded index)
        TypeName (index into String heap)
        TypeNamespace (index into String heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'TypeRef', byte_buffer)

        self.ResolutionScope = self.create_variable_length_table_reference('ResolutionScope', 'ResolutionScope')
        self.TypeName = self.create_string_stream_field_value('TypeName')
        self.TypeNamespace = self.create_string_stream_field_value('TypeNamespace')


class TYPE_DEF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    02 - TypeDef Table
        Each row represents a class in the current assembly. It is documented in ECMA-335.

    Columns:
        Flags (a 4-byte bitmask of type TypeAttributes)
        TypeName (index into String heap)
        TypeNamespace (index into String heap)
        Extends (index into TypeDef, TypeRef or TypeSpec table; more precisely, a TypeDefOrRef coded index)
        FieldList (index into Field table; it marks the first of a continguous run of Fields owned by this Type).
            The run continues to the smaller of:
                the last row of the Field table
                the next run of Fields, found by inspecting the FieldList of the next row in this TypeDef table
        MethodList (index into MethodDef table; it marks the first of a continguous run of Methods owned by this Type).
            The run continues to the smaller of:
                the last row of the MethodDef table
                the next run of Methods, found by inspecting the MethodList of the next row in this TypeDef table
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'TypeDef', byte_buffer)

        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.TypeName = self.create_string_stream_field_value('TypeName')
        self.TypeNamespace = self.create_string_stream_field_value('TypeNamespace')
        self.Extends = self.create_variable_length_table_reference('Extends', 'TypeDefOrRef')
        self.FieldList = self.create_table_reference('FieldList', 'Field')
        self.MethodList = self.create_table_reference('MethodList', 'MethodDef')


class FIELD_PTR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    03 - FieldPtr Table
        Each row represents an index into the Field table. It is not documented in ECMA-335, but the definition can be
        found in metadata.c of the .NET runtime source code.

    Columns:
        Field (index into Field table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Field', byte_buffer)

        self.Field = self.create_table_reference('Field', 'Field')


class FIELD_TABLE_ROW(METADATA_TABLE_ROW):
    """
    04 - Field Table
        Each row represents a field in a TypeDef class. The fields of one class are not stored casually: after the
        fields of one class end, the fields of the next class begin. It is documented in ECMA-335.

    Columns:
        Flags (a 2-byte bitmask of type FieldAttributes)
        Name (index into String heap)
        Signature (index into Blob heap)
    """

    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Field', byte_buffer)

        # Could parse out all the flags...
        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')
        self.Signature = self.create_blob_stream_field_value('Signature')


class METHOD_PTR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    05 - MethodPtr Table
        Each row represents an index into the MethodDef table. It is not documented in ECMA-335, but the definition can
        be found in metadata.c of the .NET runtime source code.

    Columns:
        Method (index into MethodDef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Method', byte_buffer)

        self.Method = self.create_table_reference('Method', 'MethodDef')


class METHOD_DEF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    06 - MethodDef Table
        Each row represents a method in a specific class. The methods sequence follows the same logic of the fields one.
        It is documented in ECMA-335.

    Columns:
        RVA (a 4-byte constant)
        ImplFlags (a 2-byte bitmask of type MethodImplAttributes)
        Flags (a 2-byte bitmask of type MethodAttribute)
        Name (index into String heap)
        Signature (index into Blob heap)
        ParamList (index into Param table). It marks the first of a contiguous run of Parameters owned by this method.
            The run continues to the smaller of:
                the last row of the Param table
                the next run of Parameters, found by inspecting the ParamList of the next row in the MethodDef table
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'MethodDef', byte_buffer)

        self.RVA = self.create_field_value('RVA', 4, 'I')
        self.ImplFlags = self.create_field_value('ImplFlags', 2, 'H')
        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')
        self.Signature = self.create_blob_stream_field_value('Signature')
        self.ParamList = self.create_table_reference('ParamList', 'Param')


class PARAM_PTR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    07 - ParamPtr Table
        Each row represents an index into the Param table. It is not documented in ECMA-335, but the definition can
        be found in metadata.c of the .NET runtime source code.

    Columns:
        Param (index into Param table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Param', byte_buffer)

        self.Param = self.create_table_reference('Param', 'Param')


class PARAM_TABLE_ROW(METADATA_TABLE_ROW):
    """
    08 - Param Table
        Each row represents a method's param. It is documented in ECMA-335.

    Columns:
        Flags (a 2-byte bitmask of type ParamAttributes)
        Sequence (a 2-byte constant)
        Name (index into String heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Param', byte_buffer)

        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.Sequence = self.create_field_value('Sequence', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')


class INTERFACE_IMPL_TABLE_ROW(METADATA_TABLE_ROW):
    """
    09 - InterfaceImpl Table
        Each row tells the framework a class that implements a specific interface. It is documented in ECMA-335.

    Columns:
        Class (index into the TypeDef table)
        Interface (index into the TypeDef, TypeRef or TypeSpec table; more precisely, a TypeDefOrRef coded index)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'InterfaceImpl', byte_buffer)

        self.Class = self.create_table_reference('Class', 'TypeDef')
        self.Interface = self.create_variable_length_table_reference('Interface', 'TypeDefOrRef')


class MEMBER_REF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    10 - MemberRef Table
        Also known as MethodRef table. Each row represents an imported method. It is documented in ECMA-335.

    Columns:
        Class (index into the TypeRef, ModuleRef, MethodDef, TypeSpec or TypeDef tables; more precisely, a
            MemberRefParent coded index)
        Name (index into String heap)
        Signature (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'MemberRef', byte_buffer)

        self.Class = self.create_variable_length_table_reference('Class', 'MemberRefParent')
        self.Name = self.create_string_stream_field_value('Name')
        self.Signature = self.create_blob_stream_field_value('Signature')


class CONSTANT_TABLE_ROW(METADATA_TABLE_ROW):
    """
    11 - Constant Table
        Each row represents a constant value for a Param, Field or Property. It is documented in ECMA-335.

    Columns:
        Type (a 1-byte constant, followed by a 1-byte padding zero).
        Parent (index into the Param or Field or Property table; more precisely, a HasConstant coded index)
        Value (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Constant', byte_buffer)

        self.Type = self.create_field_value('Type', 1, 'B')
        self.Padding = self.create_field_value('Padding', 1, 'B')
        self.Parent = self.create_variable_length_table_reference('Parent', 'HasConstant')
        self.Value = self.create_blob_stream_field_value('Value')


class CUSTOM_ATTRIBUTE_TABLE_ROW(METADATA_TABLE_ROW):
    """
    12 - CustomAttribute Table
        The best description is given by the SDK:
            "The CustomAttribute table stores data that can be used to instantiate a Custom Attribute (more precisely,
            an object of the specified Custom Attribute class) at runtime. The column called Type is slightly
            misleading - it actually indexes a constructor method - the owner of that constructor method is the Type of
            the Custom Attribute."
        It is documented in ECMA-335.

    Columns:
        Parent (index into any metadata table, except the CustomAttribute table itself; more precisely, a
            HasCustomAttribute coded index)
        Type (index into the MethodDef or MethodRef table; more precisely, a CustomAttributeType coded index)
        Value (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'CustomAttribute', byte_buffer)

        self.Parent = self.create_variable_length_table_reference('Parent', 'HasCustomAttribute')
        self.Type = self.create_variable_length_table_reference('Type', 'CustomAttributeType')
        self.Value = self.create_blob_stream_field_value('Value')


class FIELD_MARSHAL_TABLE_ROW(METADATA_TABLE_ROW):
    """
    13 - FieldMarshal Table
        Each row tells the way a Param or Field should be treated when called from/to unmanaged code.  It is documented
        in ECMA-335.

    Columns:
        Parent (index into Field or Param table; more precisely, a HasFieldMarshal coded index)
        NativeType (index into the Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'FieldMarshal', byte_buffer)

        self.Parent = self.create_variable_length_table_reference('Parent', 'HasFieldMarshal')
        self.NativeType = self.create_blob_stream_field_value('NativeType')


class DECL_SECURITY_TABLE_ROW(METADATA_TABLE_ROW):
    """
    14 - DeclSecurity Table
        Security attributes attached to a class, method or assembly. It is documented in ECMA-335.

    Columns:
        Action (2-byte value)
        Parent (index into the TypeDef, MethodDef or Assembly table; more precisely, a HasDeclSecurity coded index)
        PermissionSet (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'DeclSecurity', byte_buffer)

        self.Action = self.create_field_value('Action', 2, 'H')
        self.Parent = self.create_variable_length_table_reference('Parent', 'HasDeclSecurity')
        self.PermissionSet = self.create_blob_stream_field_value('PermissionSet')


class CLASS_LAYOUT_TABLE_ROW(METADATA_TABLE_ROW):
    """
    15 - ClassLayout Table
        Remember "#pragma pack(n)" for VC++? Well, this is kind of the same thing for .NET. It's useful when handing
        something from managed to unmanaged code. It is documented in ECMA-335.

    Columns:
        PackingSize (a 2-byte constant)
        ClassSize (a 4-byte constant)
        Parent (index into TypeDef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'ClassLayout', byte_buffer)

        self.PackingSize = self.create_field_value('PackingSize', 2, 'H')
        self.ClassSize = self.create_field_value('ClassSize', 4, 'I')
        self.Parent = self.create_table_reference('Parent', 'TypeDef')


class FIELD_LAYOUT_TABLE_ROW(METADATA_TABLE_ROW):
    """
    16 - FieldLayout Table
        Related with the ClassLayout. It is documented in ECMA-335.

    Columns:
        Offset (a 4-byte constant)
        Field (index into the Field table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'FieldLayout', byte_buffer)

        self.Offset = self.create_field_value('Offset', 4, 'I')
        self.Field = self.create_table_reference('Field', 'Field')


class STAND_ALONE_SIG_TABLE_ROW(METADATA_TABLE_ROW):
    """
    17 - StandAloneSig Table
        Each row represents a signature that isn't referenced by any other table. It is documented in ECMA-335.

    Columns:
        Signature (index into the Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'StandAloneSig', byte_buffer)

        self.Signature = self.create_blob_stream_field_value('Signature')


class EVENT_MAP_TABLE_ROW(METADATA_TABLE_ROW):
    """
    18 - EventMap Table
        List of events for a specific class. It is documented in ECMA-335.

    Columns:
        Parent (index into the TypeDef table)
        EventList (index into Event table). It marks the first of a contiguous run of Events owned by this Type. The run
            continues to the smaller of:
                the last row of the Event table
                the next run of Events, found by inspecting the EventList of the next row in the EventMap table
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'EventMap', byte_buffer)

        self.Parent = self.create_table_reference('Parent', 'TypeDef')
        self.EventList = self.create_table_reference('EventList', 'Event')


class EVENT_PTR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    19 - EventPtr Table
        Each row represents an index into the Event table. It is not documented in ECMA-335, but the definition can
        be found in metadata.c of the .NET runtime source code.

    Columns:
        Event (index into Event table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Event', byte_buffer)

        self.Param = self.create_table_reference('Event', 'Event')


class EVENT_TABLE_ROW(METADATA_TABLE_ROW):
    """
    20 - Event Table
        Each row represents an event. It is documented in ECMA-335.

    Columns:
        EventFlags (a 2-byte bitmask of type EventAttribute)
        Name (index into String heap)
        EventType (index into TypeDef, TypeRef or TypeSpec tables; more precisely, a TypeDefOrRef coded index)
            [this corresponds to the Type of the Event; it is not the Type that owns this event]
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Event', byte_buffer)

        self.EventFlags = self.create_field_value('EventFlags', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')
        self.EventType = self.create_variable_length_table_reference('EventType', 'TypeDefOrRef')


class PROPERTY_MAP_TABLE_ROW(METADATA_TABLE_ROW):
    """
    21 - PropertyMap Table
        List of Properties owned by a specific class. It is documented in ECMA-335.

    Columns:
        Parent (index into the TypeDef table)
        PropertyList (index into Property table). It marks the first of a contiguous run of Properties owned by Parent.
            The run continues to the smaller of:
                the last row of the Property table
                the next run of Properties, found by inspecting the PropertyList of the next row in this PropertyMap table
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'PropertyMap', byte_buffer)

        self.Parent = self.create_table_reference('Parent', 'TypeDef')
        self.PropertyList = self.create_table_reference('PropertyList', 'Property')


class PROPERTY_PTR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    07 - PropertyPtr Table
        Each row represents an index into the Property table. It is not documented in ECMA-335, but the definition can
        be found in metadata.c of the .NET runtime source code.

    Columns:
        Property (index into Property table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Property', byte_buffer)

        self.Property = self.create_table_reference('Property', 'Property')


class PROPERTY_TABLE_ROW(METADATA_TABLE_ROW):
    """
    23 - Property Table
        Each row represents a property. It is documented in ECMA-335.

    Columns:
        Flags (a 2-byte bitmask of type PropertyAttributes)
        Name (index into String heap)
        Type (index into Blob heap) [the name of this column is misleading. It does not index a TypeDef or TypeRef
            table - instead it indexes the signature in the Blob heap of the Property)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Property', byte_buffer)

        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.Name = self.create_string_stream_field_value('Name')
        self.Type = self.create_blob_stream_field_value('Type')


class METHOD_SEMANTICS_TABLE_ROW(METADATA_TABLE_ROW):
    """
    24 - MethodSemantics Table
        Links Events and Properties to specific methods. For example one Event can be associated to more methods. A
        property uses this table to associate get/set methods. It is documented in ECMA-335.

    Columns:
        Semantics (a 2-byte bitmask of type MethodSemanticsAttributes)
        Method (index into the MethodDef table)
        Association (index into the Event or Property table; more precisely, a HasSemantics coded index)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'MethodSemantics', byte_buffer)

        self.Semantics = self.create_field_value('Semantics', 2, 'H')
        self.Method = self.create_table_reference('Method', 'MethodDef')
        self.Association = self.create_variable_length_table_reference('Association', 'HasSemantics')


class METHOD_IMPL_TABLE_ROW(METADATA_TABLE_ROW):
    """
    25 - MethodImpl Table
        Specifies details of how a method is implemented. It is documented in ECMA-335.

    Columns:
        Class (index into TypeDef table)
        MethodBody (index into MethodDef or MemberRef table; more precisely, a MethodDefOrRef coded index)
        MethodDeclaration (index into MethodDef or MemberRef table; more precisely, a MethodDefOrRef coded index)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'MethodImpl', byte_buffer)

        self.Class = self.create_table_reference('Class', 'TypeDef')
        self.MethodBody = self.create_variable_length_table_reference('MethodBody', 'MethodDefOrRef')
        self.MethodDeclaration = self.create_variable_length_table_reference('MethodDeclaration', 'MethodDefOrRef')


class MODULE_REF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    26 - ModuleRef Table
        Each row represents a reference to an external module. It is documented in ECMA-335.

    Columns:
        Name (index into String heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'ModuleRef', byte_buffer)

        self.Name = self.create_string_stream_field_value('Name')


class TYPE_SPEC_TABLE_ROW(METADATA_TABLE_ROW):
    """
    27 - TypeSpec Table
        Each row represents a specification for a TypeDef or TypeRef. The only column indexes a token in the #Blob
        stream. It is documented in ECMA-335.

    Columns:
        Signature (index into the Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'TypeSpec', byte_buffer)

        self.Signature = self.create_blob_stream_field_value('Signature')


class IMPL_MAP_TABLE_ROW(METADATA_TABLE_ROW):
    """
    28 - ImplMap Table
        Quote: "The ImplMap table holds information about unmanaged methods that can be reached from managed code, using
            PInvoke dispatch. Each row of the ImplMap table associates a row in the MethodDef table (MemberForwarded)
            with the name of a routine (ImportName) in some unmanaged DLL (ImportScope).".
        This means all the unmanaged functions used by the assembly are listed here. It is documented in ECMA-335.

    Columns:
        MappingFlags (a 2-byte bitmask of type PInvokeAttributes)
        MemberForwarded (index into the Field or MethodDef table; more precisely, a MemberForwarded coded index. However,
            it only ever indexes the MethodDef table, since Field export is not supported)
        ImportName (index into the String heap)
        ImportScope (index into the ModuleRef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'ImplMap', byte_buffer)

        self.MappingFlags = self.create_field_value('MappingFlags', 2, 'H')
        self.MemberForwarded = self.create_variable_length_table_reference('MemberForwarded', 'MemberForwarded')
        self.ImportName = self.create_string_stream_field_value('ImportName')
        self.ImportScope = self.create_table_reference('ImportScope', 'ModuleRef')


class FIELD_RVA_TABLE_ROW(METADATA_TABLE_ROW):
    """
    29 - FieldRVA Table
        Each row is an extension for a Field table. The RVA in this table gives the location of the initial value for a
        Field. It is documented in ECMA-335.

    Columns:
        RVA (a 4-byte constant)
        Field (index into Field table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'FieldRVA', byte_buffer)

        self.RVA = self.create_field_value('RVA', 4, 'I')
        self.Field = self.create_table_reference('Field', 'Field')


class ENC_LOG_TABLE_ROW(METADATA_TABLE_ROW):
    """
    30 - EncLog Table
        Quote: "ENCLog and ENCMap, which occur in temporary images, generated during "Edit and Continue" or
            "incremental compilation" scenarios, whilst debugging. Both table types are reserved for future use."
        It is not documented in ECMA-335, but the definition can be found in metadata.c of the .NET runtime source code.

    Columns:
        Token (a 4-byte constant)
        FuncCode  (a 4-byte constant)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'EncLog', byte_buffer)

        self.Token = self.create_field_value('Token', 4, 'I')
        self.FuncCode = self.create_field_value('FuncCode', 4, 'I')


class ENC_MAP_TABLE_ROW(METADATA_TABLE_ROW):
    """
    31 - EncMap Table
        Quote: "ENCLog and ENCMap, which occur in temporary images, generated during "Edit and Continue" or
            "incremental compilation" scenarios, whilst debugging. Both table types are reserved for future use."
        It is not documented in ECMA-335, but the definition can be found in metadata.c of the .NET runtime source code.

    Columns:
        Token (a 4-byte constant)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'EncMap', byte_buffer)

        self.Token = self.create_field_value('Token', 4, 'I')


class ASSEMBLY_TABLE_ROW(METADATA_TABLE_ROW):
    """
    32 - Assembly Table
        It's officially a one-row table, but there are ITW files with more than one row. It stores information about
        the current assembly. It is documented in ECMA-335.

    Columns:
        HashAlgId (a 4-byte constant of type AssemblyHashAlgorithm)
        MajorVersion, MinorVersion, BuildNumber, RevisionNumber (2-byte constants)
        Flags (a 4-byte bitmask of type AssemblyFlags)
        PublicKey (index into Blob heap)
        Name (index into String heap)
        Culture (index into String heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'Assembly', byte_buffer)

        self.HashAlgId = self.create_field_value('HashAlgId', 4, 'I')
        self.MajorVersion = self.create_field_value('MajorVersion', 2, 'H')
        self.MinorVersion = self.create_field_value('MinorVersion', 2, 'H')
        self.BuildNumber = self.create_field_value('BuildNumber', 2, 'H')
        self.RevisionNumber = self.create_field_value('RevisionNumber', 2, 'H')
        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.PublicKey = self.create_blob_stream_field_value('PublicKey')
        self.Name = self.create_string_stream_field_value('Name')
        self.Culture = self.create_string_stream_field_value('Culture')


class ASSEMBLY_PROCESSOR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    33 - AssemblyProcessor Table
        This table is ignored by the CLI and shouldn't be present in an assembly. It is documented in ECMA-335.

    Columns:
        Processor (a 4-byte constant)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'AssemblyProcessor', byte_buffer)

        self.Processor = self.create_field_value('Processor', 4, 'I')


class ASSEMBLY_OS_TABLE_ROW(METADATA_TABLE_ROW):
    """
    34 - AssemblyOS Table
        This table is ignored by the CLI and shouldn't be present in an assembly. It is documented in ECMA-335.

    Columns:
        OSPlatformID (a 4-byte constant)
        OSMajorVersion (a 4-byte constant)
        OSMinorVersion (a 4-byte constant)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'AssemblyOS', byte_buffer)

        self.OSPlatformID = self.create_field_value('OSPlatformID', 4, 'I')
        self.OSMajorVersion = self.create_field_value('OSMajorVersion', 4, 'I')
        self.OSMinorVersion = self.create_field_value('OSMinorVersion', 4, 'I')


class ASSEMBLY_REF_TABLE_ROW(METADATA_TABLE_ROW):
    """
    35 - AssemblyRef Table
        Each row references an external assembly. It is documented in ECMA-335.

    Columns:
        MajorVersion, MinorVersion, BuildNumber, RevisionNumber (2-byte constants)
        Flags (a 4-byte bitmask of type AssemblyFlags)
        PublicKeyOrToken (index into Blob heap - the public key or token that identifies the author of this Assembly)
        Name (index into String heap)
        Culture (index into String heap)
        HashValue (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'AssemblyRef', byte_buffer)

        self.MajorVersion = self.create_field_value('MajorVersion', 2, 'H')
        self.MinorVersion = self.create_field_value('MinorVersion', 2, 'H')
        self.BuildNumber = self.create_field_value('BuildNumber', 2, 'H')
        self.RevisionNumber = self.create_field_value('RevisionNumber', 2, 'H')
        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.PublicKeyOrToken = self.create_blob_stream_field_value('PublicKeyOrToken')
        self.Name = self.create_string_stream_field_value('Name')
        self.Culture = self.create_string_stream_field_value('Culture')
        self.HashValue = self.create_blob_stream_field_value('HashValue')


class ASSEMBLY_REF_PROCESSOR_TABLE_ROW(METADATA_TABLE_ROW):
    """
    36 - AssemblyRefProcessor Table
        This table is ignored by the CLI and shouldn't be present in an assembly. It is documented in ECMA-335.

    Columns:
        Processor (4-byte constant)
        AssemblyRef (index into the AssemblyRef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'AssemblyRefProcessor', byte_buffer)

        self.Processor = self.create_field_value('Processor', 4, 'I')
        self.AssemblyRef = self.create_table_reference('AssemblyRef', 'AssemblyRef')


class ASSEMBLY_REF_OS_TABLE_ROW(METADATA_TABLE_ROW):
    """
    37 - AssemblyRefOS Table
        This table is ignored by the CLI and shouldn't be present in an assembly. It is documented in ECMA-335.

    Columns:
        OSPlatformId (4-byte constant)
        OSMajorVersion (4-byte constant)
        OSMinorVersion (4-byte constant)
        AssemblyRef (index into the AssemblyRef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'AssemblyRefOS', byte_buffer)

        self.OSPlatformID = self.create_field_value('OSPlatformID', 4, 'I')
        self.OSMajorVersion = self.create_field_value('OSMajorVersion', 4, 'I')
        self.OSMinorVersion = self.create_field_value('OSMinorVersion', 4, 'I')
        self.AssemblyRef = self.create_table_reference('AssemblyRef', 'AssemblyRef')


class FILE_TABLE_ROW(METADATA_TABLE_ROW):
    """
    38 - File Table
        Each row references an external file. It is documented in ECMA-335.

    Columns:
        Flags (a 4-byte bitmask of type FileAttributes)
        Name (index into String heap)
        HashValue (index into Blob heap)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'File', byte_buffer)

        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.Name = self.create_string_stream_field_value('Name')
        self.HashValue = self.create_blob_stream_field_value('HashValue')


class EXPORTED_TYPE_TABLE_ROW(METADATA_TABLE_ROW):
    """
    39 - ExportedType Table
        Quote: "The ExportedType table holds a row for each type, defined within other modules of this Assembly, that is
            exported out of this Assembly. In essence, it stores TypeDef row numbers of all types that are marked public in
            other modules that this Assembly comprises.".
         It is documented in ECMA-335.

    Columns:
        Flags (a 4-byte bitmask of type TypeAttributes)
        TypeDefId (4-byte index into a TypeDef table of another module in this Assembly). This field is used as a hint
            only. If the entry in the target TypeDef table matches the TypeName and TypeNamespace entries in this table,
            resolution has succeeded. But if there is a mismatch, the CLI shall fall back to a search of the target
            TypeDef table
        TypeName (index into the String heap)
        TypeNamespace (index into the String heap)
        Implementation. This is an index (more precisely, an Implementation coded index) into either of the following
            tables:
                File table, where that entry says which module in the current assembly holds the TypeDef
                ExportedType table, where that entry is the enclosing Type of the current nested Type
                AssemblyRef table, where that entry says in which assembly the type may now be found (Flags must have
                    the IsTypeForwarder flag set).
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'ExportedType', byte_buffer)

        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.TypeDefId = self.create_field_value('TypeDefId', 4, 'I')
        self.TypeName = self.create_string_stream_field_value('TypeName')
        self.TypeNamespace = self.create_string_stream_field_value('TypeNamespace')

        self.Implementation = self.create_variable_length_table_reference('Implementation', 'Implementation')


class MANIFEST_RESOURCE_TABLE_ROW(METADATA_TABLE_ROW):
    """
    40 - ManifestResource Table
        Each row references an internal or external resource. It is documented in ECMA-335.

    Columns:
        Offset (a 4-byte constant)
        Flags (a 4-byte bitmask of type ManifestResourceAttributes)
        Name (index into the String heap)
        Implementation (index into File table, or AssemblyRef table, or null; more precisely, an Implementation coded index)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'ManifestResource', byte_buffer)

        self.Offset = self.create_field_value('Offset', 4, 'I')
        self.Flags = self.create_field_value('Flags', 4, 'I')
        self.Name = self.create_string_stream_field_value('Name')
        self.Implementation = self.create_variable_length_table_reference('Implementation', 'Implementation')


class NESTED_CLASS_TABLE_ROW(METADATA_TABLE_ROW):
    """
    41 - NestedClass Table
        Each row represents a nested class. It is documented in ECMA-335.

    Columns:
        NestedClass (index into the TypeDef table)
        EnclosingClass (index into the TypeDef table)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'NestedClass', byte_buffer)

        self.NestedClass = self.create_table_reference('NestedClass', 'TypeDef')
        self.EnclosingClass = self.create_table_reference('EnclosingClass', 'TypeDef')


class GENERIC_PARAM_TABLE_ROW(METADATA_TABLE_ROW):
    """
    42 - GenericParam Table
        Quote: "The GenericParam table stores the generic parameters used in generic type definitions and generic
            method definitions. These generic parameters can be constrained (i.e., generic arguments shall extend some
            class and/or implement certain interfaces) or unconstrained.".
        It is documented in ECMA-335.

    Columns:
        Number (the 2-byte index of the generic parameter, numbered left-to-right, from zero)
        Flags (a 2-byte bitmask of type GenericParamAttributes)
        Owner (an index into the TypeDef or MethodDef table, specifying the Type or Method to which this generic
            parameter applies; more precisely, a TypeOrMethodDef coded index)
        Name (a non-null index into the String heap, giving the name for the generic parameter. This is purely
            descriptive and is used only by dotnetfile language compilers and by Reflection)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'GenericParam', byte_buffer)

        self.Number = self.create_field_value('Number', 2, 'H')
        self.Flags = self.create_field_value('Flags', 2, 'H')
        self.Owner = self.create_variable_length_table_reference('Owner', 'TypeOrMethodDef')
        self.Name = self.create_string_stream_field_value('Name')


class METHOD_SPEC_TABLE_ROW(METADATA_TABLE_ROW):
    """
    43 - MethodSpec
        Contains information about generic method instantiations. It is documented in ECMA-335.

    Columns:
        Method (an index into the MethodDef or MemberRef table)
        Instantiation (an index into the Blob heap, holding the signature of this instantiation)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'MethodSpec', byte_buffer)

        self.Method = self.create_variable_length_table_reference('Method', 'MethodDefOrRef')
        self.Instantiation = self.create_blob_stream_field_value('Instantiation')


class GENERIC_PARAM_CONSTRAINT_TABLE_ROW(METADATA_TABLE_ROW):
    """
    44 - GenericParamConstraint Table
        Contains information about inheritance and implementation constraints imposed on the generic parameters.  It is
        documented in ECMA-335.

    Columns:
        Owner (an index into the GenericParam table, specifying to which generic parameter this row refers)
        Constraint (an index into the TypeDef, TypeRef, or TypeSpec tables, specifying from which class this generic
            parameter is constrained to derive; or which interface this generic parameter is constrained to implement;
            more precisely, a TypeDefOrRef coded index)
    """
    def __init__(self, pe, addr: int = None, byte_buffer: bytes = None):
        METADATA_TABLE_ROW.__init__(self, pe, addr, 'GenericParamConstraint', byte_buffer)

        self.Owner = self.create_table_reference('Owner', 'GenericParam')
        self.Constraint = self.create_variable_length_table_reference('Constraint', 'TypeDefOrRef')


"""
This is a lookup table that we can use to get the row types when we're parsing each table of metadata rows in the
metadata stream. There are several tables that are not documented in ECMA-335. However, the definitions can be found
in metadata.c of the .NET runtime dotnetfile code:
https://github.com/dotnet/runtime/blob/main/src/mono/mono/metadata/metadata.c
"""
METADATA_TYPE_LOOKUP: Dict[str, Any] = {
    'Module': MODULE_TABLE_ROW,
    'TypeRef': TYPE_REF_TABLE_ROW,
    'TypeDef': TYPE_DEF_TABLE_ROW,
    'FieldPtr': FIELD_PTR_TABLE_ROW,  # Not documented in ECMA-335
    'Field': FIELD_TABLE_ROW,
    'MethodPtr': METHOD_PTR_TABLE_ROW,  # Not documented in ECMA-335
    'MethodDef': METHOD_DEF_TABLE_ROW,
    'ParamPtr': PARAM_PTR_TABLE_ROW,  # Not documented in ECMA-335
    'Param': PARAM_TABLE_ROW,
    'InterfaceImpl': INTERFACE_IMPL_TABLE_ROW,
    'MemberRef': MEMBER_REF_TABLE_ROW,
    'Constant': CONSTANT_TABLE_ROW,
    'CustomAttribute': CUSTOM_ATTRIBUTE_TABLE_ROW,
    'FieldMarshal': FIELD_MARSHAL_TABLE_ROW,
    'DeclSecurity': DECL_SECURITY_TABLE_ROW,
    'ClassLayout': CLASS_LAYOUT_TABLE_ROW,
    'FieldLayout': FIELD_LAYOUT_TABLE_ROW,
    'StandAloneSig': STAND_ALONE_SIG_TABLE_ROW,
    'EventMap': EVENT_MAP_TABLE_ROW,
    'EventPtr': EVENT_PTR_TABLE_ROW,  # Not documented in ECMA-335
    'Event': EVENT_TABLE_ROW,
    'PropertyMap': PROPERTY_MAP_TABLE_ROW,
    'PropertyPtr': PROPERTY_PTR_TABLE_ROW,  # Not documented in ECMA-335
    'Property': PROPERTY_TABLE_ROW,
    'MethodSemantics': METHOD_SEMANTICS_TABLE_ROW,
    'MethodImpl': METHOD_IMPL_TABLE_ROW,
    'ModuleRef': MODULE_REF_TABLE_ROW,
    'TypeSpec': TYPE_SPEC_TABLE_ROW,
    'ImplMap': IMPL_MAP_TABLE_ROW,
    'FieldRVA': FIELD_RVA_TABLE_ROW,
    'EncLog': ENC_LOG_TABLE_ROW,  # Not documented in ECMA-335
    'EncMap': ENC_MAP_TABLE_ROW,  # Not documented in ECMA-335
    'Assembly': ASSEMBLY_TABLE_ROW,
    'AssemblyProcessor': ASSEMBLY_PROCESSOR_TABLE_ROW,
    'AssemblyOS': ASSEMBLY_OS_TABLE_ROW,
    'AssemblyRef': ASSEMBLY_REF_TABLE_ROW,
    'AssemblyRefProcessor': ASSEMBLY_REF_PROCESSOR_TABLE_ROW,
    'AssemblyRefOS': ASSEMBLY_REF_OS_TABLE_ROW,
    'File': FILE_TABLE_ROW,
    'ExportedType': EXPORTED_TYPE_TABLE_ROW,
    'ManifestResource': MANIFEST_RESOURCE_TABLE_ROW,
    'NestedClass': NESTED_CLASS_TABLE_ROW,
    'GenericParam': GENERIC_PARAM_TABLE_ROW,
    'MethodSpec': METHOD_SPEC_TABLE_ROW,
    'GenericParamConstraint': GENERIC_PARAM_CONSTRAINT_TABLE_ROW,
    # 'Document': DOCUMENT_TABLE_ROW,  # Not documented in ECMA-335
    # 'MethodDebugInformation': METHOD_DEBUG_INFORMATION_TABLE_ROW,  # Not documented in ECMA-335
    # 'LocalScope': LOCAL_SCOPE_TABLE_ROW,  # Not documented in ECMA-335
    # 'LocalVariable': LOCAL_VARIABLE_TABLE_ROW,  # Not documented in ECMA-335
    # 'LocalConstant': LOCAL_CONSTANT_TABLE_ROW,  # Not documented in ECMA-335
    # 'ImportScope': IMPORT_SCOPE_TABLE_ROW,  # Not documented in ECMA-335
    # 'StateMachineMethod': STATE_MACHINE_METHOD_TABLE_ROW,  # Not documented in ECMA-335
    # 'CustomDebugInformation': CUSTOM_DEBUG_INFORMATION_TABLE_ROW  # Not documented in ECMA-335
}


def get_metadata_row_class_for_table(table_name: str):
    """
    maps between string represents a table name (such as "TypeRef") to
    it appropriate class
    :param table_name: string represents a table name
    :return:
    """
    return METADATA_TYPE_LOOKUP.get(table_name, None)
