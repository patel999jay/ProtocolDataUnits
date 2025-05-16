#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 Jay Patel <patel.jay@dal.ca>.
#
# Licensed under the MIT License

import struct
import binascii
import logging
from loguru import logger
import zlib
import json

# Constants
# Changed to use descriptive constants for endianness and field types.
BIG_ENDIAN = '>'
LITTLE_ENDIAN = '<'

# Constants for field types (more readable and reduces potential typos)
UINT8 = 'uint8'
INT8 = 'int8'
UINT16 = 'uint16'
INT16 = 'int16'
UINT32 = 'uint32'
INT32 = 'int32'
UINT64 = 'uint64'
INT64 = 'int64'
FLOAT = 'float'
DOUBLE = 'double'
FIXED_STRING = 'fixed_string'
LENGTH_PREFIXED_STRING = 'length_prefixed_string'
VARIABLE_LENGTH_ARRAY = 'variable_length_array'
# NESTED_PDU = 'nested_pdu'
PDU_FRAGMENT = 'pdu_fragment'
FILLER = 'filler'
PADDING = 'padding'

# Map field types to their struct format sizes for easier size calculation.
FIELD_SIZES = {
    UINT8: struct.calcsize('B'),
    INT8: struct.calcsize('b'),
    UINT16: struct.calcsize('H'),
    INT16: struct.calcsize('h'),
    UINT32: struct.calcsize('I'),
    INT32: struct.calcsize('i'),
    UINT64: struct.calcsize('Q'),
    INT64: struct.calcsize('q'),
    FLOAT: struct.calcsize('f'),
    DOUBLE: struct.calcsize('d'),
}

# Set up logging configuration
logging.basicConfig(level=logging.INFO)

class PDU:
    class PDU:
        """
        The PDU (Protocol Data Unit) class represents a data structure used for encoding and decoding binary data.

        It allows you to define the structure of a PDU with various field types, specify byte order, 
        and encode data into binary format or decode binary data back into structured data.

        **Basic Example**:
        
        .. code-block:: python
        
            # Define a simple PDU structure with uint8 and float fields
            pdu = PDU().length(16).order('big').uint8('type').float('value')
            encoded = pdu.encode({'type': 1, 'value': 3.14})
            decoded = pdu.decode(encoded)

        .. note::
            For more detailed examples, refer to the ``examples/pdu_examples.py`` file.

        **Attributes**:
            - **fields** (list): A list of field definitions for the PDU.
            - **byte_order** (str): Byte order for encoding/decoding, `'big'` or `'little'`.
            - **pdu_length** (int): Length of the PDU in bytes.
            - **default_values** (dict): Default values for fields.

        **Methods**:
            - **length(length)**: Sets the length of the PDU.
            - **order(byte_order)**: Sets the byte order of the PDU.
            - **encode(data, compress=False)**: Encodes structured data into a PDU.
            - **decode(data, decompress=False)**: Decodes binary data back into structured data.
    """

    def __init__(self):
        self.fields = []
        self.byte_order = BIG_ENDIAN
        self.pdu_length = None
        self.default_values = {}

    def __repr__(self):
        field_reprs = ", ".join(f"{name}={value}" for (field_type, name, value) in self.fields if name)
        return f"PDU(length={self.pdu_length}, byte_order={'bigendian' if self.byte_order == BIG_ENDIAN else 'littleendian'}, fields=[{field_reprs}])"

    def length(self, length=None):
        """
        Sets the length of the PDU. If the length is not provided, it will be inferred from the defined fields.

        **Parameters**:
            - **length (int, optional)**: The total length of the PDU in bytes. If not provided, the length is inferred based on the fields.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        # Infer length if not provided.
        if length is None:
            total_size = 0
            for field_type, name, value in self.fields:
                if field_type in FIELD_SIZES:
                    total_size += FIELD_SIZES[field_type]
                elif field_type == FIXED_STRING:
                    total_size += value  # Length is directly the value for fixed-length strings.
                elif field_type == LENGTH_PREFIXED_STRING:
                    total_size += 4  # Length prefix.
                    if name in self.default_values:
                        total_size += len(self.default_values[name])
                elif field_type == VARIABLE_LENGTH_ARRAY:
                    total_size += 4  # Length prefix.
                    if name in self.default_values:
                        total_size += len(self.default_values[name]) * FIELD_SIZES[value]
                elif field_type == PDU_FRAGMENT: # NESTED_PDU:
                    total_size += value.pdu_length
                elif field_type == FILLER:
                    total_size += value
                # Note: PADDING will be handled dynamically during encoding.
            self.pdu_length = total_size
        else:
            self.pdu_length = length
        return self

    def order(self, byte_order):
        """
        Sets the byte order for the PDU.

        **Parameters**:
            - **byte_order (str)**: The byte order to use. Should be 'bigendian' for big-endian or 'littleendian' for little-endian.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        # Use more descriptive endianness terms.
        self.byte_order = BIG_ENDIAN if byte_order == 'bigendian' else LITTLE_ENDIAN
        return self

    def uint8(self, name=None, value=None, default=None):
        """
        Adds a uint8 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((UINT8, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint16(self, name=None, value=None, default=None):
        """
        Adds a uint16 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((UINT16, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint32(self, name=None, value=None, default=None):
        """
        Adds a uint32 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((UINT32, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def float(self, name=None, value=None, default=None):
        """
        Adds a float field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (float, optional)**: A specific value for the field.
            - **default (float, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((FLOAT, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def double(self, name=None, value=None, default=None):
        """
        Adds a double field to the PDU.

        **Parameters:
            - **name (str, optional)**: The name of the field.
            - **value (float, optional)**: A specific value for the field.
            - **default (float, optional)**: A default value to use if none is provided during encoding.

        **Returns:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((DOUBLE, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int8(self, name=None, value=None, default=None):
        """
        Adds an int8 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((INT8, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int16(self, name=None, value=None, default=None):
        """
        Adds an int16 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((INT16, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int32(self, name=None, value=None, default=None):
        """
        Adds an int32 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((INT32, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int64(self, name=None, value=None, default=None):
        """
        Adds an int64 field to the PDU.

        **Parameter**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((INT64, name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint64(self, name=None, value=None, default=None):
        """
        Adds a uint64 field to the PDU.

        **Parameters**:
            - **name (str, optional)**: The name of the field.
            - **value (int, optional)**: A specific value for the field.
            - **default (int, optional)**: A default value to use if none is provided during encoding.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((UINT64, name, value))
        if default is not None:
            self.default_values[name] = default
        return self


    def filler(self, count):
        """
        Adds a filler field with a specified number of bytes.

        **Parameters**:
            - **count (int)**: The number of bytes for the filler.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((FILLER, None, count))
        return self

    def padding(self, value):
        """
        Adds padding bytes to the PDU.

        **Parameters**:
            - **value (int)**: The value to be used for the padding bytes.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((PADDING, None, value))
        return self

    def fixed_string(self, name, length, default=None):
        """
        Adds a fixed-length string field to the PDU.

        The encoded format is a byte sequence of the specified length. If the provided 
        string is shorter than the specified length, it will be padded with null bytes (`\x00`).
        If the string is longer, it will be truncated to fit the specified length.

        **Parameters**:
            - **name (str)**: The name of the field.
            - **length (int)**: The length of the string in bytes.
            - **default (str, optional)**: A default value to use if none is provided during encoding.

        **Example**:
        
        .. code-block:: python
            Field Definition: `fixed_string('name', 10)`
            Input: `"hello"`
            Encoded: `b'hello\x00\x00\x00\x00\x00'` (10 bytes, with 5 null bytes for padding)

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((FIXED_STRING, name, length))
        if default is not None:
            self.default_values[name] = default
        return self

    def length_prefixed_string(self, name, default=None):
        """
        Adds a length-prefixed string field to the PDU.

        The encoded format is a 4-byte unsigned integer prefix (indicating the string length)
        followed by the string data itself.

        **Parameters**:
            - **name (str)**: The name of the field.
            - **default (str, optional)**: A default value to use if none is provided during encoding.

        **Example**:
        
        .. code-block:: python
            Input: "example"
            Encoded: b'\\x07\\x00\\x00\\x00example' (where \\x07\\x00\\x00\\x00 indicates length 7)

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((LENGTH_PREFIXED_STRING, name, None))
        if default is not None:
            self.default_values[name] = default
        return self

    def variable_length_array(self, name, element_type, default=None):
        """
        Adds a variable-length array field to the PDU.

        The encoded format is a 4-byte unsigned integer prefix representing the number of 
        elements in the array, followed by the serialized form of each element according to 
        the specified `element_type`.

        **Parameters**:
            - **name (str)**: The name of the field.
            - **element_type (str)**: The type of the elements in the array (e.g., 'uint8', 'int16').
            - **default (list, optional)**: A default array to use if none is provided during encoding.

        **Example**:
        
        .. code-block:: python
            Field Definition: `variable_length_array('values', 'uint8')`
            Input: `[1, 2, 3, 4, 5]`
            Encoded: `b'\x05\x00\x00\x00\x01\x02\x03\x04\x05'`
                - `b'\x05\x00\x00\x00'` represents the length `5` as a 4-byte integer.
                - `b'\x01\x02\x03\x04\x05'` represents the array elements encoded as `uint8`.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((VARIABLE_LENGTH_ARRAY, name, element_type))
        if default is not None:
            self.default_values[name] = default
        return self

    def nested_pdu(self, name, pdu):
        """
        Adds a nested PDU (sub-PDU) field to the current PDU structure. Keep this for backward compatible for now.
        This is same as the pdu_fragment.

        **Parameters**:
            - **name (str)**: The name of the field.
            - **pdu (PDU)**: An instance of a PDU that represents the nested structure.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((PDU_FRAGMENT, name, pdu))
        return self
    
    def pdu_fragment(self, name, pdu):
        """
        Adds a nested PDU (sub-PDU) field to the current PDU structure.

        **Parameters**:
            - **name (str)**: The name of the field.
            - **pdu (PDU)**: An instance of a PDU that represents the nested structure.

        **Returns**:
            - **self**: Returns the instance of the current PDU for method chaining.
        """
        self.fields.append((PDU_FRAGMENT, name, pdu))
        return self

    @staticmethod
    def compute_crc(data):
        crc = binascii.crc32(data) & 0xffffffff
        logging.info(f"Data for CRC32: {data.hex()}, CRC32: {crc}")
        return crc
    
    @logger.catch
    def encode(self, data, compress=False):
        """
        Encodes the provided data into a PDU (Protocol Data Unit) byte array.

        The encode function serializes the data fields based on the specified PDU structure. 
        It handles various data types including integers, floats, strings, arrays, and nested PDUs. 
        Optionally, the encoded data can be compressed using zlib.

        **Parameters**:
            - **data (dict)**: A dictionary containing the field names and their corresponding values to be encoded.
            - **compress (bool)**: If True, the encoded data will be compressed using zlib. Default is False.

        **Returns**:
            - **bytes**: The encoded byte array representing the PDU.

        **Raises**:
            - **ValueError**: If a required field is missing in the provided data.

        **Field Types Handled**:
            - uint8, int8, uint16, int16, uint32, int32, uint64, int64
            - float, double
            - **fixed_string**: A string of fixed length.
            - **length_prefixed_string**: A string prefixed with its length.
            - **variable_length_array**: An array with a length prefix.
            - **pdu_fragment**: Another PDU structure embedded within the main PDU.
            - **filler: Padding bytes.
            - **padding**: Additional padding to achieve the specified PDU length.

        **CRC Computation**:
            - A CRC32 checksum is computed and appended to the end of the encoded data to ensure data integrity.
        """
        encoded = bytearray()
        if self.pdu_length is None:
            self.length()  # Infer the length if not set.

        total_field_size = 0
        for field_type, name, value in self.fields:
            if field_type in FIELD_SIZES:
                total_field_size += FIELD_SIZES[field_type]
            elif field_type == FIXED_STRING:
                total_field_size += value
            elif field_type == LENGTH_PREFIXED_STRING:
                total_field_size += 4 + len(data.get(name, self.default_values.get(name, "")))
            elif field_type == VARIABLE_LENGTH_ARRAY:
                array_length = len(data.get(name, self.default_values.get(name, [])))
                total_field_size += 4 + array_length * FIELD_SIZES[value]
            elif field_type == PDU_FRAGMENT:
                total_field_size += value.pdu_length
            elif field_type == FILLER:
                total_field_size += value

        # Adjust padding if required.
        padding_length = max(0, self.pdu_length - total_field_size - 4)  # 4 bytes for CRC
        total_field_size += padding_length

        # If the user specified length is different from the calculated one, adjust dynamically or raise a warning.
        if self.pdu_length != total_field_size:
            logging.warning(f"Inferred PDU length ({total_field_size}) adjusted to match the user-defined length ({self.pdu_length}).")
            self.pdu_length = total_field_size

        for field_type, name, value in self.fields:
            if name is not None:
                if name not in data and name not in self.default_values:
                    raise ValueError(f"Missing value for field: {name}")
                value_to_encode = data.get(name, self.default_values.get(name))
            else:
                value_to_encode = value

            if field_type == 'uint8':
                encoded_value = struct.pack(self.byte_order + 'B', value_to_encode)
            elif field_type == 'int8':
                encoded_value = struct.pack(self.byte_order + 'b', value_to_encode)
            elif field_type == 'uint16':
                encoded_value = struct.pack(self.byte_order + 'H', value_to_encode)
            elif field_type == 'int16':
                encoded_value = struct.pack(self.byte_order + 'h', value_to_encode)
            elif field_type == 'uint32':
                encoded_value = struct.pack(self.byte_order + 'I', value_to_encode)
            elif field_type == 'int32':
                encoded_value = struct.pack(self.byte_order + 'i', value_to_encode)
            elif field_type == 'uint64':
                encoded_value = struct.pack(self.byte_order + 'Q', value_to_encode)
            elif field_type == 'int64':
                encoded_value = struct.pack(self.byte_order + 'q', value_to_encode)
            elif field_type == 'float':
                encoded_value = struct.pack(self.byte_order + 'f', value_to_encode)
            elif field_type == 'double':
                encoded_value = struct.pack(self.byte_order + 'd', value_to_encode)
            elif field_type == 'fixed_string':
                encoded_value = value_to_encode.encode('utf-8').ljust(value, b'\x00')[:value]
            elif field_type == 'length_prefixed_string':
                length_prefix = struct.pack(self.byte_order + 'I', len(value_to_encode))
                encoded_value = length_prefix + value_to_encode.encode('utf-8')
            elif field_type == 'variable_length_array':
                length_prefix = struct.pack(self.byte_order + 'I', len(value_to_encode))
                element_format = {'uint8': 'B', 'int8': 'b', 'uint16': 'H', 'int16': 'h',
                                'uint32': 'I', 'int32': 'i', 'uint64': 'Q', 'int64': 'q',
                                'float': 'f', 'double': 'd'}[value]
                encoded_value = length_prefix
                for elem in value_to_encode:
                    encoded_value += struct.pack(self.byte_order + element_format, elem)
            elif field_type == 'pdu_fragment': # 'nested_pdu':
                pdu_fragment = value
                nested_encoded = pdu_fragment.encode(value_to_encode)
                encoded_value = struct.pack(self.byte_order + 'I', len(nested_encoded)) + nested_encoded
            elif field_type == 'filler':
                encoded_value = b'\x00' * value_to_encode
            elif field_type == 'padding':
                padding_length = self.pdu_length - len(encoded) - 4  # Subtract CRC length
                if padding_length > 0:
                    encoded_value = bytes([value]) * padding_length
                else:
                    encoded_value = b''

            encoded.extend(encoded_value)

        # Add padding if necessary.
        if padding_length > 0:
            encoded.extend(bytes([0] * padding_length))
            
        # Compute CRC for the data without the CRC field itself
        data_for_crc = encoded
        crc = self.compute_crc(data_for_crc)
        encoded.extend(struct.pack(self.byte_order + 'I', crc))

        if compress:
            encoded = zlib.compress(encoded)

        return bytes(encoded)

    @logger.catch
    def decode(self, data, decompress=False):
        """
        Decodes a PDU (Protocol Data Unit) byte array into its constituent fields.

        The decode function parses the provided byte array based on the specified PDU structure, 
        extracting the values of each field. It handles various data types including integers, 
        floats, strings, arrays, and nested PDUs. Optionally, the input data can be decompressed 
        using zlib.

        **Parameters**:
            - **data (bytes)**: The byte array representing the encoded PDU.
            - **decompress (bool)**: If True, the input data will be decompressed using zlib. Default is False.

        **Returns**:
            - **dict**: A dictionary containing the decoded field names and their corresponding values.

        **Raises**:
            - **ValueError**: If the CRC checksum does not match, indicating data corruption.

        **Field Types Handled**:
            - uint8, int8, uint16, int16, uint32, int32, uint64, int64
            - float, double
            - **fixed_string**: A string of fixed length.
            - **length_prefixed_string**: A string prefixed with its length.
            - **variable_length_array**: An array with a length prefix.
            - **pdu_fragment**: Another PDU structure embedded within the main PDU.
            - **filler**: Padding bytes.
            - **padding**: Additional padding to achieve the specified PDU length.

        CRC Validation:
            - A CRC32 checksum is validated at the end of the decoded data to ensure data integrity.
        """

        if decompress:
            data = zlib.decompress(data)

        decoded = {}
        offset = 0
        format_map = {
            'uint8': 'B', 'int8': 'b',
            'uint16': 'H', 'int16': 'h',
            'uint32': 'I', 'int32': 'i',
            'uint64': 'Q', 'int64': 'q',
            'float': 'f', 'double': 'd'
        }

        for field_type, name, value in self.fields:
            if name is None:
                if field_type in format_map:
                    offset += struct.calcsize(format_map[field_type])
                elif field_type == 'filler':
                    offset += value
                elif field_type == 'padding':
                    break
                continue

            if field_type in format_map:
                decoded[name], = struct.unpack_from(self.byte_order + format_map[field_type], data, offset)
                offset += struct.calcsize(format_map[field_type])
            elif field_type == 'fixed_string':
                decoded[name] = data[offset:offset + value].decode('utf-8').rstrip('\x00')
                offset += value
            elif field_type == 'length_prefixed_string':
                str_length, = struct.unpack_from(self.byte_order + 'I', data, offset)
                offset += 4
                decoded[name] = data[offset:offset + str_length].decode('utf-8')
                offset += str_length
            elif field_type == 'variable_length_array':
                length, = struct.unpack_from(self.byte_order + 'I', data, offset)
                offset += 4
                element_format = {'uint8': 'B', 'int8': 'b', 'uint16': 'H', 'int16': 'h',
                                'uint32': 'I', 'int32': 'i', 'uint64': 'Q', 'int64': 'q',
                                'float': 'f', 'double': 'd'}[value]
                decoded[name] = []
                for _ in range(length):
                    elem, = struct.unpack_from(self.byte_order + element_format, data, offset)
                    decoded[name].append(elem)
                    offset += struct.calcsize(element_format)
            elif field_type == 'pdu_fragment':
                pdu_fragment = value
                nested_length, = struct.unpack_from(self.byte_order + 'I', data, offset)
                offset += 4
                nested_data = data[offset:offset + nested_length]
                decoded[name] = pdu_fragment.decode(nested_data)
                offset += nested_length

        # Extract the CRC from the end of the data
        crc_expected = struct.unpack_from(self.byte_order + 'I', data, len(data) - 4)[0]
        data_for_crc = data[:len(data) - 4]  # Data excluding CRC
        crc_computed = self.compute_crc(data_for_crc)

        if crc_computed != crc_expected:
            raise ValueError(f"CRC mismatch: computed={crc_computed}, expected={crc_expected}")

        return decoded


    def to_json(self):
        pdu_info = {
            'length': self.pdu_length,
            'byte_order': 'big' if self.byte_order == '>' else 'little',
            'fields': self.fields
        }
        return json.dumps(pdu_info)

    @staticmethod
    def from_json(json_str):
        data = json.loads(json_str)
        pdu = PDU().length(data['length']).order(data['byte_order'])
        for field in data['fields']:
            field_name = field[0]
            field_args = field[1:]
            if field_name in ['fixed_string', 'variable_length_array', 'nested_pdu']:
                pdu = getattr(pdu, field_name)(*field_args)
            elif field_name == 'padding':
                pdu = pdu.padding(field_args[1])
            else:
                if len(field_args) == 3:
                    pdu = getattr(pdu, field_name)(*field_args[:2], default=field_args[2])
                else:
                    pdu = getattr(pdu, field_name)(*field_args)
        return pdu

def create_pdu_format(length, byte_order, *fields):
    """
    Create a PDU format using a simplified and user-friendly API.

    **Parameters**:
        - **length (int)**: The total length of the PDU.
        - **byte_order (str)**: The byte order to use ('big' for big-endian or 'little' for little-endian).
        - ***fields (tuples)**: A variable number of tuples, each representing a field in the PDU. 
                        Each tuple should contain the field type followed by the necessary arguments.

    **Returns**:
        - **PDU**: An instance of the PDU class with the specified format.
    """
    pdu = PDU().length(length).order(byte_order)
    for field in fields:
        field_type = field[0]
        if field_type == 'pdu_fragment':
            pdu = pdu.pdu_fragment(field[1], field[2])
        else:
            pdu = getattr(pdu, field_type)(*field[1:])
    return pdu
