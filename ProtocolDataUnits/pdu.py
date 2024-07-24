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
DEFAULT_BYTE_ORDER = '>'

# Set up logging configuration
logging.basicConfig(level=logging.INFO)

class PDU:
    """
    The PDU (Protocol Data Unit) class represents a data structure that is used for encoding and decoding binary data.
    It provides methods for defining the structure of the PDU, encoding data into binary format, and decoding binary data
    back into the original structure.

    Attributes:
        fields (list): A list of tuples representing the fields of the PDU. Each tuple contains the field type, name,
                       and optional value.
        byte_order (str): The byte order used for encoding and decoding the PDU. It can be either 'big' or 'little'.
        pdu_length (int): The length of the PDU in bytes.
        default_values (dict): A dictionary containing default values for fields that are not provided during encoding.

    Methods:
        length(length): Sets the length of the PDU.
        order(byte_order): Sets the byte order of the PDU.
        uint8(name, value, default): Adds a uint8 field to the PDU.
        uint16(name, value, default): Adds a uint16 field to the PDU.
        uint32(name, value, default): Adds a uint32 field to the PDU.
        float(name, value, default): Adds a float field to the PDU.
        double(name, value, default): Adds a double field to the PDU.
        int8(name, value, default): Adds an int8 field to the PDU.
        int16(name, value, default): Adds an int16 field to the PDU.
        int32(name, value, default): Adds an int32 field to the PDU.
        int64(name, value, default): Adds an int64 field to the PDU.
        uint64(name, value, default): Adds a uint64 field to the PDU.
        filler(count): Adds a filler field to the PDU.
        padding(value): Adds padding to the PDU.
        fixed_string(name, length, default): Adds a fixed-length string field to the PDU.
        length_prefixed_string(name, default): Adds a length-prefixed string field to the PDU.
        variable_length_array(name, element_type, default): Adds a variable-length array field to the PDU.
        nested_pdu(name, pdu): Adds a nested PDU field to the PDU.
        compute_crc(data): Computes the CRC32 checksum of the given data.
        encode(data, compress): Encodes the data into binary format.
        decode(data, decompress): Decodes the binary data back into the original structure.

    Example usage:
        pdu = PDU()
        pdu.uint8('field1', value=10)
        pdu.uint16('field2', value=100)
        pdu.encode({'field1': 5, 'field2': 50})
        pdu.decode(binary_data)
    
    """
    def __init__(self):
        self.fields = []
        self.byte_order = DEFAULT_BYTE_ORDER
        self.pdu_length = None
        self.default_values = {}

    def length(self, length):
        self.pdu_length = length
        return self

    def order(self, byte_order):
        self.byte_order = '>' if byte_order == 'big' else '<'
        return self

    def uint8(self, name=None, value=None, default=None):
        self.fields.append(('uint8', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint16(self, name=None, value=None, default=None):
        self.fields.append(('uint16', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint32(self, name=None, value=None, default=None):
        self.fields.append(('uint32', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def float(self, name=None, value=None, default=None):
        self.fields.append(('float', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def double(self, name=None, value=None, default=None):
        self.fields.append(('double', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int8(self, name=None, value=None, default=None):
        self.fields.append(('int8', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int16(self, name=None, value=None, default=None):
        self.fields.append(('int16', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int32(self, name=None, value=None, default=None):
        self.fields.append(('int32', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def int64(self, name=None, value=None, default=None):
        self.fields.append(('int64', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def uint64(self, name=None, value=None, default=None):
        self.fields.append(('uint64', name, value))
        if default is not None:
            self.default_values[name] = default
        return self

    def filler(self, count):
        self.fields.append(('filler', None, count))
        return self

    def padding(self, value):
        self.fields.append(('padding', None, value))
        return self

    def fixed_string(self, name, length, default=None):
        self.fields.append(('fixed_string', name, length))
        if default is not None:
            self.default_values[name] = default
        return self

    def length_prefixed_string(self, name, default=None):
        self.fields.append(('length_prefixed_string', name, None))
        if default is not None:
            self.default_values[name] = default
        return self

    def variable_length_array(self, name, element_type, default=None):
        self.fields.append(('variable_length_array', name, element_type))
        if default is not None:
            self.default_values[name] = default
        return self

    def nested_pdu(self, name, pdu):
        self.fields.append(('nested_pdu', name, pdu))
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

        Parameters:
        - data (dict): A dictionary containing the field names and their corresponding values to be encoded.
        - compress (bool): If True, the encoded data will be compressed using zlib. Default is False.

        Returns:
        - bytes: The encoded byte array representing the PDU.

        Raises:
        - ValueError: If a required field is missing in the provided data.

        Field Types Handled:
        - uint8, int8, uint16, int16, uint32, int32, uint64, int64
        - float, double
        - fixed_string: A string of fixed length.
        - length_prefixed_string: A string prefixed with its length.
        - variable_length_array: An array with a length prefix.
        - nested_pdu: Another PDU structure embedded within the main PDU.
        - filler: Padding bytes.
        - padding: Additional padding to achieve the specified PDU length.

        CRC Computation:
        - A CRC32 checksum is computed and appended to the end of the encoded data to ensure data integrity.
        """
        encoded = bytearray()
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
            elif field_type == 'nested_pdu':
                nested_pdu = value
                nested_encoded = nested_pdu.encode(value_to_encode)
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

        Parameters:
        - data (bytes): The byte array representing the encoded PDU.
        - decompress (bool): If True, the input data will be decompressed using zlib. Default is False.

        Returns:
        - dict: A dictionary containing the decoded field names and their corresponding values.

        Raises:
        - ValueError: If the CRC checksum does not match, indicating data corruption.

        Field Types Handled:
        - uint8, int8, uint16, int16, uint32, int32, uint64, int64
        - float, double
        - fixed_string: A string of fixed length.
        - length_prefixed_string: A string prefixed with its length.
        - variable_length_array: An array with a length prefix.
        - nested_pdu: Another PDU structure embedded within the main PDU.
        - filler: Padding bytes.
        - padding: Additional padding to achieve the specified PDU length.

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
            elif field_type == 'nested_pdu':
                nested_pdu = value
                nested_length, = struct.unpack_from(self.byte_order + 'I', data, offset)
                offset += 4
                nested_data = data[offset:offset + nested_length]
                decoded[name] = nested_pdu.decode(nested_data)
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

if __name__ == "__main__":
    # Example for dynamic PDU format definition
    print("===========")
    print("Basic Field Types Example")
    print("supports : uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double")
    print("===========")
    my_pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2')
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Fixed-Length Strings Example")
    print("===========")
    my_pdu = PDU().length(32).order('big').uint8('type').fixed_string('fixed_str', 10)
    encoded_bytes = my_pdu.encode({'type': 7, 'fixed_str': 'hello'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Length-Prefixed Strings Example")
    print("===========")
    my_pdu = PDU().length(40).order('big').uint8('type').length_prefixed_string('length_str')
    encoded_bytes = my_pdu.encode({'type': 7, 'length_str': 'dynamic string'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Variable-Length Arrays Example")
    print("===========")
    my_pdu = PDU().length(48).order('big').uint8('type').variable_length_array('array', 'uint8')
    encoded_bytes = my_pdu.encode({'type': 7, 'array': [1, 2, 3, 4, 5]})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Nested PDU Example")
    print("===========")
    nested_pdu = PDU().length(8).order('big').uint8('nested_type').uint8('nested_value')
    main_pdu = PDU().length(16).order('big').uint8('type').nested_pdu('nested', nested_pdu)
    encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
    decoded_data = main_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Serialization and Deserialization Example")
    print("===========")
    my_pdu = PDU().length(68).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes: {encoded_bytes}")
    print("===========")

    decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    json_str = my_pdu.to_json()
    print(f"Serialized PDU to JSON:   {json_str}")
    print("===========")

    new_pdu = PDU.from_json(json_str)
    print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")
    print("===========")

    encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")
    print("===========")

    decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
    print(f"Decoded Data (new PDU): {decoded_data_new}")
    print("===========")

    """
    ===========
    Basic Field Types Example
    supports : uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double
    ===========
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f, CRC32: 2257222243
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f, CRC32: 2257222243
    Encoded Bytes: b'\x07@H\xf5\xc3@\x19\x1e\xb8Q\xeb\x85\x1f\x86\x8azc'
    Decoded Data: {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28}
    ===========
    ===========
    Fixed-Length Strings Example
    ===========
    INFO:root:Data for CRC32: 0768656c6c6f0000000000, CRC32: 2760379114
    INFO:root:Data for CRC32: 0768656c6c6f0000000000, CRC32: 2760379114
    Encoded Bytes: b'\x07hello\x00\x00\x00\x00\x00\xa4\x88\n\xea'
    Decoded Data: {'type': 7, 'fixed_str': 'hello'}
    ===========
    ===========
    Length-Prefixed Strings Example
    ===========
    INFO:root:Data for CRC32: 070000000e64796e616d696320737472696e67, CRC32: 4010864400
    INFO:root:Data for CRC32: 070000000e64796e616d696320737472696e67, CRC32: 4010864400
    Encoded Bytes: b'\x07\x00\x00\x00\x0edynamic string\xef\x10\xef\x10'
    Decoded Data: {'type': 7, 'length_str': 'dynamic string'}
    ===========
    ===========
    Variable-Length Arrays Example
    ===========
    INFO:root:Data for CRC32: 07000000050102030405, CRC32: 3501362261
    INFO:root:Data for CRC32: 07000000050102030405, CRC32: 3501362261
    Encoded Bytes: b'\x07\x00\x00\x00\x05\x01\x02\x03\x04\x05\xd0\xb2\x8cU'
    Decoded Data: {'type': 7, 'array': [1, 2, 3, 4, 5]}
    ===========
    ===========
    Nested PDU Example
    ===========
    INFO:root:Data for CRC32: 0102, CRC32: 3066839698
    INFO:root:Data for CRC32: 07000000060102b6cc4292, CRC32: 3960647709
    INFO:root:Data for CRC32: 0102, CRC32: 3066839698
    INFO:root:Data for CRC32: 07000000060102b6cc4292, CRC32: 3960647709
    Encoded Bytes: b'\x07\x00\x00\x00\x06\x01\x02\xb6\xccB\x92\xec\x12\xb0\x1d'
    Decoded Data: {'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}}
    ===========
    ===========
    Serialization and Deserialization Example
    ===========
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffffffffffff, CRC32: 1819767949
    Encoded Bytes: b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\x8c\xd4\x9c\x9c|\x06(\xe0K\xa9\xccK\xcc\xcdLV(.)\xca\xccK\x07\x8a\xb0221\xb3\xb0\xfeG\x019\xe5%\xbd\x00!l\x1c\xff'
    ===========
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffffffffffff, CRC32: 1819767949
    Decoded Data: {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}
    ===========
    Serialized PDU to JSON:   {"length": 68, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["fixed_string", "fixed_str", 10], ["length_prefixed_string", "length_str", null], ["variable_length_array", "array", "uint8"], ["padding", null, 255]]}
    ===========
    Deserialized PDU from JSON: {"length": 68, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["fixed_string", "fixed_str", 10], ["length_prefixed_string", "length_str", null], ["variable_length_array", "array", "uint8"], ["padding", null, 255]]}
    ===========
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffffffffffff, CRC32: 1819767949
    Encoded Bytes (new PDU): b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\x8c\xd4\x9c\x9c|\x06(\xe0K\xa9\xccK\xcc\xcdLV(.)\xca\xccK\x07\x8a\xb0221\xb3\xb0\xfeG\x019\xe5%\xbd\x00!l\x1c\xff'
    ===========
    INFO:root:Data for CRC32: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffffffffffff, CRC32: 1819767949
    Decoded Data (new PDU): {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}
    ===========
    """
