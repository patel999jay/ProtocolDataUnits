#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 Jay Patel <patel.jay@dal.ca>.
#
# Licensed under the MIT License

import struct
import binascii
import io
import logging
from loguru import logger # as logging
import zlib
import json

# Constants
DEFAULT_BYTE_ORDER = '>'


# Set up logging configuration
logging.basicConfig(level=logging.INFO)


import struct
import binascii
import io
import logging
import json
import zlib
from loguru import logger

# Constants
DEFAULT_BYTE_ORDER = '>'


# Set up logging configuration
logging.basicConfig(level=logging.INFO)


class PDU:
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
    
    # Additional methods for other types
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

    def variable_length_array(self, name, value_type):
        self.fields.append(('variable_length_array', name, value_type))
        return self

    @staticmethod
    def compute_crc(data):
        crc = binascii.crc32(data) & 0xffffffff
        logging.info(f"Data for CRC: {data.hex()}, CRC: {crc}")
        return crc

    @logger.catch
    def encode(self, data, compress=False):
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
            elif field_type == 'filler':
                encoded_value = b'\x00' * value_to_encode
            elif field_type == 'padding':
                padding_length = self.pdu_length - len(encoded) - 4  # Subtract CRC length
                if padding_length > 0:
                    encoded_value = bytes([value]) * padding_length
                else:
                    encoded_value = b''
            elif field_type == 'fixed_string':
                encoded_value = struct.pack(f'{self.byte_order}{value}s', value_to_encode.encode('utf-8'))
            elif field_type == 'length_prefixed_string':
                encoded_value = struct.pack(self.byte_order + 'I', len(value_to_encode)) + value_to_encode.encode('utf-8')
            elif field_type == 'variable_length_array':
                encoded_value = struct.pack(self.byte_order + 'I', len(value_to_encode))
                for item in value_to_encode:
                    encoded_value += struct.pack(self.byte_order + {'uint8': 'B', 'int8': 'b', 'uint16': 'H', 'int16': 'h', 'uint32': 'I', 'int32': 'i', 'uint64': 'Q', 'int64': 'q', 'float': 'f', 'double': 'd'}[value], item)

            encoded.extend(encoded_value)
        
        # Compute CRC for the data without the CRC field itself
        data_for_crc = encoded
        crc = self.compute_crc(data_for_crc)
        encoded.extend(struct.pack(self.byte_order + 'I', crc))

        # Compress data if needed
        if compress:
            return zlib.compress(encoded)
        return bytes(encoded)

    @logger.catch
    def decode(self, data, decompress=False):
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
            if field_type == 'fixed_string':
                string_length = value
                decoded[name] = struct.unpack_from(f'{self.byte_order}{string_length}s', data, offset)[0].decode('utf-8').strip('\x00')
                offset += struct.calcsize(f'{self.byte_order}{string_length}s')
            elif field_type == 'length_prefixed_string':
                string_length = struct.unpack_from(self.byte_order + 'I', data, offset)[0]
                offset += struct.calcsize(self.byte_order + 'I')
                decoded[name] = struct.unpack_from(f'{self.byte_order}{string_length}s', data, offset)[0].decode('utf-8')
                offset += string_length
            elif field_type == 'variable_length_array':
                array_length = struct.unpack_from(self.byte_order + 'I', data, offset)[0]
                offset += struct.calcsize(self.byte_order + 'I')
                array_items = []
                for _ in range(array_length):
                    item, = struct.unpack_from(self.byte_order + format_map[value], data, offset)
                    array_items.append(item)
                    offset += struct.calcsize(self.byte_order + format_map[value])
                decoded[name] = array_items
            elif field_type in format_map:
                decoded[name], = struct.unpack_from(self.byte_order + format_map[field_type], data, offset)
                offset += struct.calcsize(format_map[field_type])
            elif field_type == 'filler':
                offset += value
            elif field_type == 'padding':
                break

        # Extract the CRC from the end of the data
        crc_expected = struct.unpack_from(self.byte_order + 'I', data, self.pdu_length - 4)[0]
        data_for_crc = data[:self.pdu_length - 4]  # Data excluding CRC
        crc_computed = self.compute_crc(data_for_crc)

        if crc_computed != crc_expected:
            raise ValueError(f"CRC mismatch: computed={crc_computed}, expected={crc_expected}")

        return decoded

    def to_json(self):
        return json.dumps({
            'length': self.pdu_length,
            'byte_order': 'big' if self.byte_order == '>' else 'little',
            'fields': self.fields
        })

    @staticmethod
    def from_json(json_str):
        data = json.loads(json_str)
        pdu = PDU().length(data['length']).order(data['byte_order'])
        for field in data['fields']:
            if field[0] == 'padding':
                pdu = getattr(pdu, field[0])(field[2])
            else:
                pdu = getattr(pdu, field[0])(*field[1:])
        return pdu
    
def create_pdu_format(length, byte_order, *fields):
    pdu = PDU().length(length).order(byte_order)
    for field in fields:
        pdu = getattr(pdu, field[0])(*field[1:])
    return pdu

# Usage example
# if __name__ == "__main__":
#     # Example for dynamic PDU format definition
#     my_pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2').padding(0xff)

#     # Encoding and decoding
#     encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28}, compress=True)
#     print(f"Encoded Bytes: {encoded_bytes}")

#     decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
#     print(f"Decoded Data: {decoded_data}")
    
#     # Serialization to JSON
#     json_str = my_pdu.to_json()
#     print(f"Serialized PDU to JSON:   {json_str}")

#     # Deserialization from JSON
#     new_pdu = PDU.from_json(json_str)
#     print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")
    
#     # Encoding and decoding using deserialized PDU
#     encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28}, compress=True)
#     print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")

#     decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
#     print(f"Decoded Data (new PDU): {decoded_data_new}")

#     """
#     INFO:root:Data for CRC: 074048f5c340191eb851eb851fffffffffffffff, CRC: 3703759078
#     Encoded Bytes: b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\xff\x10p\xe7\xd0\x83g\x00\x9d\xf7\x0f\xb4'
#     INFO:root:Data for CRC: 074048f5c340191eb851eb851fffffffffffffff, CRC: 3703759078
#     Decoded Data: {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28}
#     Serialized PDU to JSON:   {"length": 24, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["padding", null, 255]]}
#     Deserialized PDU from JSON: {"length": 24, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["padding", null, 255]]}
#     INFO:root:Data for CRC: 074048f5c340191eb851eb851fffffffffffffff, CRC: 3703759078
#     Encoded Bytes (new PDU): b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\xff\x10p\xe7\xd0\x83g\x00\x9d\xf7\x0f\xb4'
#     INFO:root:Data for CRC: 074048f5c340191eb851eb851fffffffffffffff, CRC: 3703759078
#     Decoded Data (new PDU): {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28}
#     """


# Usage example
if __name__ == "__main__":
    # Example for dynamic PDU format definition with various types of fields
    my_pdu = PDU().length(64).order('big') \
        .uint8('type') \
        .float('value1') \
        .double('value2') \
        .fixed_string('fixed_str', 10, default="default") \
        .length_prefixed_string('length_str', default="") \
        .variable_length_array('array', 'uint8') \
        .padding(0xff)

    # Encoding and decoding
    data_to_encode = {
        'type': 7,
        'value1': 3.14,
        'value2': 6.28,
        'fixed_str': "hello",
        'length_str': "dynamic string",
        'array': [1, 2, 3, 4, 5]
    }
    encoded_bytes = my_pdu.encode(data_to_encode, compress=True)
    print(f"Encoded Bytes: {encoded_bytes}")

    decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
    print(f"Decoded Data: {decoded_data}")

    # Serialization to JSON
    json_str = my_pdu.to_json()
    print(f"Serialized PDU to JSON: {json_str}")

    # Deserialization from JSON
    new_pdu = PDU.from_json(json_str)
    print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")

    # Encoding and decoding using deserialized PDU
    encoded_bytes_new = new_pdu.encode(data_to_encode, compress=True)
    print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")

    decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
    print(f"Decoded Data (new PDU): {decoded_data_new}")

    """
    INFO:root:Data for CRC: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffff, CRC: 3954678632
    Encoded Bytes: b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\x8c\xd4\x9c\x9c|\x06(\xe0K\xa9\xccK\xcc\xcdLV(.)\xca\xccK\x07\x8a\xb0221\xb3\xb0\xfe\x87\x83\xd7\xdbgg\x00\x00\xad\xe0\x19\xc4'
    INFO:root:Data for CRC: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffff, CRC: 3954678632
    Decoded Data: {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}
    Serialized PDU to JSON: {"length": 64, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["fixed_string", "fixed_str", 10], ["length_prefixed_string", "length_str", null], ["variable_length_array", "array", "uint8"], ["padding", null, 255]]}
    Deserialized PDU from JSON: {"length": 64, "byte_order": "big", "fields": [["uint8", "type", null], ["float", "value1", null], ["double", "value2", null], ["fixed_string", "fixed_str", 10], ["length_prefixed_string", "length_str", null], ["variable_length_array", "array", "uint8"], ["padding", null, 255]]}
    INFO:root:Data for CRC: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffff, CRC: 3954678632
    Encoded Bytes (new PDU): b'x\x9ccw\xf0\xf8z\xd8ARnG\xe0\xebV\xf9\x8c\xd4\x9c\x9c|\x06(\xe0K\xa9\xccK\xcc\xcdLV(.)\xca\xccK\x07\x8a\xb0221\xb3\xb0\xfe\x87\x83\xd7\xdbgg\x00\x00\xad\xe0\x19\xc4'
    INFO:root:Data for CRC: 074048f5c340191eb851eb851f68656c6c6f00000000000000000e64796e616d696320737472696e67000000050102030405ffffffffffffffffffff, CRC: 3954678632
    Decoded Data (new PDU): {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}
    """
