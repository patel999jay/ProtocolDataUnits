#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 Jay Patel <patel.jay@dal.ca>.
#
# Licensed under the MIT License

import struct
import binascii
import io
import logging
from loguru import logger # pip install loguru
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

    @staticmethod
    def compute_crc(data):
        crc = binascii.crc32(data) & 0xffffffff
        logging.info(f"Data for CRC32: {data.hex()}, CRC32: {crc}")
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
            if field_name in ['fixed_string', 'variable_length_array']:
                pdu = getattr(pdu, field_name)(*field_args)
            elif field_name == 'padding':
                pdu = pdu.padding(field_args[1])
            else:
                if len(field_args) == 3:
                    pdu = getattr(pdu, field_name)(*field_args[:2], default=field_args[2])
                else:
                    pdu = getattr(pdu, field_name)(*field_args)
        return pdu

# Usage example
if __name__ == "__main__":
    # Example for dynamic PDU format definition
    print("===========")
    print("Basic Field Types Example")
    print("supports : uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double")
    print("===========")
    my_pdu = PDU().length(24 + 4).order('big').uint8('type').float('value1').double('value2')  # Adding 4 bytes for CRC
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Fixed-Length Strings Example")
    print("===========")
    my_pdu = PDU().length(32 + 4).order('big').uint8('type').fixed_string('fixed_str', 10)  # Adding 4 bytes for CRC
    encoded_bytes = my_pdu.encode({'type': 7, 'fixed_str': 'hello'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Length-Prefixed Strings Example")
    print("===========")
    my_pdu = PDU().length(40 + 4).order('big').uint8('type').length_prefixed_string('length_str')  # Adding 4 bytes for CRC
    encoded_bytes = my_pdu.encode({'type': 7, 'length_str': 'dynamic string'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Variable-Length Arrays Example")
    print("===========")
    my_pdu = PDU().length(48 + 4).order('big').uint8('type').variable_length_array('array', 'uint8')  # Adding 4 bytes for CRC
    encoded_bytes = my_pdu.encode({'type': 7, 'array': [1, 2, 3, 4, 5]})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Serialization and Deserialization Example")
    print("===========")
    my_pdu = PDU().length(64 + 4).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)  # Adding 4 bytes for CRC
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes: {encoded_bytes}")

    decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
    print(f"Decoded Data: {decoded_data}")

    json_str = my_pdu.to_json()
    print(f"Serialized PDU to JSON:   {json_str}")

    new_pdu = PDU.from_json(json_str)
    print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")

    encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")

    decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
    print(f"Decoded Data (new PDU): {decoded_data_new}")
