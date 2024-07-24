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

    @staticmethod
    def compute_crc(data):
        crc = binascii.crc32(data) & 0xffffffff
        logging.info(f"Data for CRC: {data.hex()}, CRC: {crc}")
        return crc

    @logger.catch
    def encode(self, data):
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
            
            encoded.extend(encoded_value)
        
        # Compute CRC for the data without the CRC field itself
        data_for_crc = encoded
        crc = self.compute_crc(data_for_crc)
        encoded.extend(struct.pack(self.byte_order + 'I', crc))
        return bytes(encoded)

    @logger.catch
    def decode(self, data):
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

        # Extract the CRC from the end of the data
        crc_expected = struct.unpack_from(self.byte_order + 'I', data, self.pdu_length - 4)[0]
        data_for_crc = data[:self.pdu_length - 4]  # Data excluding CRC
        crc_computed = self.compute_crc(data_for_crc)

        if crc_computed != crc_expected:
            raise ValueError(f"CRC mismatch: computed={crc_computed}, expected={crc_expected}")

        return decoded

def create_pdu_format(length, byte_order, *fields):
    pdu = PDU().length(length).order(byte_order)
    for field in fields:
        pdu = getattr(pdu, field[0])(*field[1:])
    return pdu

# Usage example
if __name__ == "__main__":
    # Example for dynamic PDU format definition
    my_pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2').padding(0xff)

    # Encoding and decoding
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
    print(f"Encoded Bytes: {encoded_bytes}")

    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Decoded Data: {decoded_data}")

