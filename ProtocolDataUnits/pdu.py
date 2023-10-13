#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2023 Jay Patel <patel.jay@dal.ca>.
#
# Licensed under the MIT License

import struct
import binascii
import io
import logging

# Constants
DEFAULT_BYTE_ORDER = '>'


# Set up logging configuration
logging.basicConfig(level=logging.INFO)


class PDU:
    """
    Represents a Protocol Data Unit (PDU).

    A Protocol Data Unit (PDU) is a single unit of data in communication networks.
    This class provides methods to encode and decode PDUs, compute CRC values,
    and manage nested PDUs.

    :type: int
    :param type: The type of the PDU.

    :duration: int
    :param duration: The duration or lifetime of the PDU.

    :payload: bytes
    :param payload: The actual data carried by the PDU.

    :nested_pdu: PDU
    :param nested_pdu: An optional nested PDU object.

    :byte_order: str
    :param byte_order: The byte order for encoding/decoding operations.

    :metadata: dict
    :param metadata: Additional metadata or information about the PDU.
    """

    """
    Represents a Protocol Data Unit (PDU).

    Attributes:
    - type (int): The type of the PDU.
    - duration (int): The duration of the PDU.
    - payload (bytes): The payload of the PDU.
    - nested_pdu (PDU): A nested PDU object.
    - byte_order (str): The byte order for encoding/decoding.
    - metadata (dict): Additional metadata for the PDU.
    """

    def __init__(self, type, duration, payload=None, nested_pdu=None, byte_order=DEFAULT_BYTE_ORDER, *args, **kwargs):
        """
        Initializes a new instance of the PDU class.

        :type: int
        :param type: The type of the PDU.

        :duration: int
        :param duration: The duration of the PDU.

        :payload: bytes, optional
        :param payload: The payload of the PDU. Defaults to empty bytes.

        :nested_pdu: PDU, optional
        :param nested_pdu: A nested PDU object. Defaults to None.

        :byte_order: str, optional
        :param byte_order: The byte order for encoding/decoding. Defaults to '>'.

        :return: None
        """

        self.type = type
        self.duration = duration
        self.payload = payload or b''
        self.nested_pdu = nested_pdu
        self.byte_order = byte_order
        self.metadata = {}  # Initialize the metadata attribute
        logging.info(
            f"Initialized PDU with type: {self.type}, duration: {self.duration}, payload: {self.payload}")

    @staticmethod
    def compute_crc(data):
        """
        Computes the CRC for the given data.

        :data: bytes
        :param data: The data for which the CRC needs to be computed.

        :return: int
        :rtype: The computed CRC value.
        """

        crc = binascii.crc32(data) & 0xffffffff
        logging.info(f"Data: {data.hex()}, CRC: {crc}")
        return crc

    def encode(self):
        "Encoding function"
        encoded = bytearray()
        encoded.append(self.type)
        encoded.extend(self.duration.to_bytes(
            2, byteorder='big' if self.byte_order == '>' else 'little'))
        encoded.extend(self.encode_variable_length_field(self.payload))
        logging.debug(f"Encoding Data for CRC: {encoded.hex()}")  # Debug print
        crc = self.compute_crc(encoded)
        logging.debug(f"Encode CRC: {crc}")  # Debug print
        encoded.extend(crc.to_bytes(4, byteorder='big' if self.byte_order ==
                       '>' else 'little'))  # Ensure 4 bytes for CRC
        return encoded

    @classmethod
    def decode(cls, encoded, byte_order=DEFAULT_BYTE_ORDER):
        "Decoding function"
        # Debug print: Full encoded data
        logging.debug(f"Full encoded data: {encoded.hex()}")

        type = encoded[0]
        duration = int.from_bytes(
            encoded[1:3], byteorder='big' if byte_order == '>' else 'little')
        payload, length_of_payload = cls.decode_variable_length_field(
            encoded[3:], byte_order)

        # The offset should include the type, duration, length of payload, and the actual payload
        offset = 1 + 2 + 2 + length_of_payload

        pdu = cls(type, duration, payload, None, byte_order)

        # Extract CRC from the encoded data
        # crc = int.from_bytes(
        #     encoded[offset:offset+4], byteorder='big' if byte_order == '>' else 'little')
        crc = int.from_bytes(encoded[-4:], byteorder='big')

        # Data for CRC calculation should be everything except the CRC itself
        data_for_crc = encoded[:offset-2]
        # Debug print
        logging.info(
            f"Data for CRC (length {len(data_for_crc)}): {data_for_crc.hex()}")

        computed_crc = cls.compute_crc(data_for_crc)
        logging.debug(f"Decoded payload length: {len(payload)}")
        logging.debug(f"Decoded payload: {payload.hex()}")
        logging.debug(f"Offset after decoding variable-length field: {offset}")
        logging.debug(
            f"Decode Computed CRC: {computed_crc}, Expected CRC: {crc}")
        if computed_crc != crc:
            raise ValueError(
                f"CRC mismatch: computed={computed_crc}, expected={crc}")
        return pdu

    def encode_variable_length_field(self, field):
        length = len(field)
        encoded = length.to_bytes(
            2, byteorder='big' if self.byte_order == '>' else 'little')
        encoded += field
        return encoded

    @classmethod
    def decode_variable_length_field(cls, encoded, byte_order):
        length = int.from_bytes(
            encoded[:2], byteorder='big' if byte_order == '>' else 'little')
        field = encoded[2:2 + length]
        return field, 2 + length

    def write_to_stream(self, stream):
        stream.write(self.encode())

    @classmethod
    def read_from_stream(cls, stream, byte_order=DEFAULT_BYTE_ORDER):
        return cls.decode(stream.read(), byte_order)

    # Additional utility methods
    def get_metadata(self, key):
        return self.metadata.get(key, None)

    def set_metadata(self, key, value):
        self.metadata[key] = value

    def __eq__(self, other):
        if not isinstance(other, PDU):
            return False
        return self.type == other.type and self.duration == other.duration and self.payload == other.payload

    def __repr__(self):
        return f"PDU(type={self.type}, duration={self.duration}, payload={self.payload})"


class PDUInfo:
    "PDUInfo"

    def __init__(self, length: int, metadata: dict):
        self.length = length
        self.metadata = metadata

    def __repr__(self):
        return f"PDUInfo(length={self.length}, metadata={self.metadata})"


class EthernetFrame(PDU):
    "EthernetFrame class"

    def __init__(self, dstaddr, srcaddr, ethtype, payload):
        self.dstaddr = dstaddr  # tuple of 6 bytes
        self.srcaddr = srcaddr  # tuple of 6 bytes
        self.ethtype = ethtype  # 2 bytes
        self.payload = payload  # variable length
        logging.info(f"Initialized payload: {self.payload}")  # Debug print
        # type and duration are dummy values
        super().__init__(type=0x00, duration=0, payload=payload)

    def __str__(self):
        return f"EthernetFrame(dstaddr={self.dstaddr}, srcaddr={self.srcaddr}, ethtype={self.ethtype}, payload={self.payload})"

    def encode(self):
        encoded = bytearray()
        encoded.extend(self.dstaddr)
        encoded.extend(self.srcaddr)
        encoded.extend(self.ethtype.to_bytes(2, byteorder='big'))
        encoded.extend(self.payload)
        # logging.info(f"Encoding before crc calculation - dstaddr: {self.dstaddr}, srcaddr: {self.srcaddr}, ethtype: {self.ethtype}, payload: {self.payload}")
        crc = self.compute_crc(encoded)
        encoded.extend(crc.to_bytes(4, byteorder='big'))
        # In encode method
        logging.info(
            f"Encoding - dstaddr: {self.dstaddr}, srcaddr: {self.srcaddr}, ethtype: {self.ethtype}, payload: {self.payload}, crc: {crc}")
        return encoded

    @classmethod
    def decode(cls, encoded):
        dstaddr = tuple(encoded[0:6])
        srcaddr = tuple(encoded[6:12])
        ethtype = int.from_bytes(encoded[12:14], byteorder='big')
        payload = encoded[14:-4]  # excluding CRC
        frame = cls(dstaddr, srcaddr, ethtype, payload)
        crc = int.from_bytes(encoded[-4:], byteorder='big')
        # In decode method
        logging.info(
            f"Decoding - dstaddr: {dstaddr}, srcaddr: {srcaddr}, ethtype: {ethtype}, payload: {payload}, crc: {crc}")
        if frame.compute_crc(encoded[:-4]) != crc:
            raise ValueError(
                f"CRC mismatch: computed={frame.compute_crc(encoded[:-4])}, expected={crc}")
        return frame
