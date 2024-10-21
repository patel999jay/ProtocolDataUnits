# pdu_examples.py

from ProtocolDataUnits.pdu import create_pdu_format, PDU

from loguru import logger

# Example for dynamic PDU format definition
logger.info("===========")
logger.info("Basic Field Types Example")
logger.info("supports : uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double")
logger.info("===========")
my_pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2')
encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
decoded_data = my_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Fixed-Length Strings Example")
logger.info("===========")
my_pdu = PDU().length(32).order('big').uint8('type').fixed_string('fixed_str', 10)
encoded_bytes = my_pdu.encode({'type': 7, 'fixed_str': 'hello'})
decoded_data = my_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Length-Prefixed Strings Example")
logger.info("===========")
my_pdu = PDU().length(40).order('big').uint8('type').length_prefixed_string('length_str')
encoded_bytes = my_pdu.encode({'type': 7, 'length_str': 'dynamic string'})
decoded_data = my_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Variable-Length Arrays Example")
logger.info("===========")
my_pdu = PDU().length(48).order('big').uint8('type').variable_length_array('array', 'uint8')
encoded_bytes = my_pdu.encode({'type': 7, 'array': [1, 2, 3, 4, 5]})
decoded_data = my_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Nested PDU Example")
logger.info("===========")
nested_pdu = PDU().length(8).order('big').uint8('nested_type').uint8('nested_value')
main_pdu = PDU().length(16).order('big').uint8('type').nested_pdu('nested', nested_pdu)
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
decoded_data = main_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Nested PDU Example Updated")
logger.info("===========")
pdu_fragment_pdu = PDU().length(8).order('big').uint8('nested_type').uint8('nested_value')
main_pdu = PDU().length(16).order('big').uint8('type').pdu_fragment('nested', pdu_fragment_pdu)
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
decoded_data = main_pdu.decode(encoded_bytes)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

logger.info("===========")
logger.info("Serialization and Deserialization Example")
logger.info("===========")
my_pdu = PDU().length(68).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)
encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
logger.info(f"Encoded Bytes: {encoded_bytes}")
logger.info("===========")

# Decode the PDU with decompression enabled.
decoded_data = my_pdu.decode(encoded_bytes, decompress=True) # decompress=True means that the input data will be decompressed using zlib before decoding.
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")

json_str = my_pdu.to_json()
logger.info(f"Serialized PDU to JSON: {json_str}")
logger.info("===========")

new_pdu = PDU.from_json(json_str)
logger.info(f"Deserialized PDU from JSON: {new_pdu.to_json()}")
logger.info("===========")

# Encode the data into PDU format with compression enabled.
encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True) # compress=True means that the encoded data will be compressed using zlib before returning.
logger.info(f"Encoded Bytes (new PDU): {encoded_bytes_new}")
logger.info("===========")

decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
logger.info(f"Decoded Data (new PDU): {decoded_data_new}")
logger.info("===========")

logger.info("===========")
logger.info("API Example")
logger.info("===========")

# Create a PDU format with various fields
my_pdu_format = create_pdu_format(
    48, 'big',
    ('uint8', 'type'),
    ('float', 'value1'),
    ('double', 'value2'),
    ('fixed_string', 'fixed_str', 10),
    ('length_prefixed_string', 'length_str'),
    ('variable_length_array', 'array', 'uint8'),
    ('padding', 0xff)
)

# Nested PDU example
nested_pdu = create_pdu_format(
    8, 'big',
    ('uint8', 'nested_type'),
    ('uint8', 'nested_value')
)

main_pdu = create_pdu_format(
    16, 'big',
    ('uint8', 'type'),
    ('nested_pdu', 'nested', nested_pdu)
)

# Encode data
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
logger.info(f"Encoded Bytes: {encoded_bytes}")

# Decode data
decoded_data = main_pdu.decode(encoded_bytes)
logger.info(f"Decoded Data: {decoded_data}")
logger.info("===========")
