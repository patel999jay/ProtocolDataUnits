# ProtocolDataUnits

[![Documentation](https://readthedocs.org/projects/protocoldataunits/badge/?version=latest)](https://protocoldataunits.readthedocs.io/en/latest/?badge=latest)

ProtocolDataUnits is a Python toolset for encoding and decoding Protocol Data Units (PDUs). It is inspired by `ProtocolDataUnits.jl` by [Dr. Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl).

## Installation

You can install ProtocolDataUnits using pip:
```
pip install . # pip install ProtocolDataUnits
```

## Features

`ProtocolDataUnits` is a Python toolset for encoding and decoding Protocol Data Units (PDUs). It includes the following features:

- **Base PDU Definition**: Define the structure and format of your PDUs.
- **PDU Encoding/Decoding**: Encode and decode PDUs with various field types.
- **Nested PDU Support**: Supports PDUs within PDUs, allowing for complex data structures.
- **CRC32 Checksum**: Automatically compute and validate CRC32 checksums for data integrity.
- **Field Encoding/Decoding**: Supports a variety of field types including integers, floats, strings, and arrays.
- **Byte Order Conversion**: Flexibly handle big-endian and little-endian byte orders.
- **Metadata Storage**: Store additional metadata within PDUs.
- **Stream Writing/Reading**: Efficiently write and read PDUs to and from streams.
- **Variable Length Encoding/Decoding**: Handle fields with variable length data.
- **Pretty Printing of PDUs**: Generate human-readable representations of PDUs.
- **PDU Equality based on Fields**: Compare PDUs based on their field values.
- **Serialization and Deserialization**: Serialize PDU definitions to JSON and deserialize them back to PDU objects.

## Usage

### Creating PDU Formats

You can create PDU formats using the user-friendly API:

```python
from ProtocolDataUnits.pdu import create_pdu_format, PDU

# Create a simple PDU format
my_pdu_format = create_pdu_format(
    24, 'big',
    ('uint8', 'type'),
    ('float', 'value1'),
    ('double', 'value2')
)

# Encode data
encoded_bytes = my_pdu_format.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
print(f"Encoded Bytes: {encoded_bytes}")

# Decode data
decoded_data = my_pdu_format.decode(encoded_bytes)
print(f"Decoded Data: {decoded_data}")
```

### Nested PDU Example

```python
# Define a nested PDU format
nested_pdu = create_pdu_format(
    8, 'big',
    ('uint8', 'nested_type'),
    ('uint8', 'nested_value')
)

# Define the main PDU format containing the nested PDU
main_pdu = create_pdu_format(
    16, 'big',
    ('uint8', 'type'),
    ('nested_pdu', 'nested', nested_pdu)
)

# Encode data with nested PDU
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
print(f"Encoded Bytes: {encoded_bytes}")

# Decode data with nested PDU
decoded_data = main_pdu.decode(encoded_bytes)
print(f"Decoded Data: {decoded_data}")
```

### Serialization and Deserialization

```python
# Create a PDU with various field types
my_pdu = PDU().length(68).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)
encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
print(f"Encoded Bytes: {encoded_bytes}")

# Decode the PDU
decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
print(f"Decoded Data: {decoded_data}")

# Serialize to JSON
json_str = my_pdu.to_json()
print(f"Serialized PDU to JSON: {json_str}")

# Deserialize from JSON
new_pdu = PDU.from_json(json_str)
print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")

# Encode and decode using the deserialized PDU
encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")

decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
print(f"Decoded Data (new PDU): {decoded_data_new}")
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## References:
1. [ProtocolDataUnits.jl](https://github.com/org-arl/ProtocolDataUnits.jl.git) by [Dr. Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl)
