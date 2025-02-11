# ProtocolDataUnits

[![Documentation](https://readthedocs.org/projects/protocoldataunits/badge/?version=latest)](https://protocoldataunits.readthedocs.io/en/latest/?badge=latest)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.png?v=103)](https://github.com/ellerbrock/open-source-badges/)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)

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
- **Nested PDU / PDU_FRAGMENT Support**: Supports PDUs within PDUs, allowing for complex data structures.
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

You can create PDU formats using the user-friendly API, defining the structure, encoding data into binary format, and decoding it back into structured data.

```python
from ProtocolDataUnits.pdu import create_pdu_format, PDU

# Create a simple PDU format with uint8, float, and double fields
my_pdu_format = create_pdu_format(
    24, 'big',  # Total length: 24 bytes, big-endian order
    ('uint8', 'type'),  # 1 byte
    ('float', 'value1'),  # 4 bytes
    ('double', 'value2')  # 8 bytes
)

# Encode data into binary format
encoded_bytes = my_pdu_format.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
print(f"Encoded Bytes: {encoded_bytes}")

# Decode binary data back into structured format
decoded_data = my_pdu_format.decode(encoded_bytes)
print(f"Decoded Data: {decoded_data}")
```

### Working with Nested PDUs

Nested PDUs allow you to embed one PDU structure within another, enabling more complex data structures.

```python
# Define a nested PDU format
nested_pdu = create_pdu_format(
    8, 'big',  # Length: 8 bytes, big-endian order
    ('uint8', 'nested_type'),  # 1 byte
    ('uint8', 'nested_value')  # 1 byte
)

# Define the main PDU format containing the nested PDU
main_pdu = create_pdu_format(
    16, 'big',  # Length: 16 bytes, big-endian order
    ('uint8', 'type'),  # 1 byte
    ('pdu_fragment', 'nested', nested_pdu)  # Nested PDU takes up 8 bytes
)

# Encode data with nested PDU
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
print(f"Encoded Bytes: {encoded_bytes}")

# Decode data with nested PDU
decoded_data = main_pdu.decode(encoded_bytes)
print(f"Decoded Data: {decoded_data}")
```

### Serialization and Deserialization

You can serialize a PDU's structure to JSON, allowing you to save and reload PDU definitions, making it easy to share PDU formats or store them for later use.

```python
# Create a complex PDU with various field types
my_pdu = PDU().length(68).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)

# Encode data into the PDU format
encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
print(f"Encoded Bytes: {encoded_bytes}")

# Decode the PDU back into structured data
decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
print(f"Decoded Data: {decoded_data}")

# Serialize the PDU definition to JSON
json_str = my_pdu.to_json()
print(f"Serialized PDU to JSON: {json_str}")

# Deserialize the PDU from JSON
new_pdu = PDU.from_json(json_str)
print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")

# Encode and decode using the deserialized PDU
encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")

decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
print(f"Decoded Data (new PDU): {decoded_data_new}")
```

### Advanced Example: API Usage

```python
# Create a PDU format with various fields using the API
my_pdu_format = create_pdu_format(
    48, 'big',  # Length: 48 bytes, big-endian order
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
    ('pdu_fragment', 'nested', nested_pdu)
)

# Encode data
encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
print(f"Encoded Bytes: {encoded_bytes}")

# Decode data
decoded_data = main_pdu.decode(encoded_bytes)
print(f"Decoded Data: {decoded_data}")
```

### Notes
- **Compression and Decompression**: Using `compress=True` in `encode()` will compress the resulting byte array with zlib, reducing size. Use `decompress=True` in `decode()` to decode compressed data.
- **Serialization**: Convert your PDU definitions to JSON for easy saving and sharing of structures.
- **Flexible Field Types**: Supports integers, floats, fixed-length strings, length-prefixed strings, arrays, nested PDUs, and more.

## Data Encoding Details

The `ProtocolDataUnits` library provides support for various types of data, including fixed-length strings, length-prefixed strings, and variable-length arrays. Below is an explanation of how each of these types is encoded:

### 1. Fixed-Length Strings

A fixed-length string is encoded as a byte sequence of a specified length. If the string provided is shorter than the specified length, it is padded with null bytes (`\x00`). If the string is longer, it is truncated to fit the specified length.

- **Field Definition**: `fixed_string('name', length=10)`
- **Example**:
  - Input: `"hello"` (5 characters)
  - Length: `10`
  - Encoded: `b'hello\x00\x00\x00\x00\x00'` (5 characters plus 5 null bytes)
  - If the input was `"helloworld!!!"`, only `b'helloworld'` (10 characters) would be encoded.

### 2. Length-Prefixed Strings

A length-prefixed string is encoded as an integer representing the length of the string, followed by the string data itself. The length is typically stored as a 4-byte unsigned integer (`uint32`), allowing strings up to 2^32 - 1 bytes.

- **Field Definition**: `length_prefixed_string('name')`
- **Example**:
  - Input: `"dynamic string"`
  - Encoded: `b'\x0e\x00\x00\x00dynamic string'`
    - `b'\x0e\x00\x00\x00'` represents the length `14` (0x0e in hexadecimal) as a 4-byte integer.
    - `b'dynamic string'` is the actual string data.
  
  This encoding ensures that the length of the string is known during decoding, making it possible to handle strings of varying lengths.

### 3. Variable-Length Arrays

A variable-length array is encoded similarly to length-prefixed strings. The array is prefixed with a 4-byte integer (`uint32`) that indicates the number of elements in the array, followed by the serialized form of each element.

- **Field Definition**: `variable_length_array('name', element_type='uint8')`
- **Example**:
  - Input: `[1, 2, 3, 4, 5]` (an array of `uint8`)
  - Encoded: `b'\x05\x00\x00\x00\x01\x02\x03\x04\x05'`
    - `b'\x05\x00\x00\x00'` represents the length `5` as a 4-byte integer.
    - `b'\x01\x02\x03\x04\x05'` contains the array elements encoded as `uint8` values.

  Each element of the array is encoded according to the specified `element_type`. For instance, if the array type is `uint16`, each element would occupy 2 bytes.

### 4. Padding

Padding is used to align data to a specific byte boundary or to ensure that the PDU reaches a predefined length. Padding bytes are usually filled with a specific value (often zero or a user-defined value).

- **Field Definition**: `padding(value=0xff)`
- **Example**:
  - If 4 bytes of padding are needed, the encoded value might be `b'\xff\xff\xff\xff'` when `value=0xff`.

### Summary Table

| Field Type                  | Prefix/Length | Data Format                          | Example (in bytes)                               |
|-----------------------------|---------------|--------------------------------------|--------------------------------------------------|
| Fixed-Length String         | None          | Data padded or truncated to length   | `b'hello\x00\x00\x00\x00\x00'` (length 10)       |
| Length-Prefixed String      | 4 bytes       | Length + Data                        | `b'\x0e\x00\x00\x00dynamic string'` (length 14)  |
| Variable-Length Array       | 4 bytes       | Length + Element Data                | `b'\x05\x00\x00\x00\x01\x02\x03\x04\x05'`        |
| Padding                     | None          | Repeated value bytes                 | `b'\xff\xff\xff\xff'`                            |

### Additional Notes
- The use of length prefixes allows the decoder to know precisely how many bytes to read for a string or an array, making variable-length fields easier to handle.
- For large arrays or strings, consider the impact of storing length prefixes as `uint32` (4 bytes), as they slightly increase the size of the encoded data.
- Padding ensures data alignment but may add extra bytes to the encoded PDU.


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## References:
1. [ProtocolDataUnits.jl](https://github.com/org-arl/ProtocolDataUnits.jl.git) by [Dr. Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl)
