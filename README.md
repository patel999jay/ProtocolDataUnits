# ProtocolDataUnits

ProtocolDataUnits is a Python toolset for encoding and decoding Protocol Data Units (PDUs), It is inspired by the `ProtocolDataUnits.jl` by [Dr Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl).

## Installation

You can install ProtocolDataUnits using pip:
```
pip install ProtocolDataUnits
```

## Features

Here's a comparison of the functionalities between the `Julia` package and this `Python` package:

### Comparison Table

| Functionality                                | Julia Package | Python Class |
|----------------------------------------------|:-------------:|:------------:|
| Base PDU Definition                          |       ✔️      |      ✔️      |
| PDU Encoding/Decoding                        |       ✔️      |      ✔️      |
| Nested PDU Support                           |       ✔️      |      ✔️      |
| CRC32 Checksum                               |       ✔️      |      ✔️      |
| Field Encoding/Decoding                      |       ✔️      |      ✔️      |
| Byte Order Conversion                        |       ✔️      |      ❌      |
| Bit-level Utility Functions                  |       ✔️      |      ❌      |
| Custom Exceptions                            |       ✔️      |      ❌      |
| Ethernet Frame (or other specific PDU types) |       ❌      |      ✔️      |

### Functionality Table

| Feature/Aspect                  | Julia Package                        | Python Package                        |
|--------------------------------|--------------------------------------|--------------------------------------|
| Language                       | Julia                                | Python                               |
| CRC Computation                | Built-in CRC32 functionality         | Uses binascii.crc32                  |
| Byte Order Configurability     | Yes (via hton and ntoh functions)    | Yes (via byte_order parameter)       |
| Encoding                       | Uses built-in IOBuffer               | Uses bytearray and to_bytes          |
| Decoding                       | Uses built-in IOBuffer               | Uses bytearray and from_bytes        |
| Nested PDU                     | Supported (with recursion)           | Placeholder (no recursion)           |
| Metadata Storage               | Not Present                          | Yes (via metadata dictionary)        |
| Stream Writing/Reading         | Supported via write and read         | Supported via write_to_stream and read_from_stream |
| Variable Length Field          | Supported                            | Supported                            |
| CRC Verification               | Supported                            | Supported                            |

## Usage

```python
from ProtocolDataUnits.pdu import PDU, EthernetFrame

# Create a PDU
pdu = PDU(type=0x01, duration=500, payload=b'\x01\x02\x03\x04')
encoded_pdu = pdu.encode()
decoded_pdu = PDU.decode(encoded_pdu)

# Create an Ethernet Frame
frame = EthernetFrame(
    dstaddr=(0x01, 0x02, 0x03, 0x04, 0x05, 0x06),
    srcaddr=(0x11, 0x12, 0x13, 0x14, 0x15, 0x16),
    ethtype=0x0800,
    payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
)
encoded_frame = frame.encode()
decoded_frame = EthernetFrame.decode(encoded_frame)
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## References:
1. [ProtocolDataUnits.jl](https://github.com/org-arl/ProtocolDataUnits.jl.git) by [Dr Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl)
