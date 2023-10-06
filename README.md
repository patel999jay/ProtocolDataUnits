# ProtocolDataUnits

ProtocolDataUnits is a Python toolset for encoding and decoding Protocol Data Units (PDUs), It is inspired by the `ProtocolDataUnits.jl` by [Dr Mandar Chitre](https://github.com/mchitre), [ARL](https://github.com/org-arl).

## Installation

You can install ProtocolDataUnits using pip:
```
pip install . # pip install ProtocolDataUnits
```

## Features

Here's a comparison of the functionalities between the `Julia` package and this `Python` package:

### Comparison Table

| Functionality                                | ProtocolDataUnits.jl (Julia) | ProtocolDataUnits (Python) |
|----------------------------------------------|:----------------------------:|:--------------------------:|
| Base PDU Definition                          |              TBD              |             ✔️             |
| PDU Encoding/Decoding                        |              TBD              |             ✔️             |
| Nested PDU Support                           |              TBD              |             ❌             |
| CRC32 Checksum                               |              TBD              |             ✔️             |
| Field Encoding/Decoding                      |              TBD              |             ✔️             |
| Byte Order Conversion                        |              TBD              |             ✔️             |
| Bit-level Utility Functions                  |              TBD              |             ❌             |
| Custom Exceptions                            |              TBD              |             ❌             |
| Ethernet Frame (or other specific PDU types) |              TBD              |             ✔️             |
| Metadata Storage                             |              TBD              |             ✔️             |
| Stream Writing/Reading                       |              TBD              |             ✔️             |
| Variable Length Encoding/Decoding            |              TBD              |             ✔️             |
| Pretty Printing of PDUs                      |              TBD              |             ❌             |
| PDU Equality based on Fields                 |              TBD              |             ✔️             |
| Decoding with Specified Number of Bytes      |              TBD              |             ❌             |

### Functionality Table

| Feature/Aspect                  | ProtocolDataUnits.jl (Julia)     | PDU (Python)                         |
|--------------------------------|----------------------------------|--------------------------------------|
| Basic Functionality            |                                  |                                      |
| Encoding PDUs                  | Yes                              | Yes                                  |
| Decoding PDUs                  | Yes                              | Yes                                  |
| CRC Support                    | Yes                              | Yes                                  |
| PDU Specifics                  |                                  |                                      |
| Ethernet Frame                 | Yes                              | Yes (via EthernetFrame class)        |
| Nested PDUs                    | Not Explicitly Mentioned         | Designed but not implemented         |
| Byte Order Flexibility         | Yes (BIG_ENDIAN, LITTLE_ENDIAN)  | Yes                                  |
| Variable Length Payload        | Yes                              | Yes                                  |
| Additional Features            |                                  |                                      |
| Pretty Printing                | Yes                              | Via __repr__ method                  |
| Metadata Support               | Through PDUInfo                  | Yes, via metadata attribute          |

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
