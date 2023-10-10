from ProtocolDataUnits.pdu import PDU, EthernetFrame

# Testing the enhanced PDU class
def test_pdu():
    pdu = PDU(type=0x01, duration=500, payload=b'\x01\x02\x03\x04')
    encoded_pdu = pdu.encode()
    print(f"Encoded PDU: {encoded_pdu.hex()}")
    decoded = PDU.decode(encoded_pdu)
    print(f"Decoded PDU: {decoded}")
    assert pdu == decoded

    # Test metadata
    pdu_info = PDUInfo(length=4, metadata={
                       "source": "deviceA", "destination": "deviceB"})
    print(pdu_info)
    pdu.set_metadata("info", pdu_info)
    retrieved_info = pdu.get_metadata("info")
    print(f"Retrieved metadata: {retrieved_info}")


test_pdu()

# Testing the EthernetFrame class
def test_ethernet_frame():
    frame = EthernetFrame(
        dstaddr=(0x01, 0x02, 0x03, 0x04, 0x05, 0x06),
        srcaddr=(0x11, 0x12, 0x13, 0x14, 0x15, 0x16),
        ethtype=0x0800,
        payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                      0x07, 0x08])  # non-empty payload
    )

    # convert to a byte array
    encoded_bytes = frame.encode()
    print(f"encoded bytes: {encoded_bytes}")

    # convert back to Ethernet frame
    decoded = EthernetFrame.decode(encoded_bytes)
    print(f"decoded bytes: {decoded}")

    # check that they are the same
    assert frame.dstaddr == decoded.dstaddr
    assert frame.srcaddr == decoded.srcaddr
    assert frame.ethtype == decoded.ethtype
    assert frame.payload == decoded.payload


test_ethernet_frame()
