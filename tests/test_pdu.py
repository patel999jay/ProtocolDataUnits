from ProtocolDataUnits.pdu import PDU, EthernetFrame
import logging

# Configuring logging for the tests
logging.basicConfig(level=logging.DEBUG)


def test_pdu_encoding_decoding():
    pdu = PDU(type=0x01, duration=500, payload=b'\x01\x02\x03\x04')
    encoded_pdu = pdu.encode()
    logging.debug(f"Encoded PDU: {encoded_pdu.hex()}")
    decoded = PDU.decode(encoded_pdu)
    logging.debug(f"Decoded PDU: {decoded}")
    assert pdu == decoded, "Encoded and decoded PDU should be equal"


def test_pdu_metadata():
    pdu = PDU(type=0x01, duration=500, payload=b'\x01\x02\x03\x04')
    pdu_info = PDUInfo(length=4, metadata={
                       "source": "deviceA", "destination": "deviceB"})
    logging.debug(pdu_info)
    pdu.set_metadata("info", pdu_info)
    retrieved_info = pdu.get_metadata("info")
    logging.debug(f"Retrieved metadata: {retrieved_info}")
    assert pdu_info == retrieved_info, "Metadata set and retrieved should be equal"


def test_ethernet_frame_encoding_decoding():
    frame = EthernetFrame(
        dstaddr=(0x01, 0x02, 0x03, 0x04, 0x05, 0x06),
        srcaddr=(0x11, 0x12, 0x13, 0x14, 0x15, 0x16),
        ethtype=0x0800,
        payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    )

    # Convert to a byte array
    encoded_bytes = frame.encode()
    logging.debug(f"encoded bytes: {encoded_bytes}")

    # Convert back to Ethernet frame
    decoded = EthernetFrame.decode(encoded_bytes)
    logging.debug(f"decoded bytes: {decoded}")

    # Check that they are the same
    assert frame.dstaddr == decoded.dstaddr, "Destination address should be equal"
    assert frame.srcaddr == decoded.srcaddr, "Source address should be equal"
    assert frame.ethtype == decoded.ethtype, "Ethernet type should be equal"
    assert frame.payload == decoded.payload, "Payloads should be equal"


if __name__ == "__main__":
    test_pdu_encoding_decoding()
    test_pdu_metadata()
    test_ethernet_frame_encoding_decoding()
