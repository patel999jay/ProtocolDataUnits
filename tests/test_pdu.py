from ProtocolDataUnits.pdu import PDU, create_pdu_format
import unittest
import struct

class TestPDU(unittest.TestCase):
    def setUp(self):
        self.pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2').padding(0xff)

    def test_encode(self):
        encoded_bytes = self.pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
        expected_bytes = b'\x07' + struct.pack('>f', 3.14) + struct.pack('>d', 6.28) + b'\xff' * 7
        self.assertEqual(encoded_bytes[:-4], expected_bytes)  # Compare data except CRC

    def test_decode(self):
        encoded_bytes = self.pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
        decoded_data = self.pdu.decode(encoded_bytes)
        expected_data = {'type': 7, 'value1': 3.14, 'value2': 6.28}
        self.assertEqual(decoded_data['type'], expected_data['type'])
        self.assertAlmostEqual(decoded_data['value1'], expected_data['value1'], places=5)
        self.assertAlmostEqual(decoded_data['value2'], expected_data['value2'], places=5)

    def test_crc_check(self):
        encoded_bytes = self.pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
        computed_crc = PDU.compute_crc(encoded_bytes[:-4])
        expected_crc = int.from_bytes(encoded_bytes[-4:], byteorder='big')
        self.assertEqual(computed_crc, expected_crc)


    def test_invalid_crc(self):
        encoded_bytes = self.pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
        # Manually modify the CRC to an incorrect value
        modified_bytes = bytearray(encoded_bytes)
        modified_bytes[-1] = 0x00  # Change last byte of CRC
        with self.assertRaises(ValueError):
            self.pdu.decode(bytes(modified_bytes))

    def test_create_pdu_format(self):
        fields = [
            ('uint8', 'type'),
            ('float', 'value1'),
            ('double', 'value2'),
            ('padding', 0xff)
        ]
        dynamic_pdu = create_pdu_format(24, 'big', *fields)
        encoded_bytes = dynamic_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
        decoded_data = dynamic_pdu.decode(encoded_bytes)
        expected_data = {'type': 7, 'value1': 3.14, 'value2': 6.28}
        self.assertEqual(decoded_data['type'], expected_data['type'])
        self.assertAlmostEqual(decoded_data['value1'], expected_data['value1'], places=5)
        self.assertAlmostEqual(decoded_data['value2'], expected_data['value2'], places=5)

if __name__ == '__main__':
    unittest.main()
