import unittest
from ProtocolDataUnits.pdu import PDU, create_pdu_format

class TestPDU(unittest.TestCase):
    def test_basic_types(self):
        pdu = create_pdu_format(24, 'big', ('uint8', 'type'), ('float', 'value1'), ('double', 'value2'))
        data = {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28}
        encoded = pdu.encode(data)
        decoded = pdu.decode(encoded)
        self.assertEqual(data, decoded)
    
    def test_fixed_string(self):
        pdu = create_pdu_format(32, 'big', ('uint8', 'type'), ('fixed_string', 'fixed_str', 10))
        data = {'type': 7, 'fixed_str': 'hello'}
        encoded = pdu.encode(data)
        decoded = pdu.decode(encoded)
        self.assertEqual(data, decoded)
    
    def test_length_prefixed_string(self):
        pdu = create_pdu_format(40, 'big', ('uint8', 'type'), ('length_prefixed_string', 'length_str'))
        data = {'type': 7, 'length_str': 'dynamic string'}
        encoded = pdu.encode(data)
        decoded = pdu.decode(encoded)
        self.assertEqual(data, decoded)
    
    def test_variable_length_array(self):
        pdu = create_pdu_format(48, 'big', ('uint8', 'type'), ('variable_length_array', 'array', 'uint8'))
        data = {'type': 7, 'array': [1, 2, 3, 4, 5]}
        encoded = pdu.encode(data)
        decoded = pdu.decode(encoded)
        self.assertEqual(data, decoded)
    
    def test_nested_pdu(self):
        nested_pdu = create_pdu_format(8, 'big', ('uint8', 'nested_type'), ('uint8', 'nested_value'))
        main_pdu = create_pdu_format(16, 'big', ('uint8', 'type'), ('nested_pdu', 'nested', nested_pdu))
        data = {'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}}
        encoded = main_pdu.encode(data)
        decoded = main_pdu.decode(encoded)
        self.assertEqual(data, decoded)
    
    def test_compression(self):
        pdu = create_pdu_format(68, 'big', ('uint8', 'type'), ('float', 'value1'), ('double', 'value2'), 
                                ('fixed_string', 'fixed_str', 10), ('length_prefixed_string', 'length_str'), 
                                ('variable_length_array', 'array', 'uint8'), ('padding', 0xff))
        data = {'type': 7, 'value1': 3.140000104904175, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}
        encoded = pdu.encode(data, compress=True)
        decoded = pdu.decode(encoded, decompress=True)
        self.assertEqual(data, decoded)

    def test_json_serialization(self):
        pdu = create_pdu_format(68, 'big', ('uint8', 'type'), ('float', 'value1'), ('double', 'value2'), 
                                ('fixed_string', 'fixed_str', 10), ('length_prefixed_string', 'length_str'), 
                                ('variable_length_array', 'array', 'uint8'), ('padding', 0xff))
        json_str = pdu.to_json()
        new_pdu = PDU.from_json(json_str)
        self.assertEqual(pdu.fields, new_pdu.fields)
        self.assertEqual(pdu.byte_order, new_pdu.byte_order)
        self.assertEqual(pdu.pdu_length, new_pdu.pdu_length)

if __name__ == '__main__':
    unittest.main()
