# scripts/demo.py

from ProtocolDataUnits.pdu import PDU, create_pdu_format

def main():
    print("===========")
    print("Basic Field Types Example")
    print("supports : uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double")
    print("===========")
    my_pdu = PDU().length(24).order('big').uint8('type').float('value1').double('value2')
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Fixed-Length Strings Example")
    print("===========")
    my_pdu = PDU().length(32).order('big').uint8('type').fixed_string('fixed_str', 10)
    encoded_bytes = my_pdu.encode({'type': 7, 'fixed_str': 'hello'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Length-Prefixed Strings Example")
    print("===========")
    my_pdu = PDU().length(40).order('big').uint8('type').length_prefixed_string('length_str')
    encoded_bytes = my_pdu.encode({'type': 7, 'length_str': 'dynamic string'})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Variable-Length Arrays Example")
    print("===========")
    my_pdu = PDU().length(48).order('big').uint8('type').variable_length_array('array', 'uint8')
    encoded_bytes = my_pdu.encode({'type': 7, 'array': [1, 2, 3, 4, 5]})
    decoded_data = my_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Nested PDU Example")
    print("===========")
    nested_pdu = PDU().length(8).order('big').uint8('nested_type').uint8('nested_value')
    main_pdu = PDU().length(16).order('big').uint8('type').nested_pdu('nested', nested_pdu)
    encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
    decoded_data = main_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Nested PDU Example Updated")
    print("===========")
    nested_pdu = PDU().length(8).order('big').uint8('nested_type').uint8('nested_value')
    main_pdu = PDU().length(16).order('big').uint8('type').pdu_fragment('nested', nested_pdu)
    encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
    decoded_data = main_pdu.decode(encoded_bytes)
    print(f"Encoded Bytes: {encoded_bytes}")
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    print("===========")
    print("Serialization and Deserialization Example")
    print("===========")
    my_pdu = PDU().length(68).order('big').uint8('type').float('value1').double('value2').fixed_string('fixed_str', 10).length_prefixed_string('length_str').variable_length_array('array', 'uint8').padding(0xff)
    encoded_bytes = my_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes: {encoded_bytes}")
    print("===========")

    decoded_data = my_pdu.decode(encoded_bytes, decompress=True)
    print(f"Decoded Data: {decoded_data}")
    print("===========")

    json_str = my_pdu.to_json()
    print(f"Serialized PDU to JSON: {json_str}")
    print("===========")

    new_pdu = PDU.from_json(json_str)
    print(f"Deserialized PDU from JSON: {new_pdu.to_json()}")
    print("===========")

    encoded_bytes_new = new_pdu.encode({'type': 7, 'value1': 3.14, 'value2': 6.28, 'fixed_str': 'hello', 'length_str': 'dynamic string', 'array': [1, 2, 3, 4, 5]}, compress=True)
    print(f"Encoded Bytes (new PDU): {encoded_bytes_new}")
    print("===========")

    decoded_data_new = new_pdu.decode(encoded_bytes_new, decompress=True)
    print(f"Decoded Data (new PDU): {decoded_data_new}")
    print("===========")

    print("===========")
    print("API Example")
    print("===========")
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

    encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
    print(f"Encoded Bytes: {encoded_bytes}")

    decoded_data = main_pdu.decode(encoded_bytes)
    print(f"Decoded Data: {decoded_data}")
    print("===========")

if __name__ == "__main__":
    main()
