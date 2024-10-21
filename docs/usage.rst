Usage
=====

This section provides examples of how to use the ProtocolDataUnits library for encoding and decoding PDUs.

Basic Usage
=========================

**Creating a PDU Format**

You can create PDU formats using the user-friendly API, defining the structure, encoding data into binary format, and decoding it back into structured data.

.. code-block:: python

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

**Working with Nested / PDU_FRAGMENT PDUs**

Nested PDUs allow you to embed one PDU structure within another, enabling more complex data structures.

.. code-block:: python

    # Define a nested PDU format
    pdu_fragment_pdu = create_pdu_format(
        8, 'big',  # Length: 8 bytes, big-endian order
        ('uint8', 'nested_type'),  # 1 byte
        ('uint8', 'nested_value')  # 1 byte
    )

    # Define the main PDU format containing the nested PDU
    main_pdu = create_pdu_format(
        16, 'big',  # Length: 16 bytes, big-endian order
        ('uint8', 'type'),  # 1 byte
        ('pdu_fragment', 'nested', pdu_fragment_pdu)  # Nested PDU takes up 8 bytes
    )

    # Encode data with nested PDU
    encoded_bytes = main_pdu.encode({'type': 7, 'nested': {'nested_type': 1, 'nested_value': 2}})
    print(f"Encoded Bytes: {encoded_bytes}")

    # Decode data with nested PDU
    decoded_data = main_pdu.decode(encoded_bytes)
    print(f"Decoded Data: {decoded_data}")

**Serialization and Deserialization**

You can serialize a PDU's structure to JSON, allowing you to save and reload PDU definitions, making it easy to share PDU formats or store them for later use.

.. code-block:: python

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

**Advanced Usage**

For more advanced examples and detailed explanations, please refer to the `examples` directory or visit the API reference.


