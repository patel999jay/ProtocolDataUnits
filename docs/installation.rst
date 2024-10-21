Installation
============

ProtocolDataUnits is a Python library for encoding and decoding Protocol Data Units (PDUs). This guide will walk you through installing the package.

Prerequisites
============

- Python 3.7 or higher.
- pip (Python's package manager).

Installation with pip
=====================

To install `ProtocolDataUnits`, navigate to the directory containing `setup.py` and run:

.. code-block:: python

    git clone https://github.com/patel999jay/ProtocolDataUnits.git
    cd ProtocolDataUnits
    pip install .

Alternatively, you can install it directly from the repository:

.. code-block:: python

    pip install git+https://github.com/patel999jay/ProtocolDataUnits.git

Development Installation
=========================

If you wish to contribute to the development of ProtocolDataUnits, you can clone the repository and install it in `editable` mode:

.. code-block:: python

    git clone https://github.com/patel999jay/ProtocolDataUnits.git
    cd ProtocolDataUnits
    pip install -e .

This allows you to make changes to the code and immediately see those changes when you use the library.

Verifying the Installation
=========================

To verify that the installation was successful, run the following command in your Python environment:

.. code-block:: python

    import ProtocolDataUnits
    print(ProtocolDataUnits.__version__)

If the version number is displayed without any errors, the installation was successful.
