#
# Copyright (C) 2015-2016 The bitcoin-blockchain-parser developers
#
# This file is part of bitcoin-blockchain-parser.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of bitcoin-blockchain-parser, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.
#
""" This module contains utility functions used throughout the parser. """
import hashlib
import struct

from typing import List, Tuple
from ._types import ReadableBuffer


# Hash algorithms
def ripemd160(data: ReadableBuffer) -> bytes:
    """ Returns a RIPEMD160 hash as raw bytes.

    #### Parameters
    - data: ReadableBuffer
      - Data to run through the RIPEMD160 algorithm.

    #### Returns
    - bytes
      - Raw bytes of the results of the RIPEMD160 algorithm.

    """
    return hashlib.new('ripemd160', data).digest()

def hash160(data: ReadableBuffer) -> bytes:
    """ Returns a Bitcoin-style HASH160 hash as raw bytes.

    #### Parameters
    - data: ReadableBuffer
      - Data to run through the HASH160 algorithm.

    #### Returns
    - bytes
      - Raw bytes of the results of the HASH160 algorithm.

    """
    return ripemd160(hashlib.sha256(data).digest())

def sha256_2(data: ReadableBuffer) -> bytes:
    """ Returns the hashed result of running the data through the
    SHA256 algorithm twice.

    #### Parameters
    - data: ReadableBuffer
      - Data to run through the SHA256 algorithm twice.

    #### Returns
    - bytes
      - Raw bytes of the results of the SHA256 algorithm ran twice.

    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hexstring(_hash: bytes) -> str:
    """ Reverses the byte order and returns as a hex-encoded string. """
    return _hash[::-1].hex()


# Decoding data types
def uint32(data: ReadableBuffer) -> int:
    """ Decodes data into an unsigned 32-bit integer.

    #### Parameters
    - data: ReadableBuffer
      - Data to interpret.

    #### Returns:
    - int
      - Decoded uint32 value.

    #### Raises:
    - ValueError
      - If `data` is not exactly 4 bytes in length.
    """
    if len(data) != 4:
        raise ValueError('Unable to decode data to uint32. Incorrect size.')
    return struct.unpack('<I', data)[0]

def uint64(data: ReadableBuffer) -> Tuple[int, int]:
    """ Decodes data into an unsigned 64-bit integer.

    #### Parameters
    - data: ReadableBuffer
      - Data to interpret.

    #### Returns:
    - int
      - Decoded uint64 value.

    #### Raises:
    - ValueError
      - If `data` is not exactly 8 bytes in length.
    """
    if len(data) != 8:
        raise ValueError('Unable to decode data to uint64. Incorrect size.')
    return struct.unpack('<Q', data)[0]

def varint(data: ReadableBuffer) -> Tuple[int, int]:
    """ Decodes data according to Bitcoin specifications for a varint.

    #### Parameters
    - data: ReadableBuffer
      - Data to interpret.

    #### Returns
    - Tuple[int, int]
      - Decoded value and size packed as a tuple.

    #### Raises
    - ValueError
      - If `data` is empty.
      - If `data` has a specified size greater than 255 or less than 0.

    """
    if len(data) <= 0:
        raise ValueError('Unable to decode empty data.')
    _sz: int = int(data[0])
    if _sz > 255:
        _err: List[str] = [
            'Incorrect data encoding.',
            'Must be between 0 and 255 in length.',
            f'Provided: {_sz}'
        ]
        raise ValueError(' '.join(_err))
    if _sz < 253:
        return (_sz, 1)
    # Interpret integer encoding.
    _format: str = ''
    if _sz == 253:
        _format = '<H'
    elif _sz == 254:
        _format = '<I'
    elif _sz == 255:
        _format = '<Q'
    else:
        # Theoretically, this should be unreachable, but.
        # Better safe than sorry.
        raise ValueError(f'Unknown format value. Provided: {_sz}')
    # Decode integer.
    _sz = struct.calcsize(_format)
    return (struct.unpack(_format, data[1:_sz + 1])[0], _sz + 1)
