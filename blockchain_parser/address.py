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
""" This module contains the definition for a Bitcoin address and
related functions.

"""
from typing import Optional

from bitcoin import base58
from bitcoin.bech32 import CBech32Data

from .utils import hash160, sha256_2
from ._types import AddressType


class Address(object):
    """ A Bitcoin address with relevant information.

    #### Properties
    - address: str
    - address_type: AddressType
    - hash: bytes
    - public_key: bytes

    #### Methods
    - from_public_key(public_key: bytes) -> Address
    - from_hash160(_hash: bytes, _type: AddressType) -> Address
    - from_bech32(_hash: CBech32Data) -> Address
    - is_p2sh() -> bool

    """
    def __init__(
        self,
        _hash: Optional[bytes],
        public_key: Optional[bytes],
        address: Optional[str],
        _type: Optional[AddressType],
        segwit_version: Optional[bytes]
    ):
        self._hash: bytes = _hash
        self.public_key: bytes = public_key
        self._address: str = address
        self.address_type: AddressType = _type
        self._segwit_version: bytes = segwit_version

    def __repr__(self) -> str:
        return f'Address(addr={self.address})'


    @classmethod
    def from_public_key(cls, public_key: bytes) -> 'Address':
        """ Creates an Address from a public_key. """
        return cls(None, public_key, None, 'normal', None)

    @classmethod
    def from_hash160(cls, _hash: bytes, _type: AddressType = 'normal') -> 'Address':
        """ Creates an Address from the HASH160 hash. """
        return cls(_hash, None, None, _type, None)

    @classmethod
    def from_bech32(cls, _hash: bytes, segwit_version: bytes) -> 'Address':
        """ Creates an Address from a bech32-encoded hash. """
        return cls(_hash, None, None, 'bech32', segwit_version)


    @property
    def hash(self) -> bytes:
        """ HASH160 hash corresponding to this address. """
        if self.public_key is not None and self._hash is None:
            self._hash = hash160(self.public_key)
        return self._hash

    @property
    def address(self) -> str:
        """ Encoded representation of this address. """
        if self._address is None:
            if self.address_type != 'bech32':
                _version: bytes = b'\x00' if self.address_type == 'normal' else b'\x05'
                _checksum: bytes = sha256_2(_version + self.hash)
                self._address = base58.encode(_version + self.hash + _checksum[:4])
            else:
                _bech: CBech32Data = CBech32Data.from_bytes(self._segwit_version, self._hash)
                self._address: str = str(_bech)
        return self._address


    def is_p2sh(self) -> bool:
        """ Returns whether or not the address is a p2sh address. """
        return self.address_type == 'p2sh'
