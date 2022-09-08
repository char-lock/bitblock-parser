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
# pylint: disable=R0205
# pylint: disable=R0902
#
""" This module contains the definition of a Bitcoin block header. """
from datetime import datetime

from bitcoin.core import CBlockHeader
from .utils import uint32, hexstring


class BlockHeader(object):
    """ Header of a Bitcoin block.

    #### Properties
    - bits: int
    - difficulty: float
    - merkle_root: str
    - nonce: int
    - previous_block_hash: int
    - raw: bytes
    - timestamp: datetime
    - version: int

    #### Methods
    - from_bytes(raw_data: bytes) -> 'BlockHeader'

    """
    def __init__(self, raw_data: bytes):
        self._version: int = None
        self._previous_block_hash: str = None
        self._merkle_root: str = None
        self._timestamp: datetime = None
        self._bits: int = None
        self._nonce: int = None
        self._difficulty: int = None
        self.raw: bytes = raw_data[:80]

    def __repr__(self):
        return f'BlockHeader(previous_block_hash={self._previous_block_hash})'

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'BlockHeader':
        """ Creates a BlockHeader from the raw bytes. """
        return cls(raw_data)


    @property
    def version(self) -> int:
        """ Version of the block. """
        if self._version is None:
            self._version = uint32(self.raw[:4])
        return self._version

    @property
    def previous_block_hash(self) -> str:
        """ Hash of the previous block. """
        if self._previous_block_hash is None:
            self._previous_block_hash = hexstring(self.raw[4:36])
        return self._previous_block_hash

    @property
    def merkle_root(self) -> str:
        """ Merkle root of the block. """
        if self._merkle_root is None:
            self._merkle_root = hexstring(self.raw[36:68])
        return self._merkle_root

    @property
    def timestamp(self) -> datetime:
        """ Timestamp of the block. """
        if self._timestamp is None:
            self._timestamp = datetime.utcfromtimestamp(
                uint32(self.raw[68:72])
            )
        return self._timestamp

    @property
    def bits(self) -> int:
        """ Bits (difficulty target) of the block. """
        if self._bits is None:
            self._bits = uint32(self.raw[72:76])
        return self._bits

    @property
    def nonce(self) -> int:
        """ Nonce of the block. """
        if self._nonce is None:
            self._nonce = uint32(self.raw[76:80])
        return self._nonce

    @property
    def difficulty(self) -> float:
        """ Difficulty target of the block. """
        if self._difficulty is None:
            self._difficulty = CBlockHeader.calc_difficulty(self.bits)
        return self._difficulty
