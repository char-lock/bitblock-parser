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
""" This module contains the definition for a Bitcoin transaction's input. """
from typing import List

from .utils import varint, uint32, hexstring
from .script import Script


class TxInput():
    # pylint: disable=R0902
    """ Input portion of a Bitcoin transaction.

    #### Properties
    - raw: bytes
    - script: Script
    - sequence_number: int
    - size: int
    - transaction_hash: str
    - transaction_index: int
    - witnesses: List

    #### Methods
    - from_bytes(raw_data: bytes) -> 'TxInput'

    """
    def __init__(self, raw_bytes: bytes):
        self._transaction_hash: str = None
        self._transaction_index: int = None
        self._script: Script = None
        self._sequence_number: int = None
        self._witnesses: List = []
        self._script_length, varint_length = varint(raw_bytes[36:])
        self._script_start: int = 36 + varint_length
        self.raw: bytes = raw_bytes[:self.size]

    def __repr__(self):
        return f'Input({self.transaction_hash}, {self.transaction_index})'

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'TxInput':
        """ Creates a transaction's input from its raw bytes. """
        return cls(raw_data)

    @property
    def transaction_hash(self) -> str:
        """ Hash of the transaction containing the output redeemed by
        this input.

        """
        if self._transaction_hash is None:
            self._transaction_hash = hexstring(self.raw[:32])
        return self._transaction_hash

    @property
    def transaction_index(self) -> int:
        """ Index of the output inside the transaction redeemed by
        this input.

        """
        if self._transaction_index is None:
            self._transaction_index = uint32(self.raw[32:36])
        return self._transaction_index

    @property
    def sequence_number(self) -> int:
        """ Input's sequence number. """
        if self._sequence_number is None:
            self._sequence_number = uint32(
                self.raw[self.size - 4:self.size]
            )
        return self._sequence_number

    @property
    def script(self) -> Script:
        """ Script object representing the redeem script. """
        if self._script is None:
            _end: int = self._script_start + self._script_length
            self._script = Script.from_bytes(self.raw[self._script_start:_end])
        return self._script

    @property
    def size(self) -> int:
        """ Length of the input in bytes. """
        return self._script_start + self._script_length + 4

    @property
    def witnesses(self) -> List:
        """ List of witness data attached to this input. """
        return self._witnesses


    def add_witness(self, witness) -> None:
        """ Adds a witness to the input's list. """
        self._witnesses.append(witness)
    