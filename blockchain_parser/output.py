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
""" This module contains the definition for a Bitcoin transaction's output. """
from typing import List

from .utils import varint, uint64
from .script import Script
from .address import Address
from ._types import ScriptType


class TxOutput(object):
    """ Output portion of a Bitcoin transaction.

    #### Properties
    - value: int
    - size: int
    - script: Script
    - addresses: List[Address]
    - script_type: ScriptType

    #### Methods
    - from_bytes(raw_data: bytes) -> TxOutput

    """
    def __init__(self, raw_bytes: bytes):
        self._value: int = None
        self._script: Script = None
        self._addresses: List[Address] = None
        script_length, varint_size = varint(raw_bytes[8:])
        script_start: int = 8 + varint_size
        self._script_raw: bytes = raw_bytes[script_start:script_start + script_length]
        self.size: int = script_start + script_length
        self._value_raw: bytes = raw_bytes[:8]

    def __repr__(self):
        return f'Output(satoshis={self.value})'

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'TxOutput':
        """ Creates a transaction's output from its raw bytes. """
        return cls(raw_data)
    

    @property
    def value(self) -> int:
        """ Value of the output expressed in satoshis. """
        if self._value is None:
            self._value = uint64(self._value_raw)
        return self._value

    @property
    def script(self) -> Script:
        """ Output's script as a Script object. """
        if self._script is None:
            self._script = Script.from_bytes(self._script_raw)
        return self._script

    @property
    def addresses(self) -> List[Address]:
        """ List containing all the addresses mentioned in the
        output's script.

        """
        if self._addresses is None:
            _address: Address = None
            self._addresses = []
            if self.script_type == 'pubkey':
                _address = Address.from_public_key(self.script.operations[0])
                self._addresses.append(_address)
            elif self.script_type == 'pubkeyhash':
                _address = Address.from_hash160(self.script.operations[2])
                self._addresses.append(_address)
            elif self.script_type == 'p2sh':
                _address = Address.from_hash160(self.script.operations[1], _type='p2sh')
                self._addresses.append(_address)
            elif self.script_type == 'multisig':
                n = self.script.operations[-2]
                for operation in self.script.operations[1:1+n]:
                    self._addresses.append(Address.from_public_key(operation))
            elif self.script_type == 'p2wpkh':
                _address = Address.from_bech32(self.script.operations[1], 0)
                self._addresses.append(_address)
            elif self.script_type == 'p2wsh':
                _address = Address.from_bech32(self.script.operations[1], 0)
                self._addresses.append(_address)
        return self._addresses

    @property
    def script_type(self) -> ScriptType:
        """ Output's script type as a string. """
        _type: ScriptType = 'unknown'
        if not self.script.script.is_valid():
            return 'invalid'
        if self.script.is_pubkeyhash():
            _type = 'pubkeyhash'
        elif self.script.is_pubkey():
            _type = 'pubkey'
        elif self.script.is_p2sh():
            _type = 'p2sh'
        elif self.script.is_multisig():
            _type = 'multisig'
        elif self.script.is_return():
            _type = 'OP_RETURN'
        elif self.script.is_p2wpkh():
            _type = 'p2wpkh'
        elif self.script.is_p2wsh():
            _type = 'p2wsh'
        return _type
