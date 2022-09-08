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
#
""" This module contains the definition of a Bitcoin redemption script. """
from typing import List
from binascii import b2a_hex
import bitcoin.core.script as btc


def is_public_key(data: bytes) -> bool:
    """ Returns whether the provided bytes look like a public key or not.

    Note that this does not validate the key, just whether or not it
    matches the correct pattern.

    """
    if not isinstance(data, bytes):
        return False
    _uncompressed: bool = len(data) == 65 and int(data[0]) == 4
    _compressed: bool = len(data) == 33 and int(data[0]) in [2, 3]
    return _uncompressed or _compressed


class Script(object):
    """ Transaction script contained in a Bitcoin input or output.

    #### Properties
    raw: bytes


    #### Methods
    - from_bytes(raw_bytes: bytes) -> 'Script'
    - is_return() -> bool
    - is_p2sh() -> bool
    - is_p2wsh() -> bool
    - is_p2wpkh() -> bool
    - is_pubkey() -> bool
    - is_pubkeyhash() -> bool
    - is_multisig() -> bool
    - is_unknown() -> bool

    """
    def __init__(self, raw_data: bytes):
        self.raw: bytes = raw_data
        self._script: btc.CScript = None
        self._type: str = None
        self._value: str = None
        self._operations: List = None
        self._addresses: List = None

    def __repr__(self):
        return f'Script({self.value})'

    @classmethod
    def from_bytes(cls, raw_bytes: bytes):
        """ Creates a Script object from the raw byte data. """
        return cls(raw_bytes)


    @property
    def script(self) -> btc.CScript:
        """ Underlying CScript object. """
        if self._script is None:
            self._script = btc.CScript(self.raw)
        return self._script

    @property
    def operations(self) -> List:
        """ List of operations done by this script. """
        if self._operations is None:
            try:
                self._operations = list(self.script)
            except btc.CScriptInvalidError:
                self._operations = []
        return self._operations

    @property
    def value(self) -> str:
        """ String representation of the script"""
        if self._value is None:
            _parts: List = []
            try:
                for operation in list(self.script):
                    if isinstance(operation, bytes):
                        _parts.append(b2a_hex(operation).decode('ascii'))
                    else:
                        _parts.append(str(operation))
                self._value = " ".join(_parts)
            except btc.CScriptInvalidError:
                self._value = 'INVALID_SCRIPT'
        return self._value


    def is_return(self) -> bool:
        """ Returns whether or not the script is unspendable. """
        return self.script.is_unspendable()

    def is_p2sh(self) -> bool:
        """ Returns whether or not the script defines a p2sh address. """
        return self.script.is_p2sh()

    def is_p2wsh(self) -> bool:
        """ Returns whether or not the script defines a p2wsh address."""
        return self.script.is_witness_v0_scripthash()

    def is_p2wpkh(self) -> bool:
        """ Returns whether or not the script defines a p2wpkh address. """
        return self.script.is_witness_v0_keyhash()

    def is_pubkey(self) -> bool:
        """ Returns whether or not the script defines a public key. """
        _length: bool = len(self.operations) == 2
        _operation: bool = self.operations[-1] == btc.OP_CHECKSIG
        _pubkey: bool = is_public_key(self.operations[0])
        return _length and _operation and _pubkey

    def is_pubkeyhash(self) -> bool:
        """ Returns whether or not the script defines a hashed public key. """
        _length: bool = len(self.raw) == 25
        _op_dup: bool = self.operations[0] == btc.OP_DUP
        _op_hash: bool = self.operations[1] == btc.OP_HASH160
        _op_verify: bool = self.operations[-2] == btc.OP_EQUALVERIFY
        _op_check: bool = self.operations[-1] == btc.OP_CHECKSIG
        return _length and _op_dup and _op_hash and _op_verify and _op_check

    def is_multisig(self) -> bool:
        """ Returns whether or not the script has multiple signatures. """
        if len(self.operations) < 4:
            return False
        _m = self.operations[0]
        if not isinstance(_m, int):
            return False
        for i in range(_m):
            if not is_public_key(self.operations[1 + i]):
                return False
        _n = self.operations[-2]
        _type: bool = isinstance(_n, int)
        _value: bool = _n < _m
        _op_multi: bool = self.operations[-1] != btc.OP_CHECKMULTISIG
        if not _type or _value or _op_multi:
            return False
        return True

    def is_unknown(self) -> bool:
        """ Returns whether or not the script type is known. """
        _pubkey: bool = self.is_pubkeyhash() or self.is_pubkey()
        _p2sh: bool = self.is_p2sh()
        _multisig: bool = self.is_multisig()
        _return: bool = self.is_return()
        _p2w: bool = self.is_p2wpkh() or self.is_p2wsh()
        return _pubkey or _p2sh or _multisig or _return or _p2w
