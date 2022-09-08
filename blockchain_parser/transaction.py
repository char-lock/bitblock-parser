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
""" This module provides the definition for a Bitcoin transaction. """
from math import ceil
from typing import List

from .utils import varint, uint32, sha256_2, hexstring
from .input import TxInput
from .output import TxOutput


def bip69_sort(data: List) -> List:
    """ Sorts the data according to the BIP-69 standard. """
    return list(sorted(data, key=lambda t: (t[0], t[1])))


class Transaction(object):
    """ A Bitcoin transaction within a block.

    #### Properties
    - inputs: List[TxInput]
    - outputs: List[TxOutput]
    - n_inputs: int
    - n_outputs: int
    - is_segwit: bool
    - version: int
    - locktime: int
    - hash: str
    - vsize: int
    - txid: str

    #### Methods
    - from_bytes(raw_data: bytes) -> Transaction
    - is_coinbase() -> bool
    - uses_replace_by_fee() -> bool
    - uses_bip69() -> bool

    """
    def __init__(self, raw_data: bytes):
        self._hash: str = None
        self._txid: int = None
        self.inputs: List[TxInput] = None
        self.outputs: List[TxOutput] = None
        self._version: int = None
        self._locktime: int = None
        self.size: int = None
        self.n_inputs: int = 0
        self.n_outputs: int = 0
        self.is_segwit: bool = False
        offset: int = 4
        #
        # Adds basic support for segwit transactions
        #   - https://bitcoincore.org/en/segwit_wallet_dev/
        #   - https://en.bitcoin.it/wiki/Protocol_documentation#BlockTransactions
        #
        if b'\x00\x01' == raw_data[offset:offset + 2]:
            self.is_segwit = True
            offset += 2
        self.n_inputs, varint_size = varint(raw_data[offset:])
        offset += varint_size
        self.inputs = []
        for _ in range(self.n_inputs):
            _input: TxInput = TxInput.from_bytes(raw_data[offset:])
            offset += _input.size
            self.inputs.append(_input)
        self.n_outputs, varint_size = varint(raw_data[offset:])
        offset += varint_size
        self.outputs = []
        for _ in range(self.n_outputs):
            _output: TxOutput = TxOutput.from_bytes(raw_data[offset:])
            offset += _output.size
            self.outputs.append(_output)
        if self.is_segwit:
            self._offset_before_tx_witnesses = offset
            for _in in self.inputs:
                tx_witnesses_n, varint_size = varint(raw_data[offset:])
                offset += varint_size
                for _ in range(tx_witnesses_n):
                    component_length, varint_size = varint(
                        raw_data[offset:]
                    )
                    offset += varint_size
                    witness = raw_data[offset:offset + component_length]
                    _in.add_witness(witness)
                    offset += component_length
        self.size = offset + 4
        self.raw = raw_data[:self.size]
        if self.size != len(self.raw):
            raise ValueError('Incomplete transaction.')

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'Transaction':
        """ Creates a block from the raw bytes. """
        return cls(raw_data)

    def __repr__(self) -> str:
        return f'Transaction({self.hash})'

    @property
    def version(self) -> int:
        """ Transaction's version number. """
        if self._version is None:
            self._version = uint32(self.raw[:4])
        return self._version

    @property
    def locktime(self) -> int:
        """ Transaction's locktime. """
        if self._locktime is None:
            self._locktime = uint32(self.raw[-4:])
        return self._locktime

    @property
    def hash(self) -> str:
        """ Transaction's id -- equivalent to the hash for non-SegWit
        transactions; it differs from it for SegWit.
    
        """
        if self._hash is None:
            self._hash = hexstring(sha256_2(self.raw))
        return self._hash

    @property
    def vsize(self) -> int:
        """ Transaction size in virtual bytes. """
        if not self.is_segwit:
            return self.size
        # The witness is the last element in a transaction before the
        # 4 byte locktime, and self._offset_before_tx_witnesses is the
        # position where the witness starts.
        wit_sz: int = self.size - self._offset_before_tx_witnesses - 4
        # Size of the transaction without the segwit marker (2 bytes) and
        # the witness.
        stripped_sz: int = self.size - (2 + wit_sz)
        weight: int = stripped_sz * 3 + self.size
        # vsize is weight / 4, rounded up
        return ceil(weight / 4)

    @property
    def txid(self) -> str:
        """ Transaction's id -- equivalent to the hash for non-SegWit
        transactions; it differs from it for SegWit.
    
        """
        if self._txid is None:
            # segwit transactions have two transaction ids/hashes, txid and wtxid
            # txid is a hash of all of the legacy transaction fields only
            if self.is_segwit:

                txid_data: bytes = (
                    self.raw[:4]
                  + self.raw[6:self._offset_before_tx_witnesses]
                  + self.raw[-4:]
                )
            else:
                txid_data = self.raw
            self._txid = hexstring(sha256_2(txid_data))
        return self._txid


    def is_coinbase(self) -> bool:
        """ Returns whether transaction is a coinbase transaction or not. """
        for _input in self.inputs:
            if _input.transaction_hash == '0' * 64:
                return True
        return False

    def uses_replace_by_fee(self) -> bool:
        """ Returns whether the transaction opted-in for RBF. """
        # Coinbase transactions may have a sequence number that signals RBF
        # but they cannot use it as it's only enforced for non-coinbase txs
        if self.is_coinbase():
            return False
        # A transactions opts-in for RBF when having an input
        # with a sequence number < MAX_INT - 1
        for _input in self.inputs:
            if _input.sequence_number < 4294967294:
                return True
        return False

    def uses_bip69(self) -> bool:
        """ Returns whether the transaction complies to BIP-69,
        lexicographical ordering of inputs and outputs.

        """
        # Quick check
        if self.n_inputs == 1 and self.n_outputs == 1:
            return True
        input_keys: List = [
            (i.transaction_hash, i.transaction_index)
            for i in self.inputs
        ]
        if bip69_sort(input_keys) != input_keys:
            return False
        output_keys: List = [(o.value, o.script.value) for o in self.outputs]
        return bip69_sort(output_keys) == output_keys
