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
# pylint: disable=R0903
# pylint: disable=W0703
#
""" This module holds the definition for the Block class. """

from typing import List, Optional
from .transaction import Transaction
from .block_header import BlockHeader
from .utils import hexstring, varint, sha256_2


def get_block_transactions(raw_data: bytes) -> Transaction:
    """ Given the raw bytes of a block, yields the block's
    transactions.

    """
    # Skipping the header
    transaction_data: bytes = raw_data[80:]
    # Decoding the number of transactions, offset is the size of
    # the varint (1 to 9 bytes)
    n_transactions, offset = varint(transaction_data)
    for _ in range(n_transactions):
        # Try from 1024 (1KiB) -> 1073741824 (1GiB) slice widths
        for j in range(0, 20):
            try:
                offset_e: int = offset + (1024 * 2 ** j)
                transaction: Transaction = Transaction.from_bytes(
                    transaction_data[offset:offset_e]
                )
                yield transaction
                break
            except Exception:
                continue
        # Skipping to the next transaction
        offset += transaction.size


class Block(object):
    """ A Bitcoin block; contains its header and its transactions.

    #### Properties
    - raw: bytes
    - size: int
    - height: int
    - blk_file: str
    - hash: str
    - n_transactions: int
    - transactions: List[Transaction]
    - header: BlockHeader

    #### Methods
    - from_bytes(raw_data: bytes) -> Block

    """
    def __init__(
        self,
        raw_data: bytes,
        height: Optional[int] = None,
        blk_file: Optional[str] = None
    ):
        self.raw: bytes = raw_data
        self._hash: str = None
        self._transactions: List[Transaction] = None
        self._header: BlockHeader = None
        self._n_transactions: int = None
        self.size: int = len(raw_data)
        self.height: int = height
        self.blk_file: str = blk_file

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'Block':
        """ Creates a block from its raw bytes. """
        return cls(raw_data)

    def __repr__(self) -> str:
        return f'Block({self.hash})'


    @property
    def hash(self) -> str:
        """ Block's hash  -- sha256_2 of its 80 byte header. """
        if self._hash is None:
            self._hash = hexstring(sha256_2(self.raw[:80]))
        return self._hash

    @property
    def n_transactions(self) -> int:
        """ Number of transactions contained in this block.

        It is faster to use this than to use len(block.transactions),
        as there's no need to parse all transactions to get this
        information.

        """
        if self._n_transactions is None:
            self._n_transactions = varint(self.raw[80:])[0]
        return self._n_transactions

    @property
    def transactions(self) -> List[Transaction]:
        """ A list of the block's transactions represented as
        Transaction objects.

        """
        if self._transactions is None:
            self._transactions = list(get_block_transactions(self.raw))
        return self._transactions

    @property
    def header(self) -> BlockHeader:
        """ BlockHeader object corresponding to this block. """
        if self._header is None:
            self._header = BlockHeader.from_bytes(self.raw[:80])
        return self._header
