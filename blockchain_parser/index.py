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
#
""" This module handles finding block indexes in the database files. """
from typing import List
from struct import unpack
from .utils import hexstring


BLOCK_HAVE_DATA: int = 8
BLOCK_HAVE_UNDO: int = 16


def _leveldb_varint(raw_data: bytes) -> int:
    """ Reads the weird format of varint present in `src/serialize.h`
    of Bitcoin Core and being used for storing data in the leveldb.

    Note: This is not the varint format described for general bitcoin
    serialization use. That is defined in util.varint

    """
    idx: int = 0
    pos: int = 0
    while True:
        data: bytes = raw_data[pos]
        pos += 1
        idx = (idx << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return idx, pos
        idx += 1


class DBBlockIndex(object):
    """ A position within a database block. """
    def __init__(self, block_hash: str, raw_data: bytes):
        self.hash = block_hash
        _pos: int = 0
        _, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        self.height, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        self.status, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        self.n_tx, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        if self.status & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
            self.file, i = _leveldb_varint(raw_data[_pos:])
            _pos += i
        else:
            self.file = -1
        if self.status & BLOCK_HAVE_DATA:
            self.data_pos, i = _leveldb_varint(raw_data[_pos:])
            _pos += i
        else:
            self.data_pos = -1
        if self.status & BLOCK_HAVE_UNDO:
            self.undo_pos, i = _leveldb_varint(raw_data[_pos:])
            _pos += i
        if _pos + 80 != len(raw_data):
            raise IOError('Invalid block.')
        self.version, _prev, _merkle, _, _, self.nonce = unpack(
            "<I32s32sIII",
            raw_data[-80:]
        )
        self.prev_hash = hexstring(_prev)
        self.merkle_root = hexstring(_merkle)

    def __repr__(self) -> str:
        _return: List[str] = [
            f'DBBlockIndex({self.hash}, height={self.height}, ',
            f'file_no={self.file}, file_pos={self.data_pos})'
        ]
        return ''.join(_return)


class DBTransactionIndex(object):
    """ Transaction position within the database. """
    def __init__(self, tx_hash: str, raw_data: bytes):
        self.hash: str = tx_hash
        _pos: int = 0
        self.blockfile_no, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        self.file_offset, i = _leveldb_varint(raw_data[_pos:])
        _pos += i
        self.block_offset, i = _leveldb_varint(raw_data[_pos:])

    def __repr__(self) -> str:
        _return: List[str] = [
            f'DBTransactionIndex({self.hash}, ',
            f'blockfile_no={self.blockfile_no}, ',
            f'file_offset={self.file_offset}, ',
            f'block_offset={self.block_offset})'
        ]
        return ''.join(_return)
