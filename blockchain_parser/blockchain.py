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
# pylint: disable=W0702
# pylint: disable=W0703
# pylint: disable=C0103
# pylint: disable=R0205
#
""" This module provides the definitions for the Blockchain class. """
import mmap
import os
import pickle
import stat
import struct

from binascii import unhexlify
from typing import List, Optional
import plyvel

from .block import Block
from .index import DBBlockIndex, DBTransactionIndex
from .transaction import Transaction
from .utils import hexstring

# This definition is here to keep pylint from screaming.
mmap.PROT_READ: int = mmap.PROT_READ if mmap.PROT_READ is not None else 1


# Constant separating blocks in the .blk files
BITCOIN_CONSTANT: bytes = b'\xf9\xbe\xb4\xd9'


def get_files(path: str) -> List:
    """ Returns the sorted list of .blk files contained in the given
    directory.

    #### Parameters
    - path: str
      - Directory where .blk files are stored.

    #### Returns
    - List[str]
      - A sorted list of all blk files.

    """
    if not stat.S_ISDIR(os.stat(path)[stat.ST_MODE]):
        return [path]
    files:List[str] = os.listdir(path)
    files = [f for f in files if f.startswith("blk") and f.endswith(".dat")]
    files = map(lambda x: os.path.join(path, x), files)
    return sorted(files)

def get_blocks(block_file: str) -> mmap.mmap:
    """ Yields the raw bytes for every block of a .blk file.

    #### Parameters
    - block_file: str
      - Block file from which to read blocks.

    #### Yields
    - bytes
      - Raw bytes of the current block.

    """
    with open(block_file, "rb") as f:
        if os.name == 'nt':
            size: int = os.path.getsize(f.name)
            raw_data: mmap.mmap = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)
        else:
            # Unix-only call, will not work on Windows, see python doc.
            raw_data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
        length: int = len(raw_data)
        offset: int = 0
        block_count: int = 0
        while offset < (length - 4):
            if raw_data[offset:offset + 4] == BITCOIN_CONSTANT:
                offset += 4
                size: int = struct.unpack("<I", raw_data[offset:offset + 4])[0]
                offset += 4 + size
                block_count += 1
                yield raw_data[offset - size:offset]
            else:
                offset += 1
        raw_data.close()

def get_block(block_file: str, offset: int = 8) -> bytes:
    """ Returns a single block from a blockfile.

    #### Parameters
    - block_file: str
      - Blockfile from which to pull the block.
    - offset: int
      - Location of block in the file. This should be 4 bytes after
        the block size. First block is located at an offset of 8.

    #### Returns
    - bytes
      - Raw data of the specified block.

    """
    with open(block_file, "rb") as _file:
        # Offse
        _file.seek(offset - 4)  # Size is present 4 bytes before the db offset
        size: int = struct.unpack("<I", _file.read(4))[0]
        return _file.read(size)


class Blockchain(object):
    """ Blockchain contained in the series of .blk files maintained by
    bitcoind.

    #### Properties
    - path: str
      - Directory where block files are stored.
    - block_indexes: List[DBBlockIndex]
      - List of cached block indexes.

    #### Methods
    - get_undordered_blocks() -> Block
    - get_ordered_blocks() -> Block
    - get_transaction(self, txid: str, db: ) -> Transaction

    """
    def __init__(self, path: str):
        self.path: str = path
        self.blockIndexes: List[DBBlockIndex] = None
        self.indexPath: str = None


    def get_unordered_blocks(self) -> Block:
        """ Yields the blocks contained in the .blk files as is,
        without ordering them according to height.

        #### Yields
        - Block
          - Next block in the block files.

        """
        for blk_file in get_files(self.path):
            for raw_block in get_blocks(blk_file):
                yield Block(raw_block, None, os.path.split(blk_file)[1])

    def __get_block_indexes(self, index: str) -> List[DBBlockIndex]:
        """ Caches indexes from leveldb index file.

        There is no method for leveldb to close and release its lock
        on a file. Concurrent operations, therefore, are difficult to
        achieve. This, at least, corrects that for the index files.

        #### Parameters
        - index: str
          - Index file from which to pull index information.

        #### Returns
        - List[DBBlockIndex]
          - List of block indexes in the index file.

        """
        if self.indexPath != index:
            db: plyvel.DB = plyvel.DB(index, compression=None)
            self.blockIndexes = [DBBlockIndex(hexstring(k[1:]), v)
                                 for k, v in db.iterator() if k[0] == ord('b')]
            db.close()
            self.blockIndexes.sort(key=lambda x: x.height)
            self.indexPath = index
        return self.blockIndexes

    def _index_confirmed(
        self,
        chain_indexes: List[DBBlockIndex],
        num_confirmations: int=6) -> bool:
        """ Returns whether or not the first block index has a minimum
        number of confirmations.

        #### Parameters
        - chain_indexes: List[DBBlockIndex]
          - List of chain-related indices.
        - num_confirmations: int
          - Minimum number of confirmations for block to be confirmed.

        #### Returns
        - bool
          - True if confirmed, False if orphaned.

        """
        # The variable 'chains' holds a 2D list of sequential block
        # hash chains.
        # As soon as there is an element of length `num_confirmations`,
        # we can make a decision about whether or not the block in
        # question is confirmed by checking if its hash is in that
        # list.
        chains: List[str] = []
        # The block in question
        first_block: Block = None
        # Loop through all future blocks.
        for i, index in enumerate(chain_indexes):
            # If this block doesn't have data, don't confirm it.
            if index.file == -1 or index.data_pos == -1:
                return False
            # parse the block
            block_file: str = os.path.join(self.path, 'blk{index.file:05d}.dat')
            block = Block(get_block(block_file, index.data_pos))
            if i == 0:
                first_block = block
            chains.append([block.hash])
            for chain in chains:
                # If this block can be appended to an existing block
                # in one of the chains, do it.
                if chain[-1] == block.header.previous_block_hash:
                    chain.append(block.hash)
                # If we've found a chain length == num_dependencies
                # (usually 6), we are ready to make a decision on
                # whether or not the block belongs to a fork or the
                # main chain.
                if len(chain) == num_confirmations:
                    return first_block.hash in chain

    def get_ordered_blocks(
        self,
        index: str,
        start: int = 0,
        end: Optional[int] = None,
        cache: Optional[str] = None
    ) -> Block:
        """ Yields the blocks contained in the .blk files, ordered by
        the height extracted from the leveldb index.

        #### Parameters
        - index: str
          - Index file containing the block indexes.
        - start: int
          - Height at which to start.
        - end: Optional[int]
          - Height at which to end.
        - cache: Optional[str]
          - Location of cached block index.

        #### Yields
        - Block
          - Next block contained in the block files, in order.

        """
        block_indexes: List[DBBlockIndex]  = None
        if cache and os.path.exists(cache):
            # load the block index cache from a previous index
            with open(cache, 'rb') as _file:
                block_indexes = pickle.load(_file)
        if block_indexes is None:
            # build the block index
            block_indexes = self.__get_block_indexes(index)
            if cache and not os.path.exists(cache):
                # cache the block index for re-use next time
                with open(cache, 'wb') as _file:
                    pickle.dump(block_indexes, _file)
        # remove small forks that may have occurred while the node was live.
        # Occasionally a node will receive two different solutions to a block
        # at the same time. The Leveldb index saves both, not pruning the
        # block that leads to a shorter chain once the fork is settled without
        # "-reindex"ing the bitcoind block data. This leads to at least two
        # blocks with the same height in the database.
        # We throw out blocks that don't have at least 6 other blocks on top of
        # it (6 confirmations).
        orphans: List[Block] = []  # hold blocks that are orphans with < 6 blocks on top
        last_height: int = -1
        for i, block_index in enumerate(block_indexes):
            if last_height > -1:
                # if this block is the same height as the last block an orphan
                # occurred, now we have to figure out which of the two to keep
                if block_index.height == last_height:
                    # loop through future blocks until we find a chain 6 blocks
                    # long that includes this block. If we can't find one
                    # remove this block as it is invalid
                    if self._index_confirmed(block_indexes[i:]):
                        # if this block is confirmed, the unconfirmed block is
                        # the previous one. Remove it.
                        orphans.append(block_indexes[i - 1].hash)
                    else:
                        # if this block isn't confirmed, remove it.
                        orphans.append(block_index.hash)
            last_height = block_index.height
        # filter out the orphan blocks, so we are left only with block indexes
        # that have been confirmed
        # (or are new enough that they haven't yet been confirmed)
        block_indexes = list(filter(lambda block: block.hash not in orphans, block_indexes))
        if end is None:
            end = len(block_indexes)
        if end < start:
            block_indexes = block_indexes[::-1]
            start = len(block_indexes) - start
            end = len(block_indexes) - end
        for block_index in block_indexes[start:end]:
            if block_index.file == -1 or block_index.data_pos == -1:
                break
            block_file: str = os.path.join(self.path, f'blk{block_index.file:05d}.dat')
            yield Block(get_block(block_file, block_index.data_pos), block_index.height)

    def get_transaction(self, txid: str, db: plyvel.DB) -> Transaction:
        """ Yields the transaction contained in the .blk files as a
        Python object, similar to:

        https://developer.bitcoin.org/reference/rpc/getrawtransaction.html

        #### Parameters
        - txid: str
          - Hash of transaction to pull.
        - db: plyvel.DB
          - LevelDB object in which to search.

        #### Returns
        - Transaction
          - Transaction object with the requested transaction.

        """
        # Reformat standard txid into the format to search in.
        byte_arr: bytearray = bytearray.fromhex(txid)
        byte_arr.reverse()
        tx_hash: str = b't'.hex() + byte_arr.hex()
        tx_hash_fmtd: bytes = unhexlify(tx_hash)
        # Find the transaction and process it.
        raw_tx: bytes = db.get(tx_hash_fmtd)
        tx_idx: DBTransactionIndex = DBTransactionIndex(
            hexstring(tx_hash_fmtd),
            raw_tx
        )
        block_file: str = os.path.join(
            self.path,
            f'blk{tx_idx.blockfile_no:05d}.dat'
        )
        raw_tx = get_block(block_file, tx_idx.file_offset)
        offset: int = tx_idx.block_offset
        transaction_data = raw_tx[80:]
        # Try from 1024 (1KiB) -> 1073741824 (1GiB) slice widths
        for j in range(0, 20):
            try:
                offset_e: int = offset + (1024 * 2 ** j)
                transaction = Transaction.from_bytes(
                    transaction_data[offset:offset_e]
                )
                return transaction
            except Exception:
                continue
        return None
