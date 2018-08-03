# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Transaction-related classes and functions.'''


from collections import namedtuple
from struct import pack

from electrumx.lib.hash import sha256, double_sha256, hash_to_hex_str
from electrumx.lib.util import (
    cachedproperty, unpack_int32_from, unpack_int64_from,
    unpack_uint16_from, unpack_uint32_from, unpack_uint64_from
)


class Tx(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase

    # FIXME: add hash as a cached property?


class TxInput(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    '''Class representing a transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInput.ZERO and
                self.prev_idx == TxInput.MINUS_1)

    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))


class TxOutput(namedtuple("TxOutput", "value pk_script")):
    pass


class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    TX_HASH_FN = staticmethod(double_sha256)

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return self.read_tx(), self.TX_HASH_FN(self.binary[start:self.cursor])

    def read_tx_and_vsize(self):
        '''Return a (deserialized TX, vsize) pair.'''
        return self.read_tx(), self.binary_length

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        # Some coins have excess data beyond the end of the transactions
        return [read() for _ in range(self._read_varint())]

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxInput(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


class TxSegWit(namedtuple("Tx", "version marker flag inputs outputs "
                          "witness locktime")):
    '''Class representing a SegWit transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerSegWit(Deserializer):

    # https://bitcoincore.org/en/segwit_wallet_dev/#transaction-serialization

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for i in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for i in range(self._read_varint())]

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        marker = self.binary[self.cursor + 4]
        if marker:
            tx = super().read_tx()
            tx_hash = self.TX_HASH_FN(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        # Ugh, this is nasty.
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        return TxSegWit(version, marker, flag, inputs, outputs, witness,
                        locktime), self.TX_HASH_FN(orig_ser), vsize

    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize

class TxOcean(namedtuple("Tx", "version flag inputs outputs "
                          "locktime inwitness outwitness")):
    '''Class representing an Ocean transaction.'''
    CONFIDENTIAL_COMMITMENT = 33    # default size of confidential commitments (i.e. asset, value, nonce)
    CONFIDENTIAL_VALUE = 9          # explciti size of confidential values

    @cachedproperty
    def is_coinbase(self):
        return (self.inputs[0].is_coinbase or
                self.inputs[0].is_initial_issuance)

class TxInputOcean(namedtuple("TxInput", "prev_hash prev_idx script sequence issuance")):
    '''Class representing a transaction input.'''
    ZERO = bytes(32)
    MINUS_1 = 4294967295
    OUTPOINT_ISSUANCE_FLAG = (1 << 31)
    OUTPOINT_INDEX_MASK = 0x3fffffff

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInputOcean.ZERO and
                self.prev_idx == TxInputOcean.MINUS_1)

    ''' MAYBE not the best way of doing this
    Initial issuance should not have a prev_hash but in ocean this is set to
    a dummy commitment to the genesis arguments to be replaced by an actual
    pegin bitcoin hash. Possible solution would be to hardcode prev_hash
    Same treatment with coinbase transactions
    '''
    @cachedproperty
    def is_initial_issuance(self):
        return (self.is_issuance and
                self.sequence == TxInputOcean.MINUS_1)

    @cachedproperty
    def is_issuance(self):
        return (self.issuance is not None)

    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))

class TxOutputOcean(namedtuple("TxOutput", "asset value nonce pk_script")):
    '''Class representing a transaction output.'''
    pass

class TxInputIssuanceOcean(namedtuple("TxInputIssuance", "nonce entropy amount inflation")):
    '''Class representing a transaction input issuance.'''
    pass

class DeserializerOcean(Deserializer):
    WITNESS_SCALE_FACTOR = 4;

    '''
    Ocean Block Header sample
    00000020    version
    f2f7342df785645fc5b28e4db3261eef0b4ef57ee787068374b103854cd65b08    prevhash
    713ccf4863baa2d3cd2ed82b25e866dc660b0e1d9f359147fc968cd2ee074c99    hashMerkleRoot
    5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456    hashContract
    0000000000000000000000000000000000000000000000000000000000000000    hashAttestation
    a4375f5b    nTime
    01000000    nHeight
    69          script challenge
    522103d517f6e9affa60000a08d478970e6bbfa45d63b1967ed1e066dd46b802edb2a62102afc18e8a7ff988ca1ae7b659cb09a79852d301c2283e18cba1faf7a0b020b1a22102edd8080e31f05c68cf68a97782ac97744e86ba19dfd3ba68e597f10868ee5bc453ae
    8e          script proof
    0046304402201a822d9a7f211fbfbf2bb92ead874c71967dbd3c9e0249931cabb7591f36a46602207acbd97989005d0f16b6b6de84b03f3c659de28649a67cf2664e79badadf20c4453043021f5e1e160aa0e6afb078e9e2428d60a146598df03d48ede67799242109c2b690022023253a6381ea8cd07410903e97be730823a48a79bac16c4e097fe3fc54060888
    '''
    def read_header(self, height, static_header_size):
        '''Return the Ocean block header bytes'''
        start = self.cursor
        self.cursor += static_header_size

        challenge_size = self._read_varint() # read challenge size - 2 bytes
        if challenge_size:
            self.cursor += challenge_size # read challenge - challenge_size bytes

        proof_size = self._read_varint() # read proof size - 2 bytes
        if proof_size:
            self.cursor += proof_size # read proof

        header_end = self.cursor
        self.cursor = start
        return self._read_nbytes(header_end)

    '''
    Ocean Transaction sample
    02000000    version
    01          flag

    01          # of vins
    0000000000000000000000000000000000000000000000000000000000000000    vin prevhash
    ffffffff    vin prev_idx
    03  530101  script
    ffffffff    sequence
        - issuance example (if prev_idx & TxInputOcean.OUTPOINT_ISSUANCE_FLAG)
        0000000000000000000000000000000000000000000000000000000000000000    nonce 32bytes
        0000000000000000000000000000000000000000000000000000000000000000    entropy 32bytes
        01  00038d7ea4c68000  amount (confidential value)
        00                    inflation (confidential value)

    02          # of vouts

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1    asset (confidential asset)
    01  000000000000de80    value (confidential value)
    00                      nonce (confidential nonce)
    01  51                  script

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1
    01  0000000000000000
    00
    26  6a24aa21a9ed2127440070600b5e8482e5df5815cc15b8262acf7533136c501f3cb4801faaf6

    00000000 locktime

    # for each vin - CTxInWitness
    00  issuance amount range proof
    00  inflation range proof
    01  num of script witnesses
    20 0000000000000000000000000000000000000000000000000000000000000000 script witness
    00  num of pegin witnesses

    # for each vout - CTxOutWitness
    00  surjection proof
    00  range proof
    00  surjection proof
    00  range proof
    '''
    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        flag = self._read_byte()    # for witness
        orig_ser += b'\x00'     # for serialization hash flag is always 0

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()

        orig_ser += self.binary[start:self.cursor]

        start = self.cursor
        witness_in = []
        witness_out = []
        if flag & 1:
            witness_in = self._read_witness_in(len(inputs))
            witness_out = self._read_witness_out(len(outputs))

        base_size = len(orig_ser)
        full_size = base_size + len(self.binary[start:self.cursor])
        vsize = ((self.WITNESS_SCALE_FACTOR-1) * base_size + full_size + self.WITNESS_SCALE_FACTOR - 1) // self.WITNESS_SCALE_FACTOR

        #print(double_sha256(orig_ser))
        return TxOcean(version, flag, inputs, outputs, witness_in, witness_out,
                        locktime), double_sha256(orig_ser), vsize

    def _read_input(self):
        '''Return a TxInputOcean object'''
        prev_hash = self._read_nbytes(32)
        prev_idx = self._read_le_uint32()
        script = self._read_varbytes()
        sequence = self._read_le_uint32()

        issuance = None
        if prev_idx != TxInputOcean.MINUS_1:
            if prev_idx & TxInputOcean.OUTPOINT_ISSUANCE_FLAG:
                issuance_nonce = self._read_nbytes(32)
                issuance_entropy = self._read_nbytes(32)

                amount = self._read_confidential_value()
                inflation = self._read_confidential_value()

                issuance = TxInputIssuanceOcean(
                    issuance_nonce,
                    issuance_entropy,
                    amount,
                    inflation
                )
                prev_idx &= TxInputOcean.OUTPOINT_INDEX_MASK

        return TxInputOcean(
            prev_hash,
            prev_idx,
            script,
            sequence,
            issuance
        )

    def _read_output(self):
        '''Return a TxOutputOcean object'''
        asset = self._read_confidential_asset()
        value = self._read_confidential_value()
        nonce = self._read_confidential_nonce()
        script = self._read_varbytes()

        return TxOutputOcean(
            asset,
            value,
            nonce,
            script
        )

    # CConfidentialValue size 9, prefixA 8, prefixB 9
    def _read_confidential_value(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_VALUE-1)
        elif version == 8 or version == 9:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    # CConfidentialAsset size 33, prefixA 10, prefixB 11
    def _read_confidential_asset(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        elif version == 10 or version == 11:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    # CConfidentialNonce size 33, prefixA 2, prefixB 3
    def _read_confidential_nonce(self):
        version = self._read_byte()
        if version == 1 or version == 0xff:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        elif version == 2 or version == 3:
            return bytes([version]) + self._read_nbytes(TxOcean.CONFIDENTIAL_COMMITMENT-1)
        return bytes([version])

    def _read_witness_in(self, fields):
        read_witness_in_field = self._read_witness_in_field
        return [read_witness_in_field() for i in range(fields)]

    def _read_witness_in_field(self):
        read_varbytes = self._read_varbytes
        issuance_range_proof = read_varbytes()
        inflation_range_proof = read_varbytes()
        script_witness = [read_varbytes() for i in range(self._read_varint())]
        pegin_witness = [read_varbytes() for i in range(self._read_varint())]

        return [issuance_range_proof, inflation_range_proof, script_witness, pegin_witness]

    def _read_witness_out(self, fields):
        read_witness_out_field = self._read_witness_out_field
        return [read_witness_out_field() for i in range(fields)]

    def _read_witness_out_field(self):
        read_varbytes = self._read_varbytes
        surjection_proof = read_varbytes()
        range_proof = read_varbytes()

        return [surjection_proof, range_proof]

class DeserializerAuxPow(Deserializer):
    VERSION_AUXPOW = (1 << 8)

    def read_header(self, height, static_header_size):
        '''Return the AuxPow block header bytes'''
        start = self.cursor
        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            # We are going to calculate the block size then read it as bytes
            self.cursor = start
            self.cursor += static_header_size  # Block normal header
            self.read_tx()  # AuxPow transaction
            self.cursor += 32  # Parent block hash
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Merkle branch
            self.cursor += 4  # Index
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Chain merkle branch
            self.cursor += 4  # Chain index
            self.cursor += 80  # Parent block header
            header_end = self.cursor
        else:
            header_end = static_header_size
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerAuxPowSegWit(DeserializerSegWit, DeserializerAuxPow):
    pass


class DeserializerEquihash(Deserializer):
    def read_header(self, height, static_header_size):
        '''Return the block header bytes'''
        start = self.cursor
        # We are going to calculate the block size then read it as bytes
        self.cursor += static_header_size
        solution_size = self._read_varint()
        self.cursor += solution_size
        header_end = self.cursor
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerEquihashSegWit(DeserializerSegWit, DeserializerEquihash):
    pass


class TxJoinSplit(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a JoinSplit transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase if len(self.inputs) > 0 else False


class DeserializerZcash(DeserializerEquihash):
    def read_tx(self):
        header = self._read_le_uint32()
        overwinterd = ((header >> 31) == 1)
        if overwinterd:
            version = header & 0x7fffffff
            self._read_le_uint32()  # versionGroupId
        else:
            version = header
        base_tx = TxJoinSplit(
            version,
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )
        if base_tx.version >= 3:
            self._read_le_uint32()  # expiryHeight
        if base_tx.version >= 2:
            joinsplit_size = self._read_varint()
            if joinsplit_size > 0:
                self.cursor += joinsplit_size * 1802  # JSDescription
                self.cursor += 32  # joinSplitPubKey
                self.cursor += 64  # joinSplitSig
        return base_tx


class TxTime(namedtuple("Tx", "version time inputs outputs locktime")):
    '''Class representing transaction that has a time field.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerTxTime(Deserializer):
    def read_tx(self):
        return TxTime(
            self._read_le_int32(),   # version
            self._read_le_uint32(),  # time
            self._read_inputs(),     # inputs
            self._read_outputs(),    # outputs
            self._read_le_uint32(),  # locktime
        )


class DeserializerReddcoin(Deserializer):
    def read_tx(self):
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if version > 1:
            time = self._read_le_uint32()
        else:
            time = 0

        return TxTime(version, time, inputs, outputs, locktime)


class DeserializerTxTimeAuxPow(DeserializerTxTime):
    VERSION_AUXPOW = (1 << 8)

    def is_merged_block(self):
        start = self.cursor
        self.cursor = 0
        version = self._read_le_uint32()
        self.cursor = start
        if version & self.VERSION_AUXPOW:
            return True
        return False

    def read_header(self, height, static_header_size):
        '''Return the AuxPow block header bytes'''
        start = self.cursor
        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            # We are going to calculate the block size then read it as bytes
            self.cursor = start
            self.cursor += static_header_size  # Block normal header
            self.read_tx()  # AuxPow transaction
            self.cursor += 32  # Parent block hash
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Merkle branch
            self.cursor += 4  # Index
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Chain merkle branch
            self.cursor += 4  # Chain index
            self.cursor += 80  # Parent block header
            header_end = self.cursor
        else:
            header_end = static_header_size
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerBitcoinAtom(DeserializerSegWit):
    FORK_BLOCK_HEIGHT = 505888

    def read_header(self, height, static_header_size):
        '''Return the block header bytes'''
        header_len = static_header_size
        if height >= self.FORK_BLOCK_HEIGHT:
            header_len += 4  # flags
        return self._read_nbytes(header_len)


class DeserializerGroestlcoin(DeserializerSegWit):
    TX_HASH_FN = staticmethod(sha256)


# Decred
class TxInputDcr(namedtuple("TxInput", "prev_hash prev_idx tree sequence")):
    '''Class representing a Decred transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInputDcr.ZERO and
                self.prev_idx == TxInputDcr.MINUS_1)

    def __str__(self):
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, tree={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, self.tree, self.sequence))


class TxOutputDcr(namedtuple("TxOutput", "value version pk_script")):
    '''Class representing a Decred transaction output.'''
    pass


class TxDcr(namedtuple("Tx", "version inputs outputs locktime expiry "
                             "witness")):
    '''Class representing a Decred  transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerDecred(Deserializer):
    @staticmethod
    def blake256(data):
        from blake256.blake256 import blake_hash
        return blake_hash(data)

    @staticmethod
    def blake256d(data):
        from blake256.blake256 import blake_hash
        return blake_hash(blake_hash(data))

    def read_tx(self):
        return self._read_tx_parts(produce_hash=False)[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts(produce_hash=False)
        return tx, vsize

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        txs = [read() for _ in range(self._read_varint())]
        stxs = [read() for _ in range(self._read_varint())]
        return txs + stxs

    def read_tx_tree(self):
        '''Returns a list of deserialized_tx without tx hashes.'''
        read_tx = self.read_tx
        return [read_tx() for _ in range(self._read_varint())]

    def _read_input(self):
        return TxInputDcr(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_byte(),       # tree
            self._read_le_uint32(),  # sequence
        )

    def _read_output(self):
        return TxOutputDcr(
            self._read_le_int64(),  # value
            self._read_le_uint16(),  # version
            self._read_varbytes(),  # pk_script
        )

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        assert fields == self._read_varint()
        return [read_witness_field() for _ in range(fields)]

    def _read_witness_field(self):
        value_in = self._read_le_int64()
        block_height = self._read_le_uint32()
        block_index = self._read_le_uint32()
        script = self._read_varbytes()
        return value_in, block_height, block_index, script

    def _read_tx_parts(self, produce_hash=True):
        start = self.cursor
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        expiry = self._read_le_uint32()
        end_prefix = self.cursor
        witness = self._read_witness(len(inputs))

        # Drop the coinbase-like input from a vote tx as it creates problems
        # with UTXOs lookups and mempool management
        if inputs[0].is_coinbase and len(inputs) > 1:
            inputs = inputs[1:]

        if produce_hash:
            # TxSerializeNoWitness << 16 == 0x10000
            no_witness_header = pack('<I', 0x10000 | (version & 0xffff))
            prefix_tx = no_witness_header + self.binary[start+4:end_prefix]
            tx_hash = self.blake256(prefix_tx)
        else:
            tx_hash = None

        return TxDcr(
            version,
            inputs,
            outputs,
            locktime,
            expiry,
            witness
        ), tx_hash, self.cursor - start
