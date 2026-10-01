// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprAlgorandStateProof
/// @notice Encodings and arithmetic of Algorand state proofs, checked against go-algorand
///         (crypto/stateproof, data/stateproofmsg, data/bookkeeping, crypto/merklearray):
///
///   message hash      SHA-256("spm" ‖ msgpack(Message)), Message = {P lnProvenWeight, b
///                     BlockHeadersCommitment, f FirstAttestedRound, l LastAttestedRound, v
///                     VotersCommitment} (canonical: sorted keys, empty fields omitted)
///   weights           `verifyWeights`: numReveals·(x + w·y) ≥ (T·ln2 + numReveals·lnProvenWeight)·y
///   coin seed         "spc" ‖ 0x00 ‖ votersCommitment ‖ lnProvenWeight LE64 ‖ sigCommit ‖
///                     signedWeight LE64 ‖ messageHash, expanded with SHAKE256; 64-bit little-endian
///                     samples, rejection above ⌊2^64 / W⌋·W, coin = sample mod W
///   light header      SHA-256("B256" ‖ msgpack{"1" BlockHash, "gh" GenesisHash, "r" Round,
///                     "tc" Sha256TxnCommitment}) (consensus ≥ v39: BlockHash replaces Seed)
///   transaction leaf  SHA-256("TL" ‖ SHA-256 txid ‖ SHA-256("STIB" ‖ SignedTxnInBlock))
///   vector commitment leaf at tree position reverseBits(index, depth); node = H("MA" ‖ left ‖ right)
library ClprAlgorandStateProof {
    uint64 internal constant STRENGTH_TARGET = 256; // consensus StateProofStrengthTarget (v34+)
    uint256 internal constant LN2 = 45427; // ⌈2^16 · ln 2⌉
    uint256 internal constant MAX_REVEALS = 640;

    struct Message {
        bytes32 blockHeadersCommitment;
        bytes votersCommitment; // 64 bytes (SumHash512)
        uint64 lnProvenWeight;
        uint64 firstAttestedRound;
        uint64 lastAttestedRound;
    }

    /// @notice Canonical msgpack of a state-proof message.
    function encodeMessage(Message memory m) internal pure returns (bytes memory out) {
        uint256 n;
        bytes memory body;
        if (m.lnProvenWeight != 0) {
            body = abi.encodePacked(body, uint8(0xa1), "P", encodeUint(m.lnProvenWeight));
            n++;
        }
        if (m.blockHeadersCommitment != bytes32(0)) {
            body = abi.encodePacked(body, uint8(0xa1), "b", uint8(0xc4), uint8(32), m.blockHeadersCommitment);
            n++;
        }
        if (m.firstAttestedRound != 0) {
            body = abi.encodePacked(body, uint8(0xa1), "f", encodeUint(m.firstAttestedRound));
            n++;
        }
        if (m.lastAttestedRound != 0) {
            body = abi.encodePacked(body, uint8(0xa1), "l", encodeUint(m.lastAttestedRound));
            n++;
        }
        if (m.votersCommitment.length != 0) {
            // forge-lint: disable-next-line(unsafe-typecast)
            body = abi.encodePacked(
                body, uint8(0xa1), "v", uint8(0xc4), uint8(m.votersCommitment.length), m.votersCommitment
            );
            n++;
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        out = abi.encodePacked(uint8(0x80 | n), body); // n ≤ 5
    }

    /// @notice SHA-256 message hash that participants sign.
    function messageHash(Message memory m) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("spm", encodeMessage(m)));
    }

    /// @notice Minimal msgpack unsigned integer.
    function encodeUint(uint64 v) internal pure returns (bytes memory) {
        // forge-lint: disable-start(unsafe-typecast)
        if (v < 0x80) return abi.encodePacked(uint8(v));
        if (v < 0x100) return abi.encodePacked(uint8(0xcc), uint8(v));
        if (v < 0x10000) return abi.encodePacked(uint8(0xcd), uint16(v));
        if (v < 0x100000000) return abi.encodePacked(uint8(0xce), uint32(v));
        // forge-lint: disable-end(unsafe-typecast)
        return abi.encodePacked(uint8(0xcf), v);
    }

    /// @notice go-algorand `verifyWeights` (crypto/stateproof/weights.go), exact integer arithmetic.
    function weightsOk(uint64 signedWeight, uint64 lnProvenWeight, uint256 numReveals) internal pure returns (bool) {
        if (numReveals > MAX_REVEALS || signedWeight == 0) return false;
        uint256 sw = signedWeight;
        uint256 d = _bitLen(sw) - 1;
        uint256 sw2 = sw * sw;
        uint256 y = (uint256(1) << (2 * d)) + (uint256(1) << (d + 2)) * sw + sw2;
        uint256 x = (sw2 - (uint256(1) << (2 * d))) * 3 * (uint256(1) << 16);
        uint256 w = d * (LN2 - 1);
        uint256 lhs = numReveals * (x + w * y);
        uint256 rhs = (uint256(STRENGTH_TARGET) * LN2 + numReveals * lnProvenWeight) * y;
        return lhs >= rhs;
    }

    /// @notice Coin-generator seed (`coinChoiceSeed.ToBeHashed` with its "spc" hash id).
    function coinSeed(
        bytes memory votersCommitment,
        uint64 lnProvenWeight,
        bytes memory sigCommit,
        uint64 signedWeight,
        bytes32 msgHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            "spc", uint8(0), votersCommitment, le64(lnProvenWeight), sigCommit, le64(signedWeight), msgHash
        );
    }

    /// @notice Canonical msgpack + leaf hash of a light block header.
    function lightHeaderLeaf(bytes32 blockHash, bytes32 genesisHash, uint64 round, bytes32 txnCommitment)
        internal
        pure
        returns (bytes32)
    {
        bytes memory enc = abi.encodePacked(
            uint8(0x84),
            uint8(0xa1),
            "1",
            uint8(0xc4),
            uint8(32),
            blockHash,
            uint8(0xa2),
            "gh",
            uint8(0xc4),
            uint8(32),
            genesisHash,
            uint8(0xa1),
            "r",
            encodeUint(round),
            uint8(0xa2),
            "tc",
            uint8(0xc4),
            uint8(32),
            txnCommitment
        );
        return sha256(abi.encodePacked("B256", enc));
    }

    /// @notice Transaction-tree leaf of a SignedTxnInBlock with SHA-256 id `txid`.
    function txnLeaf(bytes32 txid, bytes memory stib) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("TL", txid, sha256(abi.encodePacked("STIB", stib))));
    }

    /// @notice Root of a SHA-256 vector commitment from one leaf and its bottom-up path
    ///         (`path.length / 32` = tree depth; `index < 2^depth`). Returns 0 on a malformed path.
    function sha256Root(bytes32 leaf, uint256 index, bytes memory path) internal pure returns (bytes32 h) {
        if (path.length % 32 != 0) return bytes32(0);
        uint256 depth = path.length / 32;
        if (depth > 32 || index >> depth != 0) return bytes32(0);
        uint256 tp = reverseBits(index, depth);
        h = leaf;
        for (uint256 l = 0; l < depth; l++) {
            bytes32 s;
            assembly ("memory-safe") {
                s := mload(add(add(path, 0x20), shl(5, l)))
            }
            h = (tp & 1) == 0 ? sha256(abi.encodePacked("MA", h, s)) : sha256(abi.encodePacked("MA", s, h));
            tp >>= 1;
        }
    }

    function reverseBits(uint256 v, uint256 depth) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < depth; i++) {
            r = (r << 1) | ((v >> i) & 1);
        }
    }

    function le64(uint64 v) internal pure returns (bytes8 out) {
        uint64 r;
        for (uint256 i = 0; i < 8; i++) {
            r = (r << 8) | ((v >> (8 * i)) & 0xff);
        }
        out = bytes8(r);
    }

    function _bitLen(uint256 x) private pure returns (uint256 n) {
        while (x != 0) {
            x >>= 1;
            n++;
        }
    }
}
