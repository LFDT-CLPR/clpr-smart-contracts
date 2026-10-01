// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title AntelopeLib
/// @notice Antelope (Spring / Leap) binary encodings, digests and Merkle trees, as used by the
///         Antelope verifiers. Every rule below is taken from AntelopeIO/spring v1.2.2 (also checked
///         against v1.0.5) and AntelopeIO/leap v3.1.2 / v5.0.3; file references are in the README.
/// @dev Antelope packs integers little-endian, `unsigned_int` as LEB128, `vector<char>` as a varint
///      length followed by the bytes, and hashes with SHA-256 (fc::sha256).
library AntelopeLib {
    error AntelopeDecode();
    error MerkleIndexOutOfRange();
    error MerkleProofLength();

    // ── Integers ──────────────────────────────────────────────────────────────

    /// @dev Reverse the byte order of a uint64.
    function bswap64(uint64 v) internal pure returns (uint64) {
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        return (v >> 32) | (v << 32);
    }

    /// @dev Reverse the byte order of a uint32.
    function bswap32(uint32 v) internal pure returns (uint32) {
        v = ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
        return (v >> 16) | (v << 16);
    }

    /// @dev Reverse the byte order of a 256-bit word.
    function bswap256(uint256 v) internal pure returns (uint256) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        return (v >> 128) | (v << 128);
    }

    /// @dev Little-endian bytes of a uint32 (4 bytes).
    function le32(uint32 v) internal pure returns (bytes4) {
        return bytes4(bswap32(v));
    }

    /// @dev Little-endian bytes of a uint64 (8 bytes).
    function le64(uint64 v) internal pure returns (bytes8) {
        return bytes8(bswap64(v));
    }

    /// @dev Read `n` (<= 32) bytes at `off` as a big-endian unsigned integer.
    // forge-lint: disable-next-line(mixed-case-function)
    function _readBE(bytes memory b, uint256 off, uint256 n) private pure returns (uint256 v) {
        if (off + n > b.length) revert AntelopeDecode();
        assembly ("memory-safe") {
            v := shr(sub(256, mul(n, 8)), mload(add(add(b, 0x20), off)))
        }
    }

    function readU8(bytes memory b, uint256 off) internal pure returns (uint8) {
        return uint8(_readBE(b, off, 1));
    }

    function readU16(bytes memory b, uint256 off) internal pure returns (uint16) {
        uint256 v = _readBE(b, off, 2);
        return uint16((v >> 8) | ((v & 0xFF) << 8));
    }

    function readU32(bytes memory b, uint256 off) internal pure returns (uint32) {
        return bswap32(uint32(_readBE(b, off, 4)));
    }

    function readU64(bytes memory b, uint256 off) internal pure returns (uint64) {
        return bswap64(uint64(_readBE(b, off, 8)));
    }

    function readBytes32(bytes memory b, uint256 off) internal pure returns (bytes32 v) {
        if (off + 32 > b.length) revert AntelopeDecode();
        assembly ("memory-safe") {
            v := mload(add(add(b, 0x20), off))
        }
    }

    /// @dev fc::unsigned_int (LEB128, at most 5 bytes for a uint32).
    function readVarUint(bytes memory b, uint256 off) internal pure returns (uint256 v, uint256 next) {
        uint256 shift;
        for (uint256 i = 0; i < 5; ++i) {
            uint8 x = readU8(b, off + i);
            v |= uint256(x & 0x7F) << shift;
            if (x & 0x80 == 0) return (v, off + i + 1);
            shift += 7;
        }
        revert AntelopeDecode();
    }

    /// @dev LEB128 encoding of `v`.
    function varUint(uint256 v) internal pure returns (bytes memory out) {
        uint256 n = 1;
        for (uint256 t = v >> 7; t != 0; t >>= 7) {
            ++n;
        }
        out = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 x = uint8(v & 0x7F);
            v >>= 7;
            out[i] = bytes1(i + 1 < n ? x | 0x80 : x);
        }
    }

    /// @dev Copy `len` bytes of `b` starting at `off`.
    function slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        if (off + len > b.length) revert AntelopeDecode();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), off), len)
        }
    }

    // ── Names ─────────────────────────────────────────────────────────────────

    /// @dev eosio::name value of a string (a-z, 1-5, '.', at most 12 characters; 13th char unsupported).
    function nameValue(string memory s) internal pure returns (uint64 v) {
        bytes memory b = bytes(s);
        if (b.length > 12) revert AntelopeDecode();
        for (uint256 i = 0; i < 12; ++i) {
            uint64 c = 0;
            if (i < b.length) {
                uint8 ch = uint8(b[i]);
                if (ch >= 0x61 && ch <= 0x7a) c = uint64(ch - 0x61 + 6);
                else if (ch >= 0x31 && ch <= 0x35) c = uint64(ch - 0x31 + 1);
                else if (ch != 0x2e) revert AntelopeDecode();
            }
            v |= (c & 0x1f) << uint64(64 - 5 * (i + 1));
        }
    }

    // ── Actions and receipts ──────────────────────────────────────────────────

    /// @dev `generate_action_digest` (spring action.hpp; leap v3 action.hpp under ACTION_RETURN_VALUE):
    ///      sha256( sha256(pack(action_base)) || sha256(pack(data) || pack(return_value)) ),
    ///      where action_base = (account, name, authorization) and `actionBase` is its packed form.
    function actionDigest(bytes memory actionBase, bytes memory data, bytes memory returnValue)
        internal
        pure
        returns (bytes32)
    {
        bytes32 h0 = sha256(actionBase);
        bytes32 h1 = sha256(abi.encodePacked(varUint(data.length), data, varUint(returnValue.length), returnValue));
        return sha256(abi.encodePacked(h0, h1));
    }

    /// @dev Savanna action receipt digest (`action_trace::digest_savanna`, spring trace.hpp):
    ///      sha256(receiver, recv_sequence, act.account, act.name, act_digest, savanna_witness_hash),
    ///      where the witness hash commits to global_sequence, auth_sequence, code and abi sequences.
    function savannaReceiptDigest(
        uint64 receiver,
        uint64 recvSequence,
        uint64 account,
        uint64 actionName,
        bytes32 actDigest,
        bytes32 witnessHash
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                le64(receiver), le64(recvSequence), le64(account), le64(actionName), actDigest, witnessHash
            )
        );
    }

    /// @dev Legacy action receipt digest (`action_trace::digest_legacy`; leap `action_receipt::digest`):
    ///      sha256(receiver, act_digest, global_sequence, recv_sequence, auth_sequence, code_sequence,
    ///      abi_sequence). `tail` is the packed form of the fields after act_digest.
    function legacyReceiptDigest(uint64 receiver, bytes32 actDigest, bytes memory tail)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(le64(receiver), actDigest, tail));
    }

    // ── Merkle trees ──────────────────────────────────────────────────────────

    /// @dev Root of a Savanna Merkle tree (`calculate_merkle`, spring merkle.hpp) from a leaf, its
    ///      index, the leaf count and the siblings bottom-up. Inner node = sha256(left || right); a
    ///      node without a right neighbour is promoted unhashed; a one-leaf tree's root is the leaf.
    ///      (Equivalent to the left-complete split `calculate_merkle` uses; see svnn_ibc savanna.hpp.)
    function savannaMerkleRoot(bytes32 leaf, uint256 index, uint256 count, bytes32[] memory siblings)
        internal
        pure
        returns (bytes32 node)
    {
        if (index >= count) revert MerkleIndexOutOfRange();
        node = leaf;
        uint256 used;
        while (count > 1) {
            if (index & 1 == 1) {
                if (used >= siblings.length) revert MerkleProofLength();
                node = sha256(abi.encodePacked(siblings[used++], node));
            } else if (index + 1 < count) {
                if (used >= siblings.length) revert MerkleProofLength();
                node = sha256(abi.encodePacked(node, siblings[used++]));
            }
            index >>= 1;
            count = (count + 1) >> 1;
        }
        if (used != siblings.length) revert MerkleProofLength();
    }

    /// @dev Root of a legacy (pre-Savanna) Merkle tree (`calculate_merkle_legacy` / leap `merkle`):
    ///      an odd layer duplicates its last node; before hashing, the left node's first byte gets its
    ///      top bit cleared and the right node's first byte gets it set (`make_canonical_pair`).
    function legacyMerkleRoot(bytes32 leaf, uint256 index, uint256 count, bytes32[] memory siblings)
        internal
        pure
        returns (bytes32 node)
    {
        if (index >= count) revert MerkleIndexOutOfRange();
        node = leaf;
        uint256 used;
        while (count > 1) {
            bytes32 other;
            if (index & 1 == 1) {
                if (used >= siblings.length) revert MerkleProofLength();
                other = siblings[used++];
                node = sha256(abi.encodePacked(_canonicalLeft(other), _canonicalRight(node)));
            } else {
                if (index + 1 < count) {
                    if (used >= siblings.length) revert MerkleProofLength();
                    other = siblings[used++];
                } else {
                    other = node; // odd layer: the last node is paired with itself
                }
                node = sha256(abi.encodePacked(_canonicalLeft(node), _canonicalRight(other)));
            }
            index >>= 1;
            count = (count + 1) >> 1;
        }
        if (used != siblings.length) revert MerkleProofLength();
    }

    function _canonicalLeft(bytes32 h) private pure returns (bytes32) {
        return h & ~bytes32(uint256(0x80) << 248);
    }

    function _canonicalRight(bytes32 h) private pure returns (bytes32) {
        return h | bytes32(uint256(0x80) << 248);
    }

    // ── Legacy block headers ──────────────────────────────────────────────────

    /// @dev Byte offsets of the fixed part of a packed `block_header` (leap block_header.hpp):
    ///      timestamp u32 | producer name | confirmed u16 | previous | transaction_mroot |
    ///      action_mroot | schedule_version u32 | new_producers optional | header_extensions.
    uint256 internal constant HDR_PRODUCER = 4;
    uint256 internal constant HDR_CONFIRMED = 12;
    uint256 internal constant HDR_PREVIOUS = 14;
    uint256 internal constant HDR_ACTION_MROOT = 78;
    uint256 internal constant HDR_SCHEDULE_VERSION = 110;
    uint256 internal constant HDR_NEW_PRODUCERS = 114;
    uint256 internal constant HDR_EXTENSIONS = 115;

    /// @dev Block number encoded in the first 4 bytes of a block id (`num_from_id`).
    function blockNumFromId(bytes32 id) internal pure returns (uint32) {
        return uint32(uint256(id) >> 224);
    }

    /// @dev Block id (`calculate_id`): sha256(header) with its first 4 bytes replaced by the block
    ///      number, big-endian. The block number is num_from_id(previous) + 1.
    function blockId(bytes32 headerDigest, uint32 num) internal pure returns (bytes32) {
        return bytes32((uint256(headerDigest) & ((uint256(1) << 224) - 1)) | (uint256(num) << 224));
    }
}
