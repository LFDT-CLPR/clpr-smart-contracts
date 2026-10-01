// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";

/// @title TezosContextProof
/// @notice Verifies that a value sits at a path of a Tezos context tree (Irmin, as configured by
///         octez `src/lib_context/encoding/context.ml`: BLAKE2b-256, 32-way inodes, stable hash for
///         directories of at most 256 entries).
///
/// Hashing rules (checked against live `merkle_tree_v2` proofs from Tezos mainnet):
///   contents           H(u64be(len) ‖ value)
///   stable directory   H(u64be(n) ‖ Σ_sorted [kind8 ‖ varint(len) ‖ name ‖ u64be(32) ‖ hash])
///                      kind8 = ff00000000000000 (contents) | 0000000000000000 (directory)
///   inode tree         H(0x01 ‖ varint(depth) ‖ varint(length) ‖ varint(k) ‖ Σ [varint(index) ‖ hash])
///   inode values       H(0x00 ‖ varint(k) ‖ Σ [varint(len) ‖ name ‖ tag ‖ hash])  tag 0 directory, 1 contents
///
/// Proof format (top-down, one entry per hashed object on the path):
///   level := kind(1) ‖ len(u16be) ‖ preimage ‖ [pointer(1) when kind = INODE_TREE]
///   then   valueLen(u32be) ‖ value
/// A stable-directory or inode-values level is searched by name for the next path step; an inode
/// tree level names which of its pointers to follow (it consumes no path step). Every preimage is
/// hashed and compared with the hash the parent level (or the root) committed to, every preimage
/// must parse exactly, and the kind recorded by the parent (directory vs contents) must match the
/// position on the path, so a contents hash can never be read as a directory.
library TezosContextProof {
    uint8 internal constant LEVEL_V1 = 0;
    uint8 internal constant LEVEL_INODE_TREE = 1;
    uint8 internal constant LEVEL_INODE_VALUES = 2;

    error ProofTruncated();
    error ProofHashMismatch(uint256 level);
    error ProofMalformed(uint256 level);
    error ProofStepNotFound(uint256 step);
    error ProofKindMismatch(uint256 step);
    error ProofTrailingBytes();
    error ProofEntryPresent(uint256 level);

    struct Cursor {
        uint256 base; // memory address of proof[0]
        uint256 end; // memory address one past the proof
        uint256 p; // current read address
    }

    /// @notice Verify `proof` for `steps` under the context tree `root`; returns the value.
    /// @notice Verify `proof` for `steps` under the context tree `root`; returns the value. If
    ///         `absentName` is non-zero, also require that the directory which lists
    ///         `steps[absentStep]` has no entry whose name hashes (keccak256) to `absentName`; that
    ///         directory must then be a stable (fully listed) directory, so absence is proven.
    function verify(bytes32 root, bytes[] memory steps, bytes memory proof, uint256 absentStep, bytes32 absentName)
        internal
        view
        returns (bytes memory value)
    {
        Cursor memory c;
        assembly ("memory-safe") {
            mstore(c, add(proof, 0x20))
            mstore(add(c, 0x20), add(add(proof, 0x20), mload(proof)))
            mstore(add(c, 0x40), add(proof, 0x20))
        }
        bytes32 expected = root;
        uint256 level = 0;
        for (uint256 s = 0; s < steps.length; s++) {
            bytes32 stepHash = keccak256(steps[s]);
            bool isContents;
            // Descend through inode-tree levels until a level lists `steps[s]` by name.
            for (;;) {
                (uint8 kind, uint256 pre, uint256 len) = _readLevel(c);
                if (TezosBlake2b.hashAt(pre, len, TezosBlake2b.H0_32) != expected) revert ProofHashMismatch(level);
                if (kind == LEVEL_INODE_TREE) {
                    if (s == absentStep) revert ProofMalformed(level); // absence needs a full listing
                    uint256 ptr = _u8(c);
                    expected = _inodeTreePointer(pre, len, ptr, level);
                    level++;
                    continue;
                }
                bool found;
                if (kind == LEVEL_V1) {
                    (found, isContents, expected) =
                        _findV1(pre, len, stepHash, level, s == absentStep ? absentName : bytes32(0));
                } else if (kind == LEVEL_INODE_VALUES) {
                    if (s == absentStep) revert ProofMalformed(level);
                    (found, isContents, expected) = _findValues(pre, len, stepHash, level);
                } else {
                    revert ProofMalformed(level);
                }
                if (!found) revert ProofStepNotFound(s);
                level++;
                break;
            }
            // Intermediate steps must be directories; the last step must be contents.
            if (isContents != (s + 1 == steps.length)) revert ProofKindMismatch(s);
        }
        uint256 vlen = _u32(c);
        if (c.p + vlen != c.end) revert ProofTrailingBytes();
        value = new bytes(vlen);
        bytes memory pre8 = new bytes(8 + vlen);
        uint256 src = c.p;
        assembly ("memory-safe") {
            mcopy(add(value, 0x20), src, vlen)
            mstore(add(pre8, 0x20), shl(192, vlen))
            mcopy(add(pre8, 0x28), src, vlen)
        }
        if (TezosBlake2b.hash256(pre8) != expected) revert ProofHashMismatch(level);
    }

    // ── level readers ─────────────────────────────────────────────────────

    function _readLevel(Cursor memory c) private pure returns (uint8 kind, uint256 pre, uint256 len) {
        if (c.p + 3 > c.end) revert ProofTruncated();
        uint256 p = c.p;
        assembly ("memory-safe") {
            let w := mload(p)
            kind := byte(0, w)
            len := and(shr(232, w), 0xffff)
        }
        pre = p + 3;
        if (pre + len > c.end) revert ProofTruncated();
        c.p = pre + len;
    }

    function _u8(Cursor memory c) private pure returns (uint256 v) {
        if (c.p + 1 > c.end) revert ProofTruncated();
        uint256 p = c.p;
        assembly ("memory-safe") {
            v := byte(0, mload(p))
        }
        c.p = p + 1;
    }

    function _u32(Cursor memory c) private pure returns (uint256 v) {
        if (c.p + 4 > c.end) revert ProofTruncated();
        uint256 p = c.p;
        assembly ("memory-safe") {
            v := shr(224, mload(p))
        }
        c.p = p + 4;
    }

    /// @dev LEB128 varint at `p` (bounded by `end`); returns the value and the next address.
    function _varint(uint256 p, uint256 end, uint256 level) private pure returns (uint256 v, uint256 q) {
        uint256 shift = 0;
        for (;;) {
            if (p >= end || shift > 28) revert ProofMalformed(level);
            uint256 b;
            assembly ("memory-safe") {
                b := byte(0, mload(p))
            }
            p++;
            v |= (b & 0x7f) << shift;
            if (b < 0x80) return (v, p);
            shift += 7;
        }
    }

    function _word(uint256 p) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(p)
        }
    }

    /// @dev Stable directory: u64be(n) ‖ n × [kind8 ‖ varint(len) ‖ name ‖ u64be(32) ‖ hash].
    function _findV1(uint256 pre, uint256 len, bytes32 stepHash, uint256 level, bytes32 absentName)
        private
        pure
        returns (bool found, bool isContents, bytes32 child)
    {
        uint256 end = pre + len;
        if (len < 8) revert ProofMalformed(level);
        uint256 n = uint256(_word(pre)) >> 192;
        uint256 p = pre + 8;
        for (uint256 i = 0; i < n; i++) {
            if (p + 8 > end) revert ProofMalformed(level);
            uint256 kind8 = uint256(_word(p)) >> 192;
            if (kind8 != 0 && kind8 != 0xff00000000000000) revert ProofMalformed(level);
            uint256 nameLen;
            (nameLen, p) = _varint(p + 8, end, level);
            uint256 name = p;
            p += nameLen;
            if (p + 40 > end) revert ProofMalformed(level);
            if (uint256(_word(p)) >> 192 != 32) revert ProofMalformed(level);
            bytes32 h = _word(p + 8);
            p += 40;
            bytes32 nh;
            assembly ("memory-safe") {
                nh := keccak256(name, nameLen)
            }
            if (absentName != bytes32(0) && nh == absentName) revert ProofEntryPresent(level);
            if (!found && nh == stepHash) {
                found = true;
                isContents = kind8 != 0;
                child = h;
            }
        }
        if (p != end) revert ProofMalformed(level);
    }

    /// @dev Inode values: 0x00 ‖ varint(k) ‖ k × [varint(len) ‖ name ‖ tag ‖ hash].
    function _findValues(uint256 pre, uint256 len, bytes32 stepHash, uint256 level)
        private
        pure
        returns (bool found, bool isContents, bytes32 child)
    {
        uint256 end = pre + len;
        if (len < 2 || uint256(_word(pre)) >> 248 != 0) revert ProofMalformed(level);
        (uint256 k, uint256 p) = _varint(pre + 1, end, level);
        for (uint256 i = 0; i < k; i++) {
            uint256 nameLen;
            (nameLen, p) = _varint(p, end, level);
            uint256 name = p;
            p += nameLen;
            if (p + 33 > end) revert ProofMalformed(level);
            uint256 tag = uint256(_word(p)) >> 248;
            if (tag > 1) revert ProofMalformed(level);
            bytes32 h = _word(p + 1);
            p += 33;
            bytes32 nh;
            assembly ("memory-safe") {
                nh := keccak256(name, nameLen)
            }
            if (!found && nh == stepHash) {
                found = true;
                isContents = tag == 1;
                child = h;
            }
        }
        if (p != end) revert ProofMalformed(level);
    }

    /// @dev Inode tree: 0x01 ‖ varint(depth) ‖ varint(length) ‖ varint(k) ‖ k × [varint(index) ‖ hash];
    ///      returns the hash of pointer number `ptr` (0-based position in the list).
    function _inodeTreePointer(uint256 pre, uint256 len, uint256 ptr, uint256 level)
        private
        pure
        returns (bytes32 child)
    {
        uint256 end = pre + len;
        if (len < 4 || uint256(_word(pre)) >> 248 != 1) revert ProofMalformed(level);
        uint256 p;
        uint256 k;
        (, p) = _varint(pre + 1, end, level); // depth
        (, p) = _varint(p, end, level); // length
        (k, p) = _varint(p, end, level);
        if (ptr >= k) revert ProofMalformed(level);
        for (uint256 i = 0; i < k; i++) {
            (, p) = _varint(p, end, level); // index
            if (p + 32 > end) revert ProofMalformed(level);
            if (i == ptr) child = _word(p);
            p += 32;
        }
        if (p != end) revert ProofMalformed(level);
    }
}
