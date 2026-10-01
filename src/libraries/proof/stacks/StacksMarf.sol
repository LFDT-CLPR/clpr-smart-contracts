// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {NakamotoHeader} from "@hiero-ledger/clpr/libraries/proof/stacks/NakamotoHeader.sol";

/// @title StacksMarf
/// @notice Verifies a Stacks MARF (Merklized Adaptive Radix Forest) inclusion proof, byte for byte in
///         the wire format a stacks-node returns (`TrieMerkleProof`, `?proof=1` on the /v2 data
///         endpoints), against a block's `state_index_root`.
///
/// The MARF is one trie per block. A write copies the root-to-leaf path into the new block's trie;
/// untouched children stay where they are and are referenced by back-pointers that name the older
/// block (its index block hash). Each trie root is mixed with the roots of its ancestors at
/// distances 1, 2, 4, 8, … (a Merkle skip list); that mixed hash is the header's state_index_root.
///
/// A proof is a list of segments, oldest trie first. Segment 0 runs from the leaf to the root of the
/// trie that holds it; every later segment runs from a back-pointer up to the root of a newer trie.
/// Between segments, shunt proofs walk the skip list from the older trie's root hash to the newer
/// one. This library follows stacks-core `TrieMerkleProof::verify_proof` (index/proofs.rs) and is
/// stricter in four places:
///   - every older trie's root hash must be bound to a block by that block's header (relayer-supplied
///     preimage whose `state_index_root` equals the hash; its block id is what the next segment's
///     back-pointer must name) — stacks-core looks the pair up in its own `root_to_block` map;
///   - the pointer a segment hashes through must be a back-pointer naming exactly that block id at the
///     first node of a later segment, and an in-trie pointer everywhere else;
///   - each node's id byte must match its proof type and every byte of the proof must be consumed
///     (stacks-core stops at the first match of the root);
///   - the key path is checked for every segment, not only for well-formedness.
///
/// Hashes (SHA-512/256) come from a {ClprSha512t256Hasher} contract.
library StacksMarf {
    /// @dev ≥ the largest preimage hashed: a Node256 is 1 + 256·34 + 1 + 32 + 256·32 = 16,930 bytes.
    uint256 private constant SCRATCH = 17_024;
    /// @dev A segment has at most one node per path byte plus the root.
    uint256 private constant MAX_SEGMENT_NODES = 33;

    uint256 private constant ITEM_LEAF = 4;
    uint256 private constant ITEM_SHUNT = 5;
    uint256 private constant TRIE_LEAF_ID = 1;

    error MarfMalformed();
    error MarfValueMismatch();
    error MarfPathMismatch();
    error MarfChildMismatch();
    error MarfShuntInvalid();
    error MarfBindingMismatch();
    error MarfBindingCount();
    error MarfRootMismatch(bytes32 computed, bytes32 expected);
    error MarfHasherFailed();

    /// @notice Revert unless `proof` shows that the MARF with root `root` maps `path` to `valueHash`.
    /// @param path the 32-byte trie path (SHA-512/256 of the key string)
    /// @param valueHash the leaf's value hash (the first 32 of its 40 bytes; the rest is zero)
    /// @param bindings header preimages (see {NakamotoHeader}) of the older tries, oldest first
    /// @return segments number of tries the proof passes through
    function verify(
        address hasher,
        bytes memory proof,
        bytes32 path,
        bytes32 valueHash,
        bytes32 root,
        bytes[] memory bindings
    ) internal view returns (uint256 segments) {
        bytes memory scratch = new bytes(SCRATCH);
        uint256 buf;
        uint256 p;
        uint256 end;
        assembly ("memory-safe") {
            buf := add(scratch, 0x20)
            p := add(proof, 0x20)
            end := add(p, mload(proof))
        }
        if (proof.length < 4 + 46) revert MarfMalformed();
        uint256 left = _u32(p);
        p += 4;

        // ── leaf: type 4 | chr | u32 path len | path | 40-byte value ──
        if (left == 0 || _u8(p) != ITEM_LEAF) revert MarfMalformed();
        uint256 leafPathLen = _u32(p + 2);
        if (leafPathLen > 32) revert MarfMalformed();
        uint256 leafPath = p + 6;
        uint256 data = leafPath + leafPathLen;
        if (data + 40 > end) revert MarfMalformed();
        if (_word(data) != valueHash || (uint256(_word(data + 32)) >> 192) != 0) revert MarfValueMismatch();
        if (!_pathEq(path, 32 - leafPathLen, leafPath, leafPathLen)) revert MarfPathMismatch();
        bytes32 hash;
        assembly ("memory-safe") {
            mstore8(buf, TRIE_LEAF_ID)
            mstore8(add(buf, 1), leafPathLen)
            mcopy(add(buf, 2), leafPath, leafPathLen)
            mcopy(add(add(buf, 2), leafPathLen), data, 40)
        }
        hash = _hash(hasher, buf, 42 + leafPathLen);
        p = data + 40;
        --left;

        uint256[] memory nodes = new uint256[](MAX_SEGMENT_NODES);
        bytes32 trieHash;
        uint256 used;
        while (true) {
            // ── one segment: its nodes, deepest first ──
            uint256 k;
            uint256 segPathLen;
            while (left != 0 && p < end && _u8(p) <= 3) {
                if (k == MAX_SEGMENT_NODES) revert MarfMalformed();
                nodes[k++] = p;
                uint256 pl;
                (p, pl) = _skipNode(p, end);
                segPathLen += 1 + pl;
                --left;
            }
            if (k == 0) revert MarfMalformed();
            uint256 cursor;
            if (segments == 0) {
                if (segPathLen + leafPathLen != 32) revert MarfPathMismatch();
                cursor = 32 - leafPathLen;
            } else {
                if (segPathLen > 32) revert MarfPathMismatch();
                cursor = segPathLen;
            }
            for (uint256 i = 0; i < k; ++i) {
                (hash, cursor) = _hashNode(hasher, buf, nodes[i], hash, path, cursor, segments != 0 && i == 0);
            }
            if (cursor != 0) revert MarfPathMismatch();

            // ── shunt proofs: skip-list hops from the previous trie to this one ──
            if (segments == 0) {
                if (left == 0 || _u8(p) != ITEM_SHUNT) revert MarfShuntInvalid();
                (uint256 idx, uint256 hp, uint256 hn, uint256 np) = _readShunt(p, end);
                if (idx != 0) revert MarfShuntInvalid();
                trieHash = hn == 0 ? hash : _hashList(hasher, buf, true, hash, hp, hn, hn, bytes32(0), false);
                p = np;
                --left;
                if (left != 0 && _u8(p) == ITEM_SHUNT) revert MarfShuntInvalid();
            } else {
                bytes32 t = trieHash;
                while (true) {
                    if (left == 0 || _u8(p) != ITEM_SHUNT) revert MarfShuntInvalid();
                    (uint256 idx, uint256 hp, uint256 hn, uint256 np) = _readShunt(p, end);
                    if (idx == 0 || idx > hn + 1) revert MarfShuntInvalid();
                    p = np;
                    --left;
                    if (left == 0 || _u8(p) != ITEM_SHUNT) {
                        // junction: this trie's root, then the skip list with the previous hop at idx
                        trieHash = _hashList(hasher, buf, true, hash, hp, hn, idx - 1, t, true);
                        break;
                    }
                    t = _hashList(hasher, buf, false, bytes32(0), hp, hn, idx - 1, t, true);
                }
            }
            ++segments;
            if (left == 0) break;

            // ── the next segment starts at a back-pointer to the block whose trie root is trieHash ──
            if (used == bindings.length) revert MarfBindingCount();
            NakamotoHeader.Header memory bh = NakamotoHeader.parse(hasher, bindings[used++]);
            if (bh.stateIndexRoot != trieHash) revert MarfBindingMismatch();
            hash = bh.blockId;
        }
        if (p != end) revert MarfMalformed();
        if (used != bindings.length) revert MarfBindingCount();
        if (trieHash != root) revert MarfRootMismatch(trieHash, root);
    }

    // ── nodes ────────────────────────────────────────────────────────────────

    /// @dev Node item: type t (0..3 = Node4/16/48/256) | chr | id | u32 path len | path |
    ///      u32 n ptrs | n × (id, chr, back_block[32]) | (n−1) × sibling hash.
    function _skipNode(uint256 q, uint256 end) private pure returns (uint256 next, uint256 pl) {
        if (q + 7 > end) revert MarfMalformed();
        uint256 t = _u8(q);
        pl = _u32(q + 3);
        if (pl > 32) revert MarfMalformed();
        uint256 np = q + 7 + pl;
        if (np + 4 > end) revert MarfMalformed();
        uint256 n = _u32(np);
        if (n != _children(t)) revert MarfMalformed();
        next = np + 4 + 34 * n + 32 * (n - 1);
        if (next > end) revert MarfMalformed();
    }

    /// @dev Hash one node with `child` in the slot its `chr` selects, and check its path bytes.
    function _hashNode(
        address hasher,
        uint256 buf,
        uint256 q,
        bytes32 child,
        bytes32 path,
        uint256 cursor,
        bool viaBackPointer
    ) private view returns (bytes32 h, uint256 newCursor) {
        uint256 t = _u8(q);
        uint256 chr = _u8(q + 1);
        uint256 id = _u8(q + 2);
        if (id != t + 2) revert MarfMalformed(); // TrieNodeID: Node4 = 2 … Node256 = 5
        uint256 pl = _u32(q + 3);
        uint256 nodePath = q + 7;
        uint256 n = _children(t);
        uint256 ptrs = nodePath + pl + 4;
        uint256 sibs = ptrs + 34 * n;

        // key order is …, node path, chr, child…; walk it backwards
        if (cursor < pl + 1 || uint8(path[cursor - 1]) != chr) revert MarfPathMismatch();
        newCursor = cursor - 1 - pl;
        if (!_pathEq(path, newCursor, nodePath, pl)) revert MarfPathMismatch();

        // exactly one non-empty pointer at chr
        uint256 at;
        uint256 count;
        uint256 pid;
        bytes32 back;
        assembly ("memory-safe") {
            for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                let e := add(ptrs, mul(j, 34))
                let w := mload(e)
                let i := byte(0, w)
                if and(iszero(iszero(i)), eq(byte(1, w), chr)) {
                    count := add(count, 1)
                    at := j
                    pid := i
                    back := mload(add(e, 2))
                }
            }
        }
        if (count != 1) revert MarfChildMismatch();
        bool isBack = pid & 0x80 != 0;
        if (viaBackPointer ? (!isBack || back != child) : isBack) revert MarfChildMismatch();

        // preimage: id | ptrs (34 B each) | u8 path len | path | child hashes in pointer order
        uint256 len;
        assembly ("memory-safe") {
            mstore8(buf, id)
            mcopy(add(buf, 1), ptrs, mul(n, 34))
            let o := add(add(buf, 1), mul(n, 34))
            mstore8(o, pl)
            mcopy(add(o, 1), nodePath, pl)
            o := add(add(o, 1), pl)
            mcopy(o, sibs, mul(at, 32))
            mstore(add(o, mul(at, 32)), child)
            mcopy(add(o, mul(add(at, 1), 32)), add(sibs, mul(at, 32)), mul(sub(sub(n, 1), at), 32))
            len := sub(add(o, mul(n, 32)), buf)
        }
        h = _hash(hasher, buf, len);
    }

    function _children(uint256 t) private pure returns (uint256) {
        if (t == 0) return 4;
        if (t == 1) return 16;
        if (t == 2) return 48;
        if (t == 3) return 256;
        revert MarfMalformed();
    }

    // ── shunts ───────────────────────────────────────────────────────────────

    /// @dev Shunt item: type 5 | i64 idx | u32 k | k × hash. Returns idx (negative → reverts), the
    ///      hash list pointer, k and the next item pointer.
    function _readShunt(uint256 p, uint256 end)
        private
        pure
        returns (uint256 idx, uint256 hp, uint256 hn, uint256 next)
    {
        if (p + 13 > end) revert MarfMalformed();
        idx = uint256(_word(p + 1)) >> 192;
        if (idx >> 63 != 0) revert MarfShuntInvalid();
        hn = _u32(p + 9);
        hp = p + 13;
        next = hp + 32 * hn;
        if (next > end) revert MarfMalformed();
    }

    /// @dev H([head] ‖ hashes[0:at] ‖ [ins] ‖ hashes[at:])
    function _hashList(
        address hasher,
        uint256 buf,
        bool withHead,
        bytes32 head,
        uint256 hp,
        uint256 hn,
        uint256 at,
        bytes32 ins,
        bool withIns
    ) private view returns (bytes32) {
        uint256 len;
        assembly ("memory-safe") {
            let o := buf
            if withHead {
                mstore(o, head)
                o := add(o, 32)
            }
            mcopy(o, hp, mul(at, 32))
            o := add(o, mul(at, 32))
            if withIns {
                mstore(o, ins)
                o := add(o, 32)
            }
            mcopy(o, add(hp, mul(at, 32)), mul(sub(hn, at), 32))
            len := sub(add(o, mul(sub(hn, at), 32)), buf)
        }
        return _hash(hasher, buf, len);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _hash(address hasher, uint256 ptr, uint256 len) private view returns (bytes32 out) {
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), hasher, ptr, len, 0x00, 0x20)
            out := mload(0x00)
        }
        if (!ok) revert MarfHasherFailed();
    }

    /// @dev path[off : off+len] == memory[ptr : ptr+len]  (off + len ≤ 32)
    function _pathEq(bytes32 path, uint256 off, uint256 ptr, uint256 len) private pure returns (bool r) {
        if (len == 0) return true;
        assembly ("memory-safe") {
            let mask := not(sub(shl(sub(256, mul(8, len)), 1), 1))
            r := eq(and(shl(mul(8, off), path), mask), and(mload(ptr), mask))
        }
    }

    function _u8(uint256 p) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := byte(0, mload(p))
        }
    }

    function _u32(uint256 p) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(224, mload(p))
        }
    }

    function _word(uint256 p) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(p)
        }
    }
}
