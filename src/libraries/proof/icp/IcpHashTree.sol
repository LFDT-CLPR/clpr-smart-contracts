// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IcpHashTree
/// @notice Internet Computer hash trees (IC interface specification, "Certification"), read
///         directly from their CBOR encoding:
///
///             tree-empty   = [0]
///             tree-fork    = [1 hash-tree hash-tree]
///             tree-labeled = [2 bytes hash-tree]
///             tree-leaf    = [3 bytes]
///             tree-pruned  = [4 hash]
///
///         reconstruct(Empty)       = H(domain_sep("ic-hashtree-empty"))
///         reconstruct(Fork t1 t2)  = H(domain_sep("ic-hashtree-fork") · reconstruct(t1) · reconstruct(t2))
///         reconstruct(Labeled l t) = H(domain_sep("ic-hashtree-labeled") · l · reconstruct(t))
///         reconstruct(Leaf v)      = H(domain_sep("ic-hashtree-leaf") · v)
///         reconstruct(Pruned h)    = h
///         domain_sep(s) = byte(|s|) · s, H = SHA-256.
///
///         The same encoding and algorithm cover the subnet's state tree (inside a certificate) and a
///         canister's own witness tree (the tree whose root the canister stores as `certified_data`).
///
/// @dev Only definite-length CBOR is accepted (the relayer re-encodes if a source used indefinite
///      lengths; the encoding does not affect the reconstructed root). An optional self-describe tag
///      55799 may prefix the tree. Every read is bounds-checked and malformed input reverts with
///      {MalformedTree}.
library IcpHashTree {
    error MalformedTree();
    error TreeTooDeep();
    error PathNotFound();

    /// @dev Bound on fork/label nesting. Mainnet state trees observed in the fixtures are < 40 deep.
    uint256 internal constant MAX_DEPTH = 96;

    bytes internal constant DS_EMPTY = "\x11ic-hashtree-empty";
    bytes internal constant DS_FORK = "\x10ic-hashtree-fork";
    bytes internal constant DS_LABELED = "\x13ic-hashtree-labeled";
    bytes internal constant DS_LEAF = "\x10ic-hashtree-leaf";

    // ── CBOR primitives ──────────────────────────────────────────────────────

    /// @dev Read a definite-length CBOR head at `off`: returns the major type, its argument and the
    ///      offset just past the head.
    function readHead(bytes memory b, uint256 off) internal pure returns (uint8 major, uint64 arg, uint256 next) {
        if (off >= b.length) revert MalformedTree();
        uint8 ib = uint8(b[off]);
        major = ib >> 5;
        uint8 info = ib & 31;
        next = off + 1;
        if (info < 24) {
            arg = info;
        } else if (info < 28) {
            uint256 n = uint256(1) << (info - 24); // 1, 2, 4 or 8 bytes
            if (next + n > b.length) revert MalformedTree();
            for (uint256 i = 0; i < n; i++) {
                arg = (arg << 8) | uint8(b[next + i]);
            }
            next += n;
        } else {
            revert MalformedTree();
        }
    }

    /// @dev Skip an optional self-describe tag (55799 = 0xd9d9f7).
    function skipSelfDescribe(bytes memory b, uint256 off) internal pure returns (uint256) {
        if (off + 3 <= b.length && b[off] == 0xd9 && b[off + 1] == 0xd9 && b[off + 2] == 0xf7) return off + 3;
        return off;
    }

    /// @dev Read a byte string at `off`: returns (start, length, next).
    function readBytes(bytes memory b, uint256 off) internal pure returns (uint256 start, uint256 len, uint256 next) {
        (uint8 major, uint64 n, uint256 p) = readHead(b, off);
        if (major != 2) revert MalformedTree();
        if (p + n > b.length) revert MalformedTree();
        return (p, n, p + n);
    }

    /// @dev Read the tree node tag at `off`: the node must be a CBOR array whose first item is a small
    ///      unsigned integer 0..4 and whose length matches that tag.
    function readNode(bytes memory b, uint256 off) internal pure returns (uint8 tag, uint256 next) {
        (uint8 major, uint64 n, uint256 p) = readHead(b, off);
        if (major != 4 || p >= b.length) revert MalformedTree();
        tag = uint8(b[p]);
        if (tag > 4) revert MalformedTree();
        // expected array lengths: empty 1, fork 3, labeled 3, leaf 2, pruned 2
        uint256 expected = tag == 0 ? 1 : (tag == 1 || tag == 2) ? 3 : 2;
        if (n != expected) revert MalformedTree();
        next = p + 1;
    }

    // ── reconstruct ──────────────────────────────────────────────────────────

    /// @notice Root hash of the CBOR-encoded hash tree `tree`. The whole input must be one tree.
    function reconstruct(bytes memory tree) internal pure returns (bytes32 root) {
        uint256 end;
        (root, end) = _reconstruct(tree, skipSelfDescribe(tree, 0), 0);
        if (end != tree.length) revert MalformedTree();
    }

    function _reconstruct(bytes memory b, uint256 off, uint256 depth) private pure returns (bytes32 h, uint256 end) {
        if (depth > MAX_DEPTH) revert TreeTooDeep();
        (uint8 tag, uint256 p) = readNode(b, off);
        if (tag == 0) return (sha256(DS_EMPTY), p);
        if (tag == 1) {
            (bytes32 l, uint256 p1) = _reconstruct(b, p, depth + 1);
            (bytes32 r, uint256 p2) = _reconstruct(b, p1, depth + 1);
            return (sha256(abi.encodePacked(DS_FORK, l, r)), p2);
        }
        (uint256 s, uint256 n, uint256 q) = readBytes(b, p);
        if (tag == 2) {
            (bytes32 sub, uint256 q2) = _reconstruct(b, q, depth + 1);
            return (sha256(abi.encodePacked(DS_LABELED, _slice(b, s, n), sub)), q2);
        }
        if (tag == 3) return (sha256(abi.encodePacked(DS_LEAF, _slice(b, s, n))), q);
        // pruned
        if (n != 32) revert MalformedTree();
        return (_word(b, s), q);
    }

    // ── lookup ──────────────────────────────────────────────────────────────

    /// @notice Value of the leaf at `path` (spec `lookup_path`, `Found` case only). Reverts with
    ///         {PathNotFound} for Absent, Unknown (pruned) and Error outcomes. The caller must check
    ///         `reconstruct(tree)` against a trusted root; the lookup only reads structure.
    function lookup(bytes memory tree, bytes[] memory path) internal pure returns (bytes memory value) {
        uint256 off = skipSelfDescribe(tree, 0);
        for (uint256 i = 0; i < path.length; i++) {
            bool found;
            (found, off) = _findLabel(tree, off, path[i], 0);
            if (!found) revert PathNotFound();
        }
        (uint8 tag, uint256 p) = readNode(tree, off);
        if (tag != 3) revert PathNotFound();
        (uint256 s, uint256 n,) = readBytes(tree, p);
        return _slice(tree, s, n);
    }

    /// @dev Search the forest `flatten_forks(node at off)` for a labeled subtree with label `label`.
    ///      Returns the offset of that subtree.
    function _findLabel(bytes memory b, uint256 off, bytes memory label, uint256 depth)
        private
        pure
        returns (bool found, uint256 sub)
    {
        if (depth > MAX_DEPTH) revert TreeTooDeep();
        (uint8 tag, uint256 p) = readNode(b, off);
        if (tag == 1) {
            (found, sub) = _findLabel(b, p, label, depth + 1);
            if (found) return (true, sub);
            return _findLabel(b, skip(b, p), label, depth + 1);
        }
        if (tag == 2) {
            (uint256 s, uint256 n, uint256 q) = readBytes(b, p);
            if (n == label.length && keccak256(_slice(b, s, n)) == keccak256(label)) return (true, q);
        }
        return (false, 0);
    }

    /// @notice Offset just past the tree node at `off`.
    function skip(bytes memory b, uint256 off) internal pure returns (uint256) {
        return _skip(b, off, 0);
    }

    function _skip(bytes memory b, uint256 off, uint256 depth) private pure returns (uint256) {
        if (depth > MAX_DEPTH) revert TreeTooDeep();
        (uint8 tag, uint256 p) = readNode(b, off);
        if (tag == 0) return p;
        if (tag == 1) return _skip(b, _skip(b, p, depth + 1), depth + 1);
        (,, uint256 q) = readBytes(b, p);
        if (tag == 2) return _skip(b, q, depth + 1);
        return q;
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), start), len)
        }
    }

    function _word(bytes memory b, uint256 start) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), start))
        }
    }

    /// @notice Decode an unsigned LEB128 value (the encoding of naturals in the IC state tree).
    function leb128(bytes memory v) internal pure returns (uint64 x) {
        if (v.length == 0 || v.length > 10) revert MalformedTree();
        uint256 acc;
        for (uint256 i = 0; i < v.length; i++) {
            uint8 c = uint8(v[i]);
            acc |= uint256(c & 0x7f) << (7 * i);
            if (c & 0x80 == 0) {
                if (i != v.length - 1 || acc > type(uint64).max) revert MalformedTree();
                // casting to 'uint64' is safe because acc was checked to fit in 64 bits.
                // forge-lint: disable-next-line(unsafe-typecast)
                return uint64(acc);
            }
        }
        revert MalformedTree();
    }
}
