// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title RskUnitrie
/// @notice Inclusion and exclusion proofs against Rootstock's Unitrie (RSKIP107 node format), the
///         binary state trie whose root is the RSK header's `stateRoot` (RSKIP126, mainnet ≥ 1,591,000).
///
/// Node message (RSKj `co.rsk.trie.Trie#toMessage` / `fromMessageRskip107`):
/// ```
/// flags(1): 0b01xxxxxx  bit5 longValue · bit4 sharedPath · bit3 left · bit2 right · bit1 leftEmbedded · bit0 rightEmbedded
/// [sharedPath]  lenPrefix ‖ ceil(L/8) bytes, bits MSB-first        (SharedPathSerializer, PathEncoder)
///               L∈[1,32] → byte L−1 · L∈[160,382] → byte L−128 · else 0xFF ‖ VarInt(L)
/// [left]        embedded: uint8 len ‖ child message · otherwise: keccak256(child message)
/// [right]       same
/// [childrenSize] bitcoin VarInt, present iff a child is present (skipped; not consensus-relevant here)
/// value         longValue: valueHash(32) ‖ uint24 length · otherwise: all remaining bytes (0 bytes = none)
/// ```
/// Node hash = keccak256(message). Walk: the remaining key must start with the node's shared path; a
/// mismatch or a key ending inside the path means "absent"; at the key's end the node's value is the
/// answer; otherwise the next key bit picks left (0) or right (1) and is consumed.
///
/// Proof format: the non-embedded node messages on the path, root first. Embedded children are read
/// from inside their parent. Every listed node must be consumed.
library RskUnitrie {
    /// @dev keccak256(RLP("")) = keccak256(0x80): the empty trie.
    bytes32 internal constant EMPTY_TRIE_HASH = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

    error UnitrieBadNode();
    error UnitrieHashMismatch();
    error UnitrieProofTooShort();
    error UnitrieUnusedProofNodes();

    struct Value {
        bool found;
        bool isLong; // value > 32 bytes: only its hash and length are in the node
        bytes value; // the inline value (isLong == false)
        bytes32 valueHash; // keccak256(value) — given for long values, computed otherwise
        uint256 length;
    }

    /// @notice Look up `key` (bit string MSB-first, `keyBits` bits) under `root`.
    function get(bytes32 root, bytes memory key, bytes[] memory nodes) internal pure returns (Value memory v) {
        if (root == EMPTY_TRIE_HASH) {
            if (nodes.length != 0) revert UnitrieUnusedProofNodes();
            return v;
        }
        if (nodes.length == 0) revert UnitrieProofTooShort();
        bytes memory node = nodes[0];
        if (keccak256(node) != root) revert UnitrieHashMismatch();
        uint256 next = 1;
        uint256 keyBits = key.length * 8;
        uint256 pos = 0;
        while (true) {
            // node is a full message (hashed or embedded)
            uint256 len = node.length;
            if (len == 0) revert UnitrieBadNode();
            uint8 flags = uint8(node[0]);
            if (flags & 0xC0 != 0x40) revert UnitrieBadNode();
            uint256 off = 1;

            // shared path
            if (flags & 0x10 != 0) {
                uint256 pathBits;
                (pathBits, off) = _pathLength(node, off);
                uint256 pathBytes = (pathBits + 7) / 8;
                if (off + pathBytes > len) revert UnitrieBadNode();
                if (pos + pathBits > keyBits) return _absent(nodes, next);
                if (!_bitsEqual(node, off * 8, key, pos, pathBits)) return _absent(nodes, next);
                pos += pathBits;
                off += pathBytes;
            }

            // child references
            bool hasLeft = flags & 0x08 != 0;
            bool hasRight = flags & 0x04 != 0;
            uint256 leftOff;
            uint256 leftLen; // 0 → hashed reference (32 bytes at leftOff)
            uint256 rightOff;
            uint256 rightLen;
            if (hasLeft) (leftOff, leftLen, off) = _ref(node, off, flags & 0x02 != 0);
            if (hasRight) (rightOff, rightLen, off) = _ref(node, off, flags & 0x01 != 0);
            if (hasLeft || hasRight) off = _skipVarInt(node, off);

            if (pos == keyBits) {
                // This node holds the answer.
                if (flags & 0x20 != 0) {
                    if (off + 35 != len) revert UnitrieBadNode();
                    v.found = true;
                    v.isLong = true;
                    v.valueHash = _word(node, off);
                    v.length = (uint256(uint8(node[off + 32])) << 16) | (uint256(uint8(node[off + 33])) << 8)
                        | uint256(uint8(node[off + 34]));
                } else if (off < len) {
                    v.found = true;
                    v.value = _slice(node, off, len - off);
                    v.valueHash = keccak256(v.value);
                    v.length = len - off;
                }
                if (next != nodes.length) revert UnitrieUnusedProofNodes();
                return v;
            }

            bool goRight = _bit(key, pos) == 1;
            pos += 1;
            if (goRight ? !hasRight : !hasLeft) return _absent(nodes, next);
            uint256 cOff = goRight ? rightOff : leftOff;
            uint256 cLen = goRight ? rightLen : leftLen;
            if (cLen != 0) {
                node = _slice(node, cOff, cLen); // embedded: authenticated by its parent's hash
            } else {
                bytes32 h = _word(node, cOff);
                if (next >= nodes.length) revert UnitrieProofTooShort();
                node = nodes[next++];
                if (keccak256(node) != h) revert UnitrieHashMismatch();
            }
        }
    }

    function _absent(bytes[] memory nodes, uint256 next) private pure returns (Value memory v) {
        if (next != nodes.length) revert UnitrieUnusedProofNodes();
        return v;
    }

    function _ref(bytes memory node, uint256 off, bool embedded)
        private
        pure
        returns (uint256 refOff, uint256 refLen, uint256 nextOff)
    {
        if (embedded) {
            if (off >= node.length) revert UnitrieBadNode();
            refLen = uint8(node[off]);
            if (refLen == 0 || off + 1 + refLen > node.length) revert UnitrieBadNode();
            return (off + 1, refLen, off + 1 + refLen);
        }
        if (off + 32 > node.length) revert UnitrieBadNode();
        return (off, 0, off + 32);
    }

    /// @dev Shared-path bit length (RSKj `SharedPathSerializer.getPathBitsLength`).
    function _pathLength(bytes memory node, uint256 off) private pure returns (uint256 bits, uint256 next) {
        if (off >= node.length) revert UnitrieBadNode();
        uint256 b = uint8(node[off]);
        if (b <= 31) return (b + 1, off + 1);
        if (b <= 254) return (b + 128, off + 1);
        (bits, next) = _readVarInt(node, off + 1);
    }

    /// @dev Bitcoin-style VarInt (RSKj `co.rsk.trie.Trie#readVarInt`, little-endian payloads).
    function _readVarInt(bytes memory b, uint256 off) private pure returns (uint256 v, uint256 next) {
        if (off >= b.length) revert UnitrieBadNode();
        uint256 first = uint8(b[off]);
        uint256 n = first < 0xfd ? 0 : first == 0xfd ? 2 : first == 0xfe ? 4 : 8;
        if (n == 0) return (first, off + 1);
        if (off + 1 + n > b.length) revert UnitrieBadNode();
        for (uint256 i = 0; i < n; ++i) {
            v |= uint256(uint8(b[off + 1 + i])) << (8 * i);
        }
        return (v, off + 1 + n);
    }

    function _skipVarInt(bytes memory b, uint256 off) private pure returns (uint256 next) {
        (, next) = _readVarInt(b, off);
    }

    /// @dev `a[aOff .. aOff+n)` == `b[bOff .. bOff+n)` as bit strings (MSB-first), compared 248 bits at a
    ///      time. Callers guarantee both ranges are in bounds; the words loaded may extend past the end
    ///      of an array but only in-range bits are compared.
    function _bitsEqual(bytes memory a, uint256 aOff, bytes memory b, uint256 bOff, uint256 n)
        private
        pure
        returns (bool)
    {
        while (n != 0) {
            uint256 m = n > 248 ? 248 : n;
            if (_bitsAt(a, aOff, m) != _bitsAt(b, bOff, m)) return false;
            aOff += m;
            bOff += m;
            n -= m;
        }
        return true;
    }

    /// @dev The `m ≤ 248` bits of `b` starting at bit `off`, right-aligned.
    function _bitsAt(bytes memory b, uint256 off, uint256 m) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(sub(256, m), shl(and(off, 7), mload(add(add(b, 0x20), shr(3, off)))))
        }
    }

    function _bit(bytes memory b, uint256 i) private pure returns (uint256) {
        return (uint8(b[i >> 3]) >> (7 - (i & 7))) & 1;
    }

    function _word(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        if (off + 32 > b.length) revert UnitrieBadNode();
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _slice(bytes memory b, uint256 off, uint256 len) private pure returns (bytes memory out) {
        if (off + len > b.length) revert UnitrieBadNode();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), off), len)
        }
    }

    // ── Rootstock key mapping (RSKj org.ethereum.db.TrieKeyMapper) ─────────────

    /// @notice `0x00 ‖ keccak256(addr)[0:10] ‖ addr` (31 bytes).
    function accountKey(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x00), bytes10(keccak256(abi.encodePacked(a))), a);
    }

    /// @notice `accountKey ‖ 0x80`: its (long) value hash is the contract's code hash.
    function codeKey(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(accountKey(a), bytes1(0x80));
    }

    /// @notice `accountKey ‖ 0x00 ‖ keccak256(slot)[0:10] ‖ stripLeadingZeros(slot)` (slot 0 → 0x00).
    function storageKey(address a, bytes32 slot) internal pure returns (bytes memory) {
        uint256 s = uint256(slot);
        uint256 n = 1;
        for (uint256 t = s >> 8; t != 0; t >>= 8) {
            ++n;
        }
        bytes memory stripped = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            stripped[n - 1 - i] = bytes1(uint8(s >> (8 * i)));
        }
        return abi.encodePacked(accountKey(a), bytes1(0x00), bytes10(keccak256(abi.encodePacked(slot))), stripped);
    }

    /// @notice A storage value: stored with leading zeros stripped; a zero word is deleted (absent).
    function storageWord(Value memory v) internal pure returns (bytes32 w) {
        if (!v.found) return bytes32(0);
        if (v.isLong || v.length > 32) revert UnitrieBadNode();
        bytes memory b = v.value;
        uint256 n = b.length;
        for (uint256 i = 0; i < n; ++i) {
            w |= bytes32(uint256(uint8(b[i])) << (8 * (n - 1 - i)));
        }
    }
}
