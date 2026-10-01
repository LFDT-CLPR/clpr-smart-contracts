// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MptMultiProof
/// @notice Many storage-slot lookups against one storage-trie root, sharing one deduplicated node pool.
/// @dev Proving ~100 storage slots of one small contract with independent `eth_getProof` paths repeats
///      the same upper nodes in every path (Arc's ValidatorRegistry: 106 slots, 95 KB of paths, but
///      only ~160 distinct nodes, ~12 KB). Here each distinct node is sent once and hashed once; every
///      lookup then walks the pool by index, scanning RLP in place (no copies, no per-visit allocation).
///
///      Encoding (`RLP([nodes, paths])`):
///        nodes  RLP list of byte strings, each the trie node's own RLP (as in `eth_getProof`).
///        paths  one byte string: for each lookup in the order the CALLER performs them,
///               `count(1) ‖ index(2, big-endian) × count`, the pool indices of that lookup's path
///               from the root. The caller derives every key itself; `paths` only says where the
///               nodes are, and every node is still checked against the hash its parent commits to.
///      {finish} requires every path byte to be consumed, and a path may not continue past the node
///      that ends its lookup, so a proof carries nothing unused.
///
///      Node semantics follow {MerklePatriciaProof.getOrEmpty}: branch (17 items) and extension or
///      leaf (2 items) nodes, 32-byte hash references only (inline nodes rejected), and a proven-absent
///      key reads as zero. Keys are 32-byte hashes, so no value ever sits in a branch.
library MptMultiProof {
    error MultiProofInvalidNode();
    error MultiProofHashMismatch();
    error MultiProofInlineNodeUnsupported();
    error MultiProofPathOutOfRange();
    error MultiProofPathTooShort();
    error MultiProofTrailingPath();
    error MultiProofInvalidPathPrefix();
    error MultiProofInvalidValue();

    /// @dev `nodes[i]` = (payloadLength << 128) | payloadPointer of node i, in memory.
    struct Pool {
        uint256[] nodes;
        bytes32[] hashes;
        uint256 pathPtr;
        uint256 pathLen;
        uint256 cursor;
    }

    uint256 private constant LOW128 = (1 << 128) - 1;

    /// @dev Index `RLP([nodes, paths])` (already in memory) and hash every node once.
    function load(Memory.Slice item) internal pure returns (Pool memory p) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 2) revert MultiProofInvalidNode();

        uint256 ptr = uint256(Memory.Slice.unwrap(f[0])) & LOW128;
        (uint256 cur, uint256 end) = _listPayload(ptr, Memory.length(f[0]));
        uint256 count;
        for (uint256 c = cur; c < end; ++count) {
            (uint256 dp, uint256 dl) = _string(c, end);
            c = dp + dl;
        }
        p.nodes = new uint256[](count);
        p.hashes = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            (uint256 dp, uint256 dl) = _string(cur, end);
            p.nodes[i] = (dl << 128) | dp;
            bytes32 h;
            assembly ("memory-safe") {
                h := keccak256(dp, dl)
            }
            p.hashes[i] = h;
            cur = dp + dl;
        }

        uint256 pp = uint256(Memory.Slice.unwrap(f[1])) & LOW128;
        (uint256 pdp, uint256 pdl) = _string(pp, pp + Memory.length(f[1]));
        if (pdp + pdl != pp + Memory.length(f[1])) revert MultiProofInvalidNode();
        (p.pathPtr, p.pathLen) = (pdp, pdl);
    }

    /// @dev Reverts unless every path byte was used.
    function finish(Pool memory p) internal pure {
        if (p.cursor != p.pathLen) revert MultiProofTrailingPath();
    }

    /// @notice Storage word at `slot` in the storage trie `root`; zero when the slot is proven absent.
    function getWord(Pool memory p, bytes32 root, bytes32 slot) internal pure returns (bytes32) {
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        uint256 count = _nextByte(p);
        if (count == 0) revert MultiProofPathTooShort();
        bytes32 expected = root;
        uint256 keyIdx;
        unchecked {
            for (uint256 i; i < count; ++i) {
                uint256 idx = _nextIndex(p);
                if (idx >= p.nodes.length) revert MultiProofPathOutOfRange();
                if (p.hashes[idx] != expected) revert MultiProofHashMismatch();
                bool last = i + 1 == count;
                uint256 node = p.nodes[idx];
                uint256 want = keyIdx < 64 ? _nib(keyHash, keyIdx) : 16;
                (uint256 n, uint256 p0, uint256 l0, uint256 p1, uint256 l1, uint256 pw, uint256 lw) =
                    _scan(node & LOW128, node >> 128, want);

                if (n == 17) {
                    if (keyIdx >= 64) revert MultiProofInvalidNode();
                    ++keyIdx;
                    if (lw == 0) {
                        if (!last) revert MultiProofTrailingPath();
                        return bytes32(0);
                    }
                    if (lw != 32) revert MultiProofInlineNodeUnsupported();
                    expected = _load32(pw);
                } else if (n == 2) {
                    (bool isLeaf, uint256 len, uint256 off) = _prefix(p0, l0);
                    bool matches = len + keyIdx <= 64 && _nibblesEqual(p0, off, keyHash, keyIdx, len);
                    if (!matches || (isLeaf && keyIdx + len != 64)) {
                        if (!last) revert MultiProofTrailingPath();
                        return bytes32(0);
                    }
                    keyIdx += len;
                    if (isLeaf) {
                        if (!last) revert MultiProofTrailingPath();
                        return _scalar(p1, l1);
                    }
                    if (l1 != 32) revert MultiProofInlineNodeUnsupported();
                    expected = _load32(p1);
                } else {
                    revert MultiProofInvalidNode();
                }
            }
        }
        revert MultiProofPathTooShort();
    }

    // ── RLP scanning (in place) ──────────────────────────────────────────────

    /// @dev Scan the RLP list at [ptr, ptr+len): item count `n` and the payload (ptr,len) of items 0, 1
    ///      and `want`. Reverts on a malformed list or any item that is itself a list (inline node).
    function _scan(uint256 ptr, uint256 len, uint256 want)
        private
        pure
        returns (uint256 n, uint256 p0, uint256 l0, uint256 p1, uint256 l1, uint256 pw, uint256 lw)
    {
        (uint256 cur, uint256 end) = _listPayload(ptr, len);
        if (end != ptr + len) revert MultiProofInvalidNode();
        bool bad;
        assembly ("memory-safe") {
            for {} lt(cur, end) {} {
                let b := byte(0, mload(cur))
                let dp := cur
                let dl := 1
                if gt(b, 0x7f) {
                    switch lt(b, 0xb8)
                    case 1 {
                        dp := add(cur, 1)
                        dl := sub(b, 0x80)
                    }
                    default {
                        if gt(b, 0xbf) {
                            bad := 1
                            break
                        }
                        let lol := sub(b, 0xb7)
                        dl := shr(mul(8, sub(32, lol)), mload(add(cur, 1)))
                        dp := add(add(cur, 1), lol)
                    }
                }
                if gt(add(dp, dl), end) {
                    bad := 1
                    break
                }
                if eq(n, 0) {
                    p0 := dp
                    l0 := dl
                }
                if eq(n, 1) {
                    p1 := dp
                    l1 := dl
                }
                if eq(n, want) {
                    pw := dp
                    lw := dl
                }
                cur := add(dp, dl)
                n := add(n, 1)
            }
        }
        if (bad) revert MultiProofInvalidNode();
    }

    /// @dev List header at `ptr` (within `len` bytes): returns its payload range.
    function _listPayload(uint256 ptr, uint256 len) private pure returns (uint256 cur, uint256 end) {
        if (len == 0) revert MultiProofInvalidNode();
        uint256 b0 = _byteAt(ptr);
        uint256 payload;
        if (b0 < 0xc0) revert MultiProofInvalidNode();
        if (b0 <= 0xf7) {
            payload = b0 - 0xc0;
            cur = ptr + 1;
        } else {
            uint256 lol = b0 - 0xf7;
            if (lol > 4 || 1 + lol > len) revert MultiProofInvalidNode();
            payload = _beUint(ptr + 1, lol);
            cur = ptr + 1 + lol;
        }
        end = cur + payload;
        if (end > ptr + len) revert MultiProofInvalidNode();
    }

    /// @dev String item at `ptr` (not past `end`): its payload range. Lists are rejected.
    function _string(uint256 ptr, uint256 end) private pure returns (uint256 dp, uint256 dl) {
        if (ptr >= end) revert MultiProofInvalidNode();
        uint256 b = _byteAt(ptr);
        if (b < 0x80) {
            (dp, dl) = (ptr, 1);
        } else if (b <= 0xb7) {
            (dp, dl) = (ptr + 1, b - 0x80);
        } else if (b <= 0xbf) {
            uint256 lol = b - 0xb7;
            if (lol > 4) revert MultiProofInvalidNode();
            dl = _beUint(ptr + 1, lol);
            dp = ptr + 1 + lol;
        } else {
            revert MultiProofInvalidNode();
        }
        if (dp + dl > end) revert MultiProofInvalidNode();
    }

    /// @dev Storage leaf value: an RLP string holding the minimal big-endian scalar (≤ 32 bytes).
    function _scalar(uint256 ptr, uint256 len) private pure returns (bytes32) {
        if (len == 0) revert MultiProofInvalidValue();
        uint256 b = _byteAt(ptr);
        if (len == 1) {
            if (b >= 0x80) revert MultiProofInvalidValue();
            return bytes32(b);
        }
        if (b < 0x81 || b > 0xa0 || len != b - 0x80 + 1) revert MultiProofInvalidValue();
        return bytes32(_beUint(ptr + 1, len - 1));
    }

    /// @dev Hex-prefix decode: (isLeaf, nibble count, nibble offset of the first path nibble).
    function _prefix(uint256 ptr, uint256 len) private pure returns (bool isLeaf, uint256 nibbles, uint256 off) {
        if (len == 0) revert MultiProofInvalidPathPrefix();
        uint256 b = _byteAt(ptr);
        uint256 flag = b >> 4;
        if (flag > 3) revert MultiProofInvalidPathPrefix();
        isLeaf = flag >= 2;
        bool odd = flag % 2 == 1;
        if (!odd && b & 0x0f != 0) revert MultiProofInvalidPathPrefix();
        off = odd ? 1 : 2;
        nibbles = len * 2 - off;
    }

    /// @dev Path nibbles [off, off+len) at `ptr` equal key nibbles [keyIdx, keyIdx+len).
    function _nibblesEqual(uint256 ptr, uint256 off, bytes32 key, uint256 keyIdx, uint256 len)
        private
        pure
        returns (bool eq_)
    {
        assembly ("memory-safe") {
            eq_ := 1
            for { let j := 0 } lt(j, len) { j := add(j, 1) } {
                let pi := add(off, j)
                let pb := byte(0, mload(add(ptr, shr(1, pi))))
                let pn := and(shr(mul(4, iszero(and(pi, 1))), pb), 0x0f)
                let ki := add(keyIdx, j)
                let kb := byte(shr(1, ki), key)
                let kn := and(shr(mul(4, iszero(and(ki, 1))), kb), 0x0f)
                if iszero(eq(pn, kn)) {
                    eq_ := 0
                    break
                }
            }
        }
    }

    function _nextByte(Pool memory p) private pure returns (uint256 b) {
        uint256 c = p.cursor;
        if (c >= p.pathLen) revert MultiProofPathTooShort();
        b = _byteAt(p.pathPtr + c);
        p.cursor = c + 1;
    }

    function _nextIndex(Pool memory p) private pure returns (uint256 idx) {
        uint256 c = p.cursor;
        if (c + 2 > p.pathLen) revert MultiProofPathTooShort();
        uint256 ptr = p.pathPtr + c;
        assembly ("memory-safe") {
            idx := shr(240, mload(ptr))
        }
        p.cursor = c + 2;
    }

    function _nib(bytes32 key, uint256 i) private pure returns (uint256 n) {
        assembly ("memory-safe") {
            n := and(shr(mul(4, iszero(and(i, 1))), byte(shr(1, i), key)), 0x0f)
        }
    }

    function _byteAt(uint256 ptr) private pure returns (uint256 b) {
        assembly ("memory-safe") {
            b := byte(0, mload(ptr))
        }
    }

    function _load32(uint256 ptr) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(ptr)
        }
    }

    /// @dev Big-endian unsigned integer of `len` (≤ 32) bytes at `ptr`.
    function _beUint(uint256 ptr, uint256 len) private pure returns (uint256 v) {
        if (len > 32) revert MultiProofInvalidNode();
        if (len == 0) return 0;
        assembly ("memory-safe") {
            v := shr(mul(8, sub(32, len)), mload(ptr))
        }
    }
}
