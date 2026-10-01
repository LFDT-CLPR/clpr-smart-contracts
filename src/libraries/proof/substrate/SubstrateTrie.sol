// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";

/// @title SubstrateTrie
/// @notice Verifies Substrate storage read proofs (`state_getReadProof`): the base-16
///         Patricia-Merkle trie of `sp-trie` with `BlakeTwo256` node hashing, LayoutV0 and LayoutV1
///         (V1 stores values of 33 bytes or more as separate hashed value nodes).
///
/// Node encoding (sp-trie node_header.rs / node_codec.rs):
///   header byte, by its top bits
///     00000000  empty trie
///     01xxxxxx  leaf                  nibble count in 6 bits
///     10xxxxxx  branch, no value      nibble count in 6 bits
///     11xxxxxx  branch with value     nibble count in 6 bits
///     001xxxxx  leaf, hashed value    nibble count in 5 bits
///     0001xxxx  branch, hashed value  nibble count in 4 bits
///   A count field with all bits set continues in following bytes (each byte added; < 255 ends).
///   Then the partial key: ceil(count/2) bytes, an odd count is left-padded with a zero nibble.
///   Leaf:   value = Compact(len) ‖ bytes (inline) | 32-byte blake2_256 of the value (hashed).
///   Branch: bitmap u16 LE (bit i = child i) ‖ [value as above] ‖ per child Compact(len) ‖ data,
///           where len == 32 is a child hash and len < 32 an inline child node.
///
/// A proof is an unordered set of node encodings. Every node is located by its blake2_256, so a
/// node the walk needs but the proof lacks reverts ({MissingProofNode}): absence of a key is only
/// concluded from a node that actually rules the key out.
library SubstrateTrie {
    error MissingProofNode(bytes32 hash);
    error InvalidNodeEncoding();
    error EmptyProof();

    uint256 private constant KIND_EMPTY = 0;
    uint256 private constant KIND_LEAF = 1;
    uint256 private constant KIND_BRANCH = 2;

    /// @dev Proof nodes and their blake2_256 hashes (computed once per proof).
    struct Proof {
        bytes[] nodes;
        bytes32[] hashes;
    }

    /// @notice Hashes every node of `nodes` once.
    function load(bytes[] memory nodes) internal view returns (Proof memory p) {
        if (nodes.length == 0) revert EmptyProof();
        p.nodes = nodes;
        p.hashes = new bytes32[](nodes.length);
        for (uint256 i; i < nodes.length; ++i) {
            p.hashes[i] = Blake2b.hash256(nodes[i]);
        }
    }

    /// @notice Looks `key` up in the trie rooted at `root`.
    /// @return exists Whether the key is present.
    /// @return value  The stored value (empty when absent).
    function get(Proof memory p, bytes32 root, bytes memory key)
        internal
        pure
        returns (bool exists, bytes memory value)
    {
        bytes memory node = _lookup(p, root);
        uint256 keyNibbles = key.length * 2;
        uint256 nib;
        while (true) {
            (uint256 kind, bool hashedValue, bool branchHasValue, uint256 count, uint256 off) = _header(node);
            if (kind == KIND_EMPTY) return (false, value);

            // Partial key.
            uint256 partialBytes = (count + 1) / 2;
            if (off + partialBytes > node.length) revert InvalidNodeEncoding();
            uint256 start = off * 2;
            if (count % 2 == 1) {
                if (uint8(node[off]) >> 4 != 0) revert InvalidNodeEncoding();
                start += 1;
            }
            if (nib + count > keyNibbles) return (false, value);
            for (uint256 i; i < count; ++i) {
                if (_nibble(node, start + i) != _nibble(key, nib + i)) return (false, value);
            }
            nib += count;
            off += partialBytes;

            if (kind == KIND_LEAF) {
                if (nib != keyNibbles) return (false, value);
                uint256 end;
                (value, end) = _readValue(p, node, off, hashedValue);
                if (end != node.length) revert InvalidNodeEncoding();
                return (true, value);
            }

            // Branch.
            if (off + 2 > node.length) revert InvalidNodeEncoding();
            uint256 bitmap = uint256(uint8(node[off])) | (uint256(uint8(node[off + 1])) << 8);
            if (bitmap == 0) revert InvalidNodeEncoding();
            off += 2;
            if (branchHasValue) {
                if (nib == keyNibbles) {
                    (value,) = _readValue(p, node, off, hashedValue);
                    return (true, value);
                }
                off = _skipValue(node, off, hashedValue);
            } else if (nib == keyNibbles) {
                return (false, value);
            }

            uint256 idx = _nibble(key, nib);
            ++nib;
            if ((bitmap >> idx) & 1 == 0) return (false, value);
            uint256 len;
            for (uint256 c; c <= idx; ++c) {
                if ((bitmap >> c) & 1 == 0) continue;
                (len, off) = ScaleCodec.readCompact(node, off);
                if (c == idx) break;
                off += len;
            }
            if (len == 32) {
                node = _lookup(p, ScaleCodec.readBytes32(node, off));
            } else if (len > 0 && len < 32) {
                node = ScaleCodec.slice(node, off, len);
            } else {
                revert InvalidNodeEncoding();
            }
        }
    }

    // ── Internals ────────────────────────────────────────────────────────────

    function _lookup(Proof memory p, bytes32 h) private pure returns (bytes memory) {
        for (uint256 i; i < p.hashes.length; ++i) {
            if (p.hashes[i] == h) return p.nodes[i];
        }
        revert MissingProofNode(h);
    }

    /// @dev Node kind, value flags, partial-key nibble count and the offset just past the header.
    function _header(bytes memory node)
        private
        pure
        returns (uint256 kind, bool hashedValue, bool branchHasValue, uint256 count, uint256 off)
    {
        if (node.length == 0) revert InvalidNodeEncoding();
        uint256 b0 = uint8(node[0]);
        uint256 maskBits;
        uint256 top = b0 >> 6;
        if (top == 1) {
            (kind, maskBits) = (KIND_LEAF, 2);
        } else if (top == 2) {
            (kind, maskBits) = (KIND_BRANCH, 2);
        } else if (top == 3) {
            (kind, maskBits, branchHasValue) = (KIND_BRANCH, 2, true);
        } else if (b0 == 0) {
            if (node.length != 1) revert InvalidNodeEncoding();
            return (KIND_EMPTY, false, false, 0, 1);
        } else if (b0 >> 5 == 1) {
            (kind, maskBits, hashedValue) = (KIND_LEAF, 3, true);
        } else if (b0 >> 4 == 1) {
            (kind, maskBits, hashedValue, branchHasValue) = (KIND_BRANCH, 4, true, true);
        } else {
            revert InvalidNodeEncoding();
        }
        // forge-lint: disable-next-line(incorrect-shift)
        uint256 maxValue = 255 >> maskBits; // the count field's all-ones value (sp-trie decode_size)
        count = b0 & maxValue;
        off = 1;
        if (count == maxValue) {
            count -= 1;
            while (true) {
                if (off >= node.length) revert InvalidNodeEncoding();
                uint256 n = uint8(node[off++]);
                if (n < 255) {
                    count += n + 1;
                    break;
                }
                count += 255;
            }
        }
    }

    function _readValue(Proof memory p, bytes memory node, uint256 off, bool hashed)
        private
        pure
        returns (bytes memory value, uint256 end)
    {
        if (hashed) {
            value = _lookup(p, ScaleCodec.readBytes32(node, off));
            return (value, off + 32);
        }
        uint256 len;
        (len, off) = ScaleCodec.readCompact(node, off);
        value = ScaleCodec.slice(node, off, len);
        end = off + len;
    }

    function _skipValue(bytes memory node, uint256 off, bool hashed) private pure returns (uint256) {
        if (hashed) return off + 32;
        uint256 len;
        (len, off) = ScaleCodec.readCompact(node, off);
        return off + len;
    }

    function _nibble(bytes memory b, uint256 i) private pure returns (uint256) {
        uint256 v = uint8(b[i / 2]);
        return i % 2 == 0 ? v >> 4 : v & 0x0f;
    }
}
