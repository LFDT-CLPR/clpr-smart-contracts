// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title EvmMptBuilder
/// @dev Why this exists. {ClprEvmStateProof.verifyProvenSlots} verifies each storage-proof entry
///      independently against one shared storage root, and each entry carries **its own** node
///      list. Building a real trie makes the measured MPT walk realistic: proof depth is a property of the
///      trie, and depth is what the walk's gas is proportional to.
///
/// @dev Depth control. ETH mainnet's account trie holds ~10^8.4 accounts, so a path crosses ~7-8 branch nodes before
///      its leaf. {padKeysPresent} and {padKeysAbsent} synthesise sibling keys that share a controlled nibble prefix with a target,
///      forcing a branch node at every level along that target's path.
///
/// @dev Deviation from canonical Ethereum RLP: children are **always** hash-referenced, never
///      inlined, even when a node's own encoding is under 32 bytes.
///      {MerklePatriciaProof} rejects inline child references outright
///      (`MPTInlineNodeUnsupported`), so hash-referencing everywhere is what the verifier under
///      measurement accepts.
contract EvmMptBuilder {
    /// @dev A key was walked into a subtree whose node was never stored — the trie is malformed.
    error NodeMissing(bytes32 nodeHash);
    /// @dev `build` was given mismatched key/value array lengths.
    error KeyValueLengthMismatch();
    /// @dev `build` was called with no keys; an empty trie has no root this walker can express.
    error EmptyTrie();

    uint256 private constant NIBBLES = 64; // 32-byte key hash

    /// @dev keccak256(node) => node RLP. Populated by {build}, read by {proof}.
    mapping(bytes32 => bytes) private _nodes;

    /// @notice Root hash of the trie most recently built.
    bytes32 public root;

    // ─────────────────────────────────────────────────────────────────────────
    //   Build
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Build a trie over `keyHashes => values` and return its root.
    /// @param keyHashes Trie paths
    /// @param values The **inner** leaf payloads.
    function build(bytes32[] memory keyHashes, bytes[] memory values) public returns (bytes32) {
        if (keyHashes.length != values.length) revert KeyValueLengthMismatch();
        if (keyHashes.length == 0) revert EmptyTrie();

        uint256[] memory idx = new uint256[](keyHashes.length);
        for (uint256 i = 0; i < idx.length; i++) {
            idx[i] = i;
        }
        root = _build(keyHashes, values, idx, 0);
        return root;
    }

    /// @dev Emit the subtree covering `idx` (all sharing nibbles `[0, depth)`) and return its hash.
    ///      One index ⇒ leaf; a shared prefix ⇒ extension; otherwise a 17-item branch.
    function _build(bytes32[] memory k, bytes[] memory v, uint256[] memory idx, uint256 depth)
        private
        returns (bytes32)
    {
        if (idx.length == 1) {
            uint256 i = idx[0];
            bytes[] memory leaf = new bytes[](2);
            leaf[0] = RLP.encode(_compactPath(k[i], depth, NIBBLES - depth, true));
            leaf[1] = RLP.encode(v[i]);
            return _put(RLP.encode(leaf));
        }

        uint256 lcp = _commonPrefix(k, idx, depth);
        if (lcp > 0) {
            bytes32 childRef = _build(k, v, idx, depth + lcp);
            bytes[] memory ext = new bytes[](2);
            ext[0] = RLP.encode(_compactPath(k[idx[0]], depth, lcp, false));
            ext[1] = RLP.encode(childRef);
            return _put(RLP.encode(ext));
        }

        bytes[] memory branch = new bytes[](17);
        for (uint256 nib = 0; nib < 16; nib++) {
            uint256[] memory sub = _partition(k, idx, depth, nib);
            branch[nib] = sub.length == 0 ? RLP.encode(new bytes(0)) : RLP.encode(_build(k, v, sub, depth + 1));
        }
        branch[16] = RLP.encode(new bytes(0)); // no value at a branch: keys are all full-length
        return _put(RLP.encode(branch));
    }

    /// @dev Number of nibbles from `depth` on which every index in `idx` agrees.
    function _commonPrefix(bytes32[] memory k, uint256[] memory idx, uint256 depth) private pure returns (uint256 lcp) {
        while (depth + lcp < NIBBLES) {
            uint256 nib = _nibAt(k[idx[0]], depth + lcp);
            for (uint256 j = 1; j < idx.length; j++) {
                if (_nibAt(k[idx[j]], depth + lcp) != nib) return lcp;
            }
            lcp++;
        }
    }

    /// @dev The subset of `idx` whose nibble at `depth` equals `nib`.
    function _partition(bytes32[] memory k, uint256[] memory idx, uint256 depth, uint256 nib)
        private
        pure
        returns (uint256[] memory sub)
    {
        uint256 count;
        for (uint256 j = 0; j < idx.length; j++) {
            if (_nibAt(k[idx[j]], depth) == nib) count++;
        }
        sub = new uint256[](count);
        uint256 p;
        for (uint256 j = 0; j < idx.length; j++) {
            if (_nibAt(k[idx[j]], depth) == nib) sub[p++] = idx[j];
        }
    }

    function _put(bytes memory node) private returns (bytes32 nodeHash) {
        nodeHash = keccak256(node);
        _nodes[nodeHash] = node;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Proof emission
    // ─────────────────────────────────────────────────────────────────────────
    function proof(bytes32 keyHash) public view returns (bytes[] memory out) {
        bytes[] memory buf = new bytes[](NIBBLES + 1);
        uint256 n;
        bytes32 nodeHash = root;
        uint256 keyIdx;

        while (true) {
            bytes memory node = _nodes[nodeHash];
            if (node.length == 0) revert NodeMissing(nodeHash);
            buf[n++] = node;

            Memory.Slice[] memory items = RLP.decodeList(node);
            if (items.length == 17) {
                if (keyIdx >= NIBBLES) break; // value sits at the branch terminal
                bytes memory child = RLP.readBytes(items[_nibAt(keyHash, keyIdx)]);
                keyIdx++;
                if (child.length == 0) break; // proven absent under this branch
                nodeHash = _toBytes32(child);
            } else {
                bytes memory path = RLP.readBytes(items[0]);
                (bool isLeaf, uint256 pathLen, uint256 pathOffset) = _decodePathPrefix(path);
                bool diverges = pathLen + keyIdx > NIBBLES;
                for (uint256 j = 0; !diverges && j < pathLen; j++) {
                    if (_pathNibAt(path, pathOffset + j) != _nibAt(keyHash, keyIdx + j)) diverges = true;
                }
                if (isLeaf || diverges) break; // leaf reached, or path diverges ⇒ absent
                keyIdx += pathLen;
                nodeHash = _toBytes32(RLP.readBytes(items[1]));
            }
        }

        out = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = buf[i];
        }
    }

    /// @notice {proof} in the wire shape the verifiers consume: an RLP list whose items are
    ///         byte strings wrapping each node's own RLP.
    function proofRlp(bytes32 keyHash) public view returns (bytes memory) {
        bytes[] memory nodes = proof(keyHash);
        bytes[] memory wrapped = new bytes[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            wrapped[i] = RLP.encode(nodes[i]);
        }
        return RLP.encode(wrapped);
    }

    /// @notice Proof depth for `keyHash`
    function proofDepth(bytes32 keyHash) external view returns (uint256) {
        return proof(keyHash).length;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Depth padding
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Sibling keys that force `target`'s **inclusion** path to cross `depth` branch nodes
    ///         before its leaf (proof depth `depth + 1`).
    /// @dev Key `i` agrees with `target` on nibbles `[0, i)` and differs at nibble `i`, so a branch
    ///      is unavoidable at every level `i < depth`.
    function padKeysPresent(bytes32 target, uint256 depth) external pure returns (bytes32[] memory pad) {
        pad = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            pad[i] = _bumpNibble(target, i);
        }
    }

    /// @notice Sibling keys that force `target`'s **exclusion** path to cross `depth` branch nodes
    ///         before diverging (proof depth `depth + 1`). `target` itself is never inserted.
    /// @dev Keys `1..depth` agree with `target` on nibbles `[0, i)` and differ at nibble `i`; the
    ///      deepest one leaves a leaf at level `depth` whose path diverges from `target`.
    function padKeysAbsent(bytes32 target, uint256 depth) external pure returns (bytes32[] memory pad) {
        pad = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            pad[i] = _bumpNibble(target, i + 1);
        }
    }

    /// @notice Like {padKeysPresent}, but fills **all 16 slots** of every branch node on the path.
    /// @dev Branch-node width is not cosmetic: a 2-child branch encodes to ~81 bytes while a full one
    ///      is ~529, and the walker keccaks and copies every node it visits.
    function padKeysDensePresent(bytes32 target, uint256 depth) external pure returns (bytes32[] memory pad) {
        pad = new bytes32[](depth * 15);
        uint256 n;
        for (uint256 i = 0; i < depth; i++) {
            for (uint256 d = 1; d < 16; d++) {
                pad[n++] = _setNibble(target, i, (_nibAt(target, i) + d) & 0xf);
            }
        }
    }

    /// @notice Dense-branch counterpart of {padKeysAbsent}: `target` stays out of the trie, its path
    ///         crosses `depth` full branch nodes, and its slot in the last one is empty.
    function padKeysDenseAbsent(bytes32 target, uint256 depth) external pure returns (bytes32[] memory pad) {
        pad = new bytes32[](depth * 15);
        uint256 n;
        for (uint256 i = 1; i <= depth; i++) {
            for (uint256 d = 1; d < 16; d++) {
                pad[n++] = _setNibble(target, i, (_nibAt(target, i) + d) & 0xf);
            }
        }
    }

    /// @dev `target` with the nibble at `pos` incremented mod 16 — a key sharing exactly the first
    ///      `pos` nibbles.
    function _bumpNibble(bytes32 target, uint256 pos) private pure returns (bytes32) {
        return _setNibble(target, pos, (_nibAt(target, pos) + 1) & 0xf);
    }

    /// @dev `target` with the nibble at `pos` replaced by `value`.
    function _setNibble(bytes32 target, uint256 pos, uint256 value) private pure returns (bytes32) {
        require(pos < NIBBLES, "pos");
        uint256 shift = 4 * (NIBBLES - 1 - pos);
        return bytes32((uint256(target) & ~(uint256(0xf) << shift)) | ((value & 0xf) << shift));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Nibble / compact-path primitives (mirror MerklePatriciaProof)
    // ─────────────────────────────────────────────────────────────────────────

    function _nibAt(bytes32 keyHash, uint256 i) private pure returns (uint256) {
        uint8 b = uint8(keyHash[i >> 1]);
        return (i & 1 == 0) ? (b >> 4) : (b & 0x0f);
    }

    function _pathNibAt(bytes memory path, uint256 i) private pure returns (uint256) {
        uint8 b = uint8(path[i >> 1]);
        return (i & 1 == 0) ? (b >> 4) : (b & 0x0f);
    }

    function _decodePathPrefix(bytes memory path)
        private
        pure
        returns (bool isLeaf, uint256 pathLen, uint256 payloadOffsetNibbles)
    {
        uint8 prefixNib = uint8(path[0]) >> 4;
        isLeaf = (prefixNib & 0x2) != 0;
        if ((prefixNib & 0x1) != 0) {
            pathLen = path.length * 2 - 1;
            payloadOffsetNibbles = 1;
        } else {
            pathLen = path.length * 2 - 2;
            payloadOffsetNibbles = 2;
        }
    }

    /// @dev MPT compact ("hex-prefix") encoding of `key`'s nibbles `[from, from + len)`.
    ///      Prefix nibble: bit 1 = leaf, bit 0 = odd length; even lengths get a zero pad nibble.
    function _compactPath(bytes32 key, uint256 from, uint256 len, bool isLeaf) private pure returns (bytes memory out) {
        uint256 odd = len & 1;
        out = new bytes((len + (odd == 1 ? 1 : 2)) / 2);
        uint256 p;
        _setNib(out, p++, (isLeaf ? 2 : 0) | odd);
        if (odd == 0) _setNib(out, p++, 0);
        for (uint256 j = 0; j < len; j++) {
            _setNib(out, p++, _nibAt(key, from + j));
        }
    }

    function _setNib(bytes memory b, uint256 i, uint256 v) private pure {
        // `b` starts zeroed, so OR-ing in place is equivalent to assignment.
        // forge-lint: disable-next-line(unsafe-typecast)
        b[i >> 1] = bytes1(uint8(uint8(b[i >> 1]) | ((i & 1) == 0 ? (v << 4) : v)));
    }

    function _toBytes32(bytes memory b) private pure returns (bytes32 out) {
        assembly ("memory-safe") {
            out := mload(add(b, 32))
        }
    }
}
