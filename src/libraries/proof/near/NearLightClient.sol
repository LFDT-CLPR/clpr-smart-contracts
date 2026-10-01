// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";

/// @title NearLightClient
/// @notice NEAR light client (NEP-25, nomicon "ChainSpec/LightClient") and NEAR state-trie proofs.
///
/// Checked against nearcore `bb04d86` (30 Sep 2026):
///  - block hash: `LightClientBlockLiteView::hash` (core/primitives/src/views.rs) =
///    sha256(sha256(sha256(borsh(BlockHeaderInnerLite)) ‖ inner_rest_hash) ‖ prev_block_hash);
///    next block hash = sha256(next_block_inner_hash ‖ block hash) (`merkle::combine_hash`).
///  - approval message: `Approval::get_data_for_sig(Endorsement(next_block_hash), height + 2)` =
///    borsh(ApprovalInner::Endorsement) ‖ u64le(height + 2) = 0x00 ‖ next_block_hash ‖ u64le(height + 2).
///  - producers: `compute_bp_hash_from_validator_stakes(.., true)` = sha256(borsh(Vec<ValidatorStake>)),
///    ValidatorStake::V1 = 0x00 ‖ account_id(u32 len ‖ utf8) ‖ PublicKey(u8 type ‖ key) ‖ u128 stake.
///  - quorum: approved_stake * 3 > total_stake * 2 over the producers of the block's epoch
///    (test-loop-tests/src/tests/light_client.rs `validate_light_client_block`).
///  - state root: `Chunks::compute_state_root` = merklize(chunk.prev_state_root) with nearcore's
///    `merklize` (leaf sha256(root), node sha256(l ‖ r), an odd node is carried up unchanged).
///  - trie: `RawTrieNodeWithSize` borsh (core/store/src/trie/raw_node.rs), node hash = sha256(borsh);
///    nibble paths use `NibbleSlice::encode_nibbles` (0x10 odd, 0x20 leaf);
///    key `TrieKey::ContractData` = 0x09 ‖ account_id ‖ ',' ‖ data key (core/primitives/src/trie_key.rs).
library NearLightClient {
    /// @dev Light-client block, as served by `next_light_client_block`, plus the producer set of its
    ///      epoch (raw borsh bytes) and the subset of approvals the relayer chose to send.
    struct Block {
        bytes32 prevBlockHash;
        bytes32 nextBlockInnerHash;
        bytes innerLite; // borsh BlockHeaderInnerLite (V1, 208 bytes)
        bytes32 innerRestHash;
        bytes producers; // borsh Vec<ValidatorStake> of the block's epoch
        uint256[] signers; // strictly increasing indices into `producers`
        bytes[] signatures; // 64-byte approval per signer, or empty = pre-verified in the signature cache
    }

    /// @dev The epoch window a light client trusts: the producers of `epochId` and of `nextEpochId`.
    struct EpochState {
        bytes32 epochId;
        bytes32 nextEpochId;
        bytes32 epochBpHash;
        bytes32 nextBpHash;
    }

    struct InnerLite {
        uint64 height;
        bytes32 epochId;
        bytes32 nextEpochId;
        bytes32 prevStateRoot;
        bytes32 nextBpHash;
    }

    uint256 internal constant INNER_LITE_V1_LENGTH = 208;
    uint256 internal constant MAX_PRODUCERS = 1024;
    uint8 internal constant KEY_ED25519 = 0;
    uint8 internal constant KEY_SECP256K1 = 1;
    uint8 internal constant COL_CONTRACT_DATA = 9;
    uint8 internal constant ACCOUNT_DATA_SEPARATOR = 0x2c; // ','

    error InnerLiteLength();
    error EpochNotTrusted(bytes32 epochId);
    error ProducersHashMismatch();
    error BadProducers();
    error SignersNotAscending();
    error SignerOutOfRange();
    error SignerKeyNotEd25519(uint256 index);
    error InsufficientStake(uint256 approved, uint256 total);
    error ShardIndexOutOfRange();
    error StateRootMismatch();
    error TrieNodeHashMismatch(uint256 index);
    error TrieMalformedNode(uint256 index);
    error TrieKeyNotFound();
    error TrieProofTooLong();
    error TrieKeyPresent();
    error TrieValueMismatch();

    // ── Light client ─────────────────────────────────────────────────────────

    /// @notice Verify one light-client block against the trusted epoch window and advance the window
    ///         when the block is in the next epoch.
    function verifyBlock(
        EpochState memory st,
        Block memory b,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache cache
    ) internal view returns (InnerLite memory lite, EpochState memory next) {
        lite = parseInnerLite(b.innerLite);
        bytes32 bpHash;
        bool advances;
        if (lite.epochId == st.epochId) {
            bpHash = st.epochBpHash;
        } else if (lite.epochId == st.nextEpochId) {
            bpHash = st.nextBpHash;
            advances = true;
        } else {
            revert EpochNotTrusted(lite.epochId);
        }
        if (sha256(b.producers) != bpHash) revert ProducersHashMismatch();

        bytes memory message = approvalMessage(b, lite.height);
        _checkApprovals(b, message, ed25519, cache);

        next = advances
            ? EpochState({
                epochId: lite.epochId,
                nextEpochId: lite.nextEpochId,
                epochBpHash: st.nextBpHash,
                nextBpHash: lite.nextBpHash
            })
            : st;
    }

    /// @notice The bytes every approving producer signed for this light-client block.
    function approvalMessage(Block memory b, uint64 height) internal pure returns (bytes memory) {
        bytes32 current =
            sha256(abi.encodePacked(sha256(abi.encodePacked(sha256(b.innerLite), b.innerRestHash)), b.prevBlockHash));
        bytes32 nextHash = sha256(abi.encodePacked(b.nextBlockInnerHash, current));
        return abi.encodePacked(uint8(0), nextHash, _le64(height + 2));
    }

    /// @notice The block hash (`LightClientBlockLiteView::hash`).
    function blockHash(Block memory b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(sha256(b.innerLite), b.innerRestHash)), b.prevBlockHash));
    }

    function _checkApprovals(
        Block memory b,
        bytes memory message,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache cache
    ) private view {
        (bytes32[] memory keys, uint8[] memory keyTypes, uint256[] memory stakes, uint256 total) =
            parseProducers(b.producers);
        if (b.signatures.length != b.signers.length) revert BadProducers();
        bytes32 messageHash = keccak256(message);
        uint256 approved;
        uint256 prev;
        for (uint256 i = 0; i < b.signers.length; i++) {
            uint256 idx = b.signers[i];
            if (i > 0 && idx <= prev) revert SignersNotAscending();
            prev = idx;
            if (idx >= keys.length) revert SignerOutOfRange();
            if (keyTypes[idx] != KEY_ED25519) revert SignerKeyNotEd25519(idx);
            ClprEd25519Check.check(ed25519, cache, keys[idx], message, messageHash, b.signatures[i], idx);
            approved += stakes[idx];
        }
        if (approved * 3 <= total * 2) revert InsufficientStake(approved, total);
    }

    /// @notice Strict decode of borsh `BlockHeaderInnerLite` (V1).
    function parseInnerLite(bytes memory raw) internal pure returns (InnerLite memory lite) {
        if (raw.length != INNER_LITE_V1_LENGTH) revert InnerLiteLength();
        lite.height = _readLe64(raw, 0);
        lite.epochId = _word(raw, 8);
        lite.nextEpochId = _word(raw, 40);
        lite.prevStateRoot = _word(raw, 72);
        // 104 prev_outcome_root, 136 timestamp (u64)
        lite.nextBpHash = _word(raw, 144);
        // 176 block_merkle_root
    }

    /// @notice Strict decode of borsh `Vec<ValidatorStake>`: per producer its key (zero for a
    ///         secp256k1 key, which can never approve here), key type and stake; plus the total stake.
    function parseProducers(bytes memory raw)
        internal
        pure
        returns (bytes32[] memory keys, uint8[] memory keyTypes, uint256[] memory stakes, uint256 total)
    {
        if (raw.length < 4) revert BadProducers();
        uint256 n = _readLe32(raw, 0);
        if (n == 0 || n > MAX_PRODUCERS) revert BadProducers();
        keys = new bytes32[](n);
        keyTypes = new uint8[](n);
        stakes = new uint256[](n);
        uint256 off = 4;
        for (uint256 i = 0; i < n; i++) {
            if (off + 5 > raw.length || uint8(raw[off]) != 0) revert BadProducers(); // ValidatorStake::V1
            uint256 idLen = _readLe32(raw, off + 1);
            off += 5 + idLen;
            if (idLen < 2 || idLen > 64 || off + 1 > raw.length) revert BadProducers();
            uint8 kt = uint8(raw[off]);
            off += 1;
            if (kt == KEY_ED25519) {
                if (off + 32 > raw.length) revert BadProducers();
                keys[i] = _word(raw, off);
                off += 32;
            } else if (kt == KEY_SECP256K1) {
                off += 64;
            } else {
                revert BadProducers();
            }
            keyTypes[i] = kt;
            if (off + 16 > raw.length) revert BadProducers();
            uint256 stake = _readLe128(raw, off);
            off += 16;
            stakes[i] = stake;
            total += stake;
        }
        if (off != raw.length) revert BadProducers();
    }

    // ── State root ───────────────────────────────────────────────────────────

    /// @notice Check `shardStateRoots` merklize to the block's `prev_state_root` and return one shard's root.
    function shardStateRoot(bytes32 prevStateRoot, bytes32[] memory shardStateRoots, uint256 shardIndex)
        internal
        pure
        returns (bytes32)
    {
        if (shardIndex >= shardStateRoots.length) revert ShardIndexOutOfRange();
        if (merklize(shardStateRoots) != prevStateRoot) revert StateRootMismatch();
        return shardStateRoots[shardIndex];
    }

    /// @notice nearcore `merkle::merklize` over 32-byte items.
    function merklize(bytes32[] memory items) internal pure returns (bytes32) {
        uint256 n = items.length;
        if (n == 0) return bytes32(0);
        bytes32[] memory h = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            h[i] = sha256(abi.encodePacked(items[i]));
        }
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                h[i] = 2 * i + 1 < n ? sha256(abi.encodePacked(h[2 * i], h[2 * i + 1])) : h[2 * i];
            }
            n = m;
        }
        return h[0];
    }

    // ── Trie ─────────────────────────────────────────────────────────────────

    /// @notice The trie key of contract storage entry `dataKey` of `accountId`.
    function contractDataKey(bytes memory accountId, bytes memory dataKey) internal pure returns (bytes memory) {
        return abi.encodePacked(COL_CONTRACT_DATA, accountId, ACCOUNT_DATA_SEPARATOR, dataKey);
    }

    /// @notice Prove `value` is stored under `key` in the trie with root `root`. `nodes` are the raw
    ///         `RawTrieNodeWithSize` encodings on the path, root first.
    function verifyValue(bytes32 root, bytes memory key, bytes[] memory nodes, bytes memory value) internal pure {
        (bool found, bytes memory node, uint256 valueOff) = _walk(root, key, nodes);
        if (!found) revert TrieKeyNotFound();
        _checkValue(node, valueOff, value);
    }

    /// @notice Prove no value is stored under `key`: the path, root first, ends where the key leaves
    ///         the trie (a missing branch child, a diverging leaf or extension path, a leaf with a
    ///         shorter key, or a branch without a value at the key's end).
    function verifyAbsent(bytes32 root, bytes memory key, bytes[] memory nodes) internal pure {
        (bool found,,) = _walk(root, key, nodes);
        if (found) revert TrieKeyPresent();
    }

    /// @dev Walk `key` down the hash-linked `nodes`. Returns `found = true` with the node holding the
    ///      key's `ValueRef` and its offset, or `found = false` when the last node proves the key is
    ///      absent. Every node up to that point is hash-checked and fully length-checked; a path that
    ///      ends on a child hash, or carries nodes after the value, reverts.
    function _walk(bytes32 root, bytes memory key, bytes[] memory nodes)
        private
        pure
        returns (bool found, bytes memory node, uint256 valueOff)
    {
        uint256 nib = 0; // nibble position in key
        uint256 keyNibbles = key.length * 2;
        bytes32 expected = root;
        for (uint256 i = 0; i < nodes.length; i++) {
            node = nodes[i];
            bool last = i + 1 == nodes.length;
            if (sha256(node) != expected) revert TrieNodeHashMismatch(i);
            if (node.length < 1 + 8) revert TrieMalformedNode(i);
            uint8 tag = uint8(node[0]);
            uint256 off = 1;
            if (tag == 0 || tag == 3) {
                // Leaf(Vec<u8>, ValueRef) | Extension(Vec<u8>, CryptoHash)
                if (off + 4 > node.length) revert TrieMalformedNode(i);
                uint256 len = _readLe32(node, off);
                off += 4;
                if (len == 0 || off + len + (tag == 0 ? 36 : 32) + 8 != node.length) revert TrieMalformedNode(i);
                uint8 first = uint8(node[off]);
                bool isLeaf = first & 0x20 != 0;
                if (isLeaf != (tag == 0) || first & 0xc0 != 0 || (first & 0x10 == 0 && first & 0x0f != 0)) {
                    revert TrieMalformedNode(i);
                }
                // nibbles: optional odd first nibble in the low half of the flag byte, then full bytes
                uint256 pathNibbles = (len - 1) * 2 + (first & 0x10 != 0 ? 1 : 0);
                if (!_pathMatches(node, off, len, first, key, nib, pathNibbles)) return (false, node, 0);
                nib += pathNibbles;
                off += len;
                if (tag == 0) {
                    // a leaf whose key is a strict prefix of this key leaves the key absent
                    if (nib != keyNibbles) return (false, node, 0);
                    if (!last) revert TrieProofTooLong();
                    return (true, node, off);
                }
                expected = _word(node, off);
            } else if (tag == 1 || tag == 2) {
                // BranchNoValue(Children) | BranchWithValue(ValueRef, Children)
                uint256 vOff = off;
                if (tag == 2) off += 36;
                if (off + 2 > node.length) revert TrieMalformedNode(i);
                uint256 bitmap = uint256(uint8(node[off])) | (uint256(uint8(node[off + 1])) << 8);
                off += 2;
                if (off + _popcount16(bitmap) * 32 + 8 != node.length) revert TrieMalformedNode(i);
                if (nib == keyNibbles) {
                    if (tag == 1) return (false, node, 0);
                    if (!last) revert TrieProofTooLong();
                    return (true, node, vOff);
                }
                uint256 c = _nibble(key, nib);
                if (bitmap & (1 << c) == 0) return (false, node, 0);
                expected = _word(node, off + 32 * _popcount16(bitmap & ((1 << c) - 1)));
                nib += 1;
            } else {
                revert TrieMalformedNode(i);
            }
        }
        // the path ended on a child hash: the proof is missing nodes
        revert TrieKeyNotFound();
    }

    /// @dev Whether the encoded nibble path of a leaf/extension equals `key` from nibble `nib`.
    function _pathMatches(
        bytes memory node,
        uint256 off,
        uint256 len,
        uint8 first,
        bytes memory key,
        uint256 nib,
        uint256 pathNibbles
    ) private pure returns (bool) {
        if (nib + pathNibbles > key.length * 2) return false;
        uint256 p = 0;
        if (first & 0x10 != 0) {
            if (first & 0x0f != _nibble(key, nib)) return false;
            p = 1;
        }
        for (uint256 j = 1; j < len; j++) {
            uint8 bt = uint8(node[off + j]);
            if (bt >> 4 != _nibble(key, nib + p) || bt & 0x0f != _nibble(key, nib + p + 1)) return false;
            p += 2;
        }
        return true;
    }

    function _checkValue(bytes memory node, uint256 off, bytes memory value) private pure {
        uint256 len = _readLe32(node, off);
        bytes32 h = _word(node, off + 4);
        if (len != value.length || sha256(value) != h) revert TrieValueMismatch();
    }

    // ── byte helpers ─────────────────────────────────────────────────────────

    function _nibble(bytes memory key, uint256 i) private pure returns (uint256) {
        uint8 b = uint8(key[i / 2]);
        return i % 2 == 0 ? b >> 4 : b & 0x0f;
    }

    function _popcount16(uint256 x) private pure returns (uint256 c) {
        while (x != 0) {
            c += x & 1;
            x >>= 1;
        }
    }

    function _word(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _readLe32(bytes memory b, uint256 off) internal pure returns (uint256 v) {
        for (uint256 i = 0; i < 4; i++) {
            v |= uint256(uint8(b[off + i])) << (8 * i);
        }
    }

    function _readLe64(bytes memory b, uint256 off) internal pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) {
            v |= uint64(uint8(b[off + i])) << uint64(8 * i);
        }
    }

    function _readLe128(bytes memory b, uint256 off) internal pure returns (uint256 v) {
        for (uint256 i = 0; i < 16; i++) {
            v |= uint256(uint8(b[off + i])) << (8 * i);
        }
    }

    function _le64(uint64 v) internal pure returns (bytes8 out) {
        uint64 r;
        for (uint256 i = 0; i < 8; i++) {
            r = (r << 8) | ((v >> uint64(8 * i)) & 0xff);
        }
        out = bytes8(r);
    }
}
