// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";

/// @title ClprCommitteeMerkle
/// @notice keccak256 Merkle commitment over the 512 uncompressed sync-committee pubkeys.
///
/// The trust anchor stores only this 32-byte root (plus the aggregate key); the actual keys are
/// supplied per bundle for the (usually few) NON-signers and authenticated against the root, so
/// neither the contract's storage nor the hot path ever carries the full 66 KB key list.
///
/// Tree shape (must be mirrored byte-for-byte by the relay and the Java implementation):
///   - 512 leaves, leaf_i = keccak256(uncompressedKey_i) (128-byte EIP-2537 G1, pad16‖x‖pad16‖y);
///   - parent = keccak256(left ‖ right); complete binary tree of depth 9;
///   - inclusion is POSITIONAL: bit j of the committee index says whether the running hash is the
///     right child at level j. Binding the key to its index is what stops a relay from passing an
///     arbitrary point as a "non-signer" (the q = aggregate − forged attack) — only the key that
///     the beacon committed at that bitvector position can fold to the root.
library ClprCommitteeMerkle {
    // Single source of truth is the SSZ library (the beacon-protocol constant). DEPTH must stay
    // log2(COMMITTEE_SIZE); a consistency test asserts `1 << DEPTH == COMMITTEE_SIZE`.
    uint256 internal constant COMMITTEE_SIZE = ClprBeaconSsz.SYNC_COMMITTEE_SIZE;
    uint256 internal constant DEPTH = 9; // log2(COMMITTEE_SIZE)
    uint256 internal constant KEY_LENGTH = 128; // uncompressed EIP-2537 G1
    /// @dev One non-signer entry on the wire: key (128) ‖ 9 bottom-up siblings (9 × 32).
    uint256 internal constant ENTRY_LENGTH = KEY_LENGTH + DEPTH * 32; // 416

    /// @notice The committee key list did not have exactly 512 entries.
    error CommitteeMerkleWrongKeyCount();
    /// @notice {fold} was given an empty or non-power-of-two node list.
    error CommitteeMerkleNotPowerOfTwo();

    /// @notice Merkle root over the 512 uncompressed keys (built once per rotation/genesis;
    ///         1,023 keccaks, no storage).
    function root(bytes[] memory keys) internal pure returns (bytes32 result) {
        if (keys.length != COMMITTEE_SIZE) revert CommitteeMerkleWrongKeyCount();
        bytes32[] memory nodes = new bytes32[](COMMITTEE_SIZE);
        for (uint256 i = 0; i < COMMITTEE_SIZE; i++) {
            nodes[i] = keccak256(keys[i]);
        }
        // In-place fold: children 2i/2i+1 are 64 contiguous bytes, so each parent is a
        // single keccak over the array itself — no per-node abi.encodePacked buffer.
        assembly ("memory-safe") {
            let base := add(nodes, 32)
            // mload(nodes) = nodes.length = COMMITTEE_SIZE (indirect constants can't be used in assembly)
            for { let n := mload(nodes) } gt(n, 1) {} {
                n := shr(1, n)
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    mstore(add(base, shl(5, i)), keccak256(add(base, shl(6, i)), 0x40))
                }
            }
            result := mload(base)
        }
    }

    /// @notice Fold a power-of-two run of sibling nodes of this tree (leaf hashes, or subtree roots of
    ///         one level) into their common ancestor with the same `parent = keccak256(left ‖ right)`
    ///         rule as {root}. 32 leaves fold to a level-5 node; the 16 level-5 nodes fold to the root.
    ///         Mutates `nodes`.
    function fold(bytes32[] memory nodes) internal pure returns (bytes32 result) {
        uint256 n = nodes.length;
        if (n == 0 || (n & (n - 1)) != 0) revert CommitteeMerkleNotPowerOfTwo();
        assembly ("memory-safe") {
            let base := add(nodes, 32)
            for {} gt(n, 1) {} {
                n := shr(1, n)
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    mstore(add(base, shl(5, i)), keccak256(add(base, shl(6, i)), 0x40))
                }
            }
            result := mload(base)
        }
    }

    /// @notice Verify a wire entry (`key ‖ proof`, read in place from `entry`) proves its key at
    ///         committee `index` under `expectedRoot`; on success `key` is the extracted 128-byte
    ///         key — the only copy made. `ok` is false on any shape or fold mismatch (caller reverts).
    function verifyAndExtractKey(Memory.Slice entry, uint256 index, bytes32 expectedRoot)
        internal
        pure
        returns (bool ok, bytes memory key)
    {
        if (Memory.length(entry) != ENTRY_LENGTH || index >= COMMITTEE_SIZE) return (false, key);
        bytes32 raw = Memory.Slice.unwrap(entry); // OZ Memory packing: length(128) ‖ pointer(128)
        bytes32 computed;
        assembly ("memory-safe") {
            let ptr := and(raw, shr(128, not(0)))
            // The key must be materialized for the caller anyway (the single per-entry copy);
            // hashing the copy keeps the leaf keccak contiguous. Siblings are read in place.
            key := mload(0x40)
            mstore(key, KEY_LENGTH)
            mcopy(add(key, 32), ptr, KEY_LENGTH)
            mstore(0x40, add(key, add(32, KEY_LENGTH)))
            computed := keccak256(add(key, 32), KEY_LENGTH)
            // Fold bottom-up through the 9 siblings using the 0x00/0x20 scratch space;
            // bit j of `index` picks whether the running hash is the right child.
            let proofPtr := add(ptr, KEY_LENGTH)
            for { let j := 0 } lt(j, DEPTH) { j := add(j, 1) } {
                let sib := mload(add(proofPtr, shl(5, j)))
                switch and(shr(j, index), 1)
                case 1 {
                    mstore(0x00, sib)
                    mstore(0x20, computed)
                }
                default {
                    mstore(0x00, computed)
                    mstore(0x20, sib)
                }
                computed := keccak256(0x00, 0x40)
            }
        }
        ok = computed == expectedRoot;
    }
}
