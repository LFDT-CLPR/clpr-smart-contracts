// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @title ClprBeaconSsz
/// @notice Helpers for SSZ Merkle-proof verification used by the Ethereum mainnet verifier.
///
/// Ethereum's beacon chain uses SSZ (Simple Serialize) with sha256-based binary Merkle trees.
/// Each leaf is sha256-hashed, and internal nodes are sha256(left || right).
/// A Merkle proof is a vector of 32-byte siblings from leaf to root.
///
/// The ExecutionPayloadHeader is stored inside BeaconBlockBody, which is inside BeaconBlockBody.
/// The generalized index for `execution_payload` within a `BeaconBlockBody` (Capella+) is 25 (gindex).
///
/// Reference: https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md
library ClprBeaconSsz {
    error SszProofLengthMismatch(uint256 got, uint256 expected);
    error SszProofInvalid();
    error InvalidCommitteeSize();
    error ChunksNotPowerOfTwo();
    error InvalidPubkeyLength();

    // ── Sync committee / BLS sizes (Altair, unchanged through Electra) ────────
    uint256 internal constant SYNC_COMMITTEE_SIZE = 512;
    uint256 internal constant BLS_PUBKEY_LENGTH = 48;

    /// @dev `DOMAIN_SYNC_COMMITTEE` (0x07000000) in the top 4 bytes of a 32-byte word.
    bytes32 internal constant DOMAIN_SYNC_COMMITTEE_PREFIX = bytes32(uint256(0x07000000) << 224);

    /// @notice Verify an SSZ Merkle inclusion proof.
    /// @param leaf         The 32-byte leaf value (already sha256-hashed if required).
    /// @param proof        Array of 32-byte sibling hashes from leaf up to (but excluding) root.
    /// @param root         Expected Merkle root.
    /// @param gindex       Generalized index of the leaf in the tree.
    function verifyProof(bytes32 leaf, bytes32[] memory proof, bytes32 root, uint256 gindex)
        internal
        pure
        returns (bool)
    {
        bytes32 computed = leaf;
        uint256 idx = gindex;
        for (uint256 i = 0; i < proof.length; i++) {
            if (idx & 1 == 1) {
                // leaf is right child
                computed = sha256(abi.encodePacked(proof[i], computed));
            } else {
                // leaf is left child
                computed = sha256(abi.encodePacked(computed, proof[i]));
            }
            idx >>= 1;
        }
        return computed == root;
    }

    /// @notice Convenience wrapper that reverts instead of returning false.
    function verifyProofOrRevert(bytes32 leaf, bytes32[] memory proof, bytes32 root, uint256 gindex) internal pure {
        if (!verifyProof(leaf, proof, root, gindex)) revert SszProofInvalid();
    }

    /// @notice Hash a BeaconBlockHeader to produce its hash_tree_root.
    ///         Layout (Capella): [slot(8), proposer_index(8), parent_root(32),
    ///                           state_root(32), body_root(32)]
    ///         SSZ hash_tree_root of a container = merkleize(chunks(fields)).
    ///         Each field is packed/padded to 32-byte chunks.
    ///
    /// @param slot           8-byte slot number (little-endian uint64, zero-padded to 32).
    /// @param proposerIndex  8-byte proposer validator index.
    /// @param parentRoot     32-byte parent block root.
    /// @param stateRoot      32-byte beacon state root.
    /// @param bodyRoot       32-byte beacon block body root.
    function beaconBlockHeaderRoot(
        uint64 slot,
        uint64 proposerIndex,
        bytes32 parentRoot,
        bytes32 stateRoot,
        bytes32 bodyRoot
    ) internal pure returns (bytes32) {
        // SSZ uint64 → little-endian padded to 32 bytes.
        bytes32 slotChunk = _uint64ToLE32(slot);
        bytes32 proposerChunk = _uint64ToLE32(proposerIndex);
        // Merkleize 5 chunks: next power-of-two = 8 chunks (pad with zeros).
        bytes32[8] memory chunks;
        chunks[0] = slotChunk;
        chunks[1] = proposerChunk;
        chunks[2] = parentRoot;
        chunks[3] = stateRoot;
        chunks[4] = bodyRoot;
        // chunks[5..7] remain zero
        return _merkleize8(chunks);
    }

    /// @notice Compute the SSZ signing root: sha256(block_header_root || fork_data_root).
    ///         fork_data_root = hash_tree_root(ForkData{current_version, genesis_validators_root}).
    ///         For on-chain usage the prover supplies the pre-computed signing root.
    ///         This helper is provided for test/verification use.
    function computeSigningRoot(bytes32 blockHeaderRoot, bytes32 domain) internal pure returns (bytes32) {
        // SigningData: [object_root(32), domain(32)]
        bytes32[2] memory chunks;
        chunks[0] = blockHeaderRoot;
        chunks[1] = domain;
        return sha256(abi.encodePacked(chunks[0], chunks[1]));
    }

    /// @notice `compute_domain(DOMAIN_SYNC_COMMITTEE, forkVersion, genesisValidatorsRoot)`.
    ///         `fork_data_root = sha256(pad32(forkVersion) || genesisValidatorsRoot)`;
    ///         `domain = DOMAIN_SYNC_COMMITTEE(0x07000000) || fork_data_root[0:28]`.
    function computeSyncCommitteeDomain(bytes4 forkVersion, bytes32 genesisValidatorsRoot)
        internal
        pure
        returns (bytes32)
    {
        // pad32(forkVersion): the 4-byte version sits in the top bytes, low 28 bytes zero.
        bytes32 paddedVersion = bytes32(forkVersion);
        bytes32 forkDataRoot = sha256(abi.encodePacked(paddedVersion, genesisValidatorsRoot));
        // domain = 0x07000000 (top 4 bytes) || forkDataRoot[0:28] (shifted into the low 28 bytes).
        return DOMAIN_SYNC_COMMITTEE_PREFIX | (forkDataRoot >> 32);
    }

    /// @notice SSZ `hash_tree_root(SyncCommittee)` = `sha256(merkleize(pubkeyRoots) || pubkeyHash(aggregate))`
    ///         where each leaf is `sha256(pubkey48 || 16 zero bytes)` over the *compressed* 48-byte
    ///         encoding the beacon commits to — computed here from UNCOMPRESSED (128-byte EIP-2537)
    ///         pubkeys by compressing each on the fly. This lets the relayer ship ONLY the uncompressed
    ///         committee: the root is reconstructed from the derived compressed keys and proven against the beacon's
    ///         `next_sync_committee` branch, which authenticates the uncompressed keys in one pass (no
    ///         separate compressed committee, no separate compress-and-compare bind).
    /// @dev    Fail-closed: `compressG1` is a pure, injective encoding of a valid G1 point, so a wrong
    ///         uncompressed key can't reproduce the beacon-committed root — the branch check just fails.
    ///         (Direction matters: on-chain *de*compression is gas-infeasible; *compression* is cheap.)
    function syncCommitteeRootFromUncompressed(bytes[] memory uncompressedPubkeys, bytes memory uncompressedAggregate)
        internal
        pure
        returns (bytes32)
    {
        if (uncompressedPubkeys.length != SYNC_COMMITTEE_SIZE) revert InvalidCommitteeSize();
        bytes32[] memory leaves = new bytes32[](SYNC_COMMITTEE_SIZE);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            leaves[i] = pubkeyLeafFromUncompressed(uncompressedPubkeys[i]);
        }
        return syncCommitteeRootFromPubkeysRoot(merkleize(leaves), uncompressedAggregate);
    }

    /// @notice SSZ leaf of one committee member, `sha256(compressG1(key) || 16 zero bytes)`, from its
    ///         UNCOMPRESSED (128-byte EIP-2537) key. A run of these leaves merkleizes to a subtree of the
    ///         `pubkeys` vector, which is what lets the committee be processed in fixed-size chunks.
    function pubkeyLeafFromUncompressed(bytes memory uncompressedPubkey) internal pure returns (bytes32) {
        return _pubkeyHash64(ClprBls12381.compressG1(uncompressedPubkey));
    }

    /// @notice SSZ `hash_tree_root(SyncCommittee)` from the root of its `pubkeys` vector (512 leaves, see
    ///         {pubkeyLeafFromUncompressed}) and the UNCOMPRESSED aggregate key.
    function syncCommitteeRootFromPubkeysRoot(bytes32 pubkeysRoot, bytes memory uncompressedAggregate)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(pubkeysRoot, pubkeyLeafFromUncompressed(uncompressedAggregate)));
    }

    /// @notice SSZ balanced-binary-tree merkleization over a power-of-two number of 32-byte leaves.
    ///         Folds adjacent pairs `parent = sha256(left || right)` until one node remains. Mutates
    ///         `chunks` in place; callers pass a fresh array.
    function merkleize(bytes32[] memory chunks) internal pure returns (bytes32) {
        uint256 n = chunks.length;
        if (n == 0 || (n & (n - 1)) != 0) revert ChunksNotPowerOfTwo();
        while (n > 1) {
            uint256 half = n >> 1;
            for (uint256 i = 0; i < half; i++) {
                chunks[i] = sha256(abi.encodePacked(chunks[2 * i], chunks[2 * i + 1]));
            }
            n = half;
        }
        return chunks[0];
    }

    /// @dev SSZ leaf for a 48-byte BLS pubkey: `sha256(pubkey || 16 zero bytes)` (padded to 64).
    function _pubkeyHash64(bytes memory pubkey48) private pure returns (bytes32) {
        if (pubkey48.length != BLS_PUBKEY_LENGTH) revert InvalidPubkeyLength();
        return sha256(abi.encodePacked(pubkey48, bytes16(0)));
    }

    /// @dev SSZ uint64 → little-endian bytes, zero-padded to 32 bytes.
    function _uint64ToLE32(uint64 v) private pure returns (bytes32) {
        bytes memory b = new bytes(32);
        for (uint256 i = 0; i < 8; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
        bytes32 result;
        assembly {
            result := mload(add(b, 32))
        }
        return result;
    }

    /// @dev Merkleize exactly 8 chunks (power-of-two = 8; final tree has 4+2+1 = 7 internal nodes).
    function _merkleize8(bytes32[8] memory chunks) private pure returns (bytes32) {
        // Level 1: 4 nodes from pairs of chunks
        bytes32 n00 = sha256(abi.encodePacked(chunks[0], chunks[1]));
        bytes32 n01 = sha256(abi.encodePacked(chunks[2], chunks[3]));
        bytes32 n10 = sha256(abi.encodePacked(chunks[4], chunks[5]));
        bytes32 n11 = sha256(abi.encodePacked(chunks[6], chunks[7]));
        // Level 2: 2 nodes
        bytes32 m0 = sha256(abi.encodePacked(n00, n01));
        bytes32 m1 = sha256(abi.encodePacked(n10, n11));
        // Level 3: root
        return sha256(abi.encodePacked(m0, m1));
    }

    // ── Generalized indices (Capella) ────────────────────────────────────────

    /// @notice Generalized index of `execution_payload` inside `BeaconBlockBody` (Capella).
    ///         Depth = 4, position = 9 → gindex = 2^4 + 9 = 25.
    uint256 internal constant GINDEX_EXECUTION_PAYLOAD_IN_BODY = 25;

    /// @notice Generalized index of `block_hash` inside `ExecutionPayloadHeader` (Capella).
    ///         Depth = 4, position = 12 → gindex = 2^4 + 12 = 28.
    ///         `block_hash` = EVM block hash = keccak256(RLP(evm_header)).
    uint256 internal constant GINDEX_BLOCK_HASH_IN_EXECUTION_PAYLOAD = 28;

    /// @notice Generalized index of `execution_payload.state_root` relative to `BeaconBlockBody`
    ///         (Deneb/Electra): body field 9 (gindex 25) composed with ExecutionPayloadHeader field 2
    ///         (gindex 34) ⇒ 25*32 + 2 = 802, i.e. depth 9, leaf index 290.
    uint256 internal constant GINDEX_EXECUTION_STATE_ROOT_IN_BODY = 802;

    /// @notice Generalized index of `next_sync_committee` relative to `BeaconState` (Electra):
    ///         state field 23 of 37 padded to 64 ⇒ gindex 87, depth 6, leaf index 23.
    uint256 internal constant GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE = 87;
}
