// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {Sha384} from "@hiero-ledger/clpr/libraries/crypto/Sha384.sol";

/// @title ClprMerkleProof
/// @notice SHA-384 binary merkle path walker for Hiero `MerklePath` proofs
///         (`block/stream/state_proof.proto`). Walks siblings bottom-to-top
///         with the `is_left` flag controlling combine order; leaf bytes get
///         a `0x00` domain-separation prefix, sibling steps a `0x02`, and
///         unary climb steps a `0x01`.
library ClprMerkleProof {
    /// @notice Content variant of a `MerklePath` — mirrors the proto's
    ///         `oneof content { hash, state_item_leaf, block_item_leaf,
    ///         timestamp_leaf }` discriminator
    ///         (`block/stream/state_proof.proto`), with an `Any` sentinel for
    ///         callers that match the first populated variant of any kind.
    enum LeafKind {
        Any,
        Hash, // proto field 3 — internal-node hash (e.g. prev-block-root spine)
        StateItemLeaf, // proto field 4 — `StateItem` leaf
        BlockItemLeaf, // proto field 5 — `BlockItem` leaf
        TimestampLeaf // proto field 6 — `proto.Timestamp` leaf
    }

    /// @notice The leaf path has no computable base hash (all content variants are empty).
    error MerkleProofNoBaseHash();
    /// @notice A cycle was detected while following `next_path_index` chain links.
    error MerkleProofChainCycle();
    /// @notice A `next_path_index` link points outside the `paths` array.
    error MerkleProofChainOutOfRange(uint256 index);
    /// @notice A non-leaf spine path unexpectedly carries leaf content.
    error MerkleProofChainHasContent(uint256 pathIndex);
    /// @notice A `MerklePath` populates more than one `content`
    error MerkleProofAmbiguousContent();
    /// @notice The requested `startIndex` is out of range for the given `paths` array.
    error MerkleProofStartIndexOutOfRange(uint256 startIndex);

    /// @dev Marker for "no further path in the chain" — equals
    ///      `MerklePath.next_path_index` when set to UINT32_MAX (the proto
    ///      comment's `-1` sentinel from `BlockStateProofGenerator.java:57`).
    uint32 internal constant TERMINATOR = type(uint32).max;

    /// @notice Walks a chained `MerklePath` proof starting at an explicit index.
    ///         Used when the caller has *already* picked which leaf-bearing path
    ///         to anchor on (e.g. iterating over every state-item leaf in a
    ///         bundle and checking each chain against a known block root).
    function computeChainedRoot(ClprStateProof.MerklePath[] memory paths, uint256 startIndex)
        internal
        pure
        returns (bytes memory)
    {
        if (startIndex >= paths.length) revert MerkleProofStartIndexOutOfRange(startIndex);
        bytes memory baseHash = _baseHashOf(paths[startIndex]);
        if (baseHash.length == 0) revert MerkleProofNoBaseHash();
        return _walkChain(paths, startIndex, baseHash);
    }

    /// @notice Returns the index of the first path in `paths` whose `content`
    ///         oneof matches `kind`, or `type(uint256).max` if none does.
    /// @dev    The proto documents `paths` as ordered
    ///         [prev-block-spine (Hash), consensus-timestamp (TimestampLeaf),
    ///          block-root spine (Hash), state-item leaves...]
    function findFirstPath(ClprStateProof.MerklePath[] memory paths, LeafKind kind) internal pure returns (uint256) {
        for (uint256 i = 0; i < paths.length; i++) {
            if (_pathMatches(paths[i], kind)) return i;
        }
        return type(uint256).max;
    }

    /// @dev Returns the merkle base hash implied by a path's content variants.
    ///      Empty bytes if none of the four content fields are populated.
    function _baseHashOf(ClprStateProof.MerklePath memory p) private pure returns (bytes memory) {
        uint256 variants;
        if (p.explicitHash.length != 0) variants++;
        if (p.stateItemLeaf.length != 0) variants++;
        if (p.blockItemLeaf.length != 0) variants++;
        if (p.timestampLeaf.length != 0) variants++;
        if (variants > 1) revert MerkleProofAmbiguousContent();
        if (variants == 0) return "";

        if (p.explicitHash.length != 0) return p.explicitHash;

        bytes memory leaf;
        if (p.stateItemLeaf.length != 0) leaf = p.stateItemLeaf;
        else if (p.blockItemLeaf.length != 0) leaf = p.blockItemLeaf;
        else leaf = p.timestampLeaf;

        return Sha384.hash(abi.encodePacked(bytes1(0x00), leaf));
    }

    /// @dev Predicate for `findFirstPath`: checks whether `p`'s populated
    ///      content variant matches `kind`. `LeafKind.Any` matches any
    ///      populated content variant.
    function _pathMatches(ClprStateProof.MerklePath memory p, LeafKind kind) private pure returns (bool) {
        if (kind == LeafKind.StateItemLeaf) return p.stateItemLeaf.length != 0;
        if (kind == LeafKind.BlockItemLeaf) return p.blockItemLeaf.length != 0;
        if (kind == LeafKind.TimestampLeaf) return p.timestampLeaf.length != 0;
        if (kind == LeafKind.Hash) return p.explicitHash.length != 0;
        return p.explicitHash.length != 0 || p.stateItemLeaf.length != 0 || p.blockItemLeaf.length != 0
            || p.timestampLeaf.length != 0;
    }

    /// @dev Shared walk: combine `baseHash` with `paths[startIndex].siblings`,
    ///      then follow `next_path_index` through intermediates (which must have
    ///      no content), combining siblings at each hop. Returns the accumulated
    ///      SHA-384 hash.
    function _walkChain(ClprStateProof.MerklePath[] memory paths, uint256 startIndex, bytes memory baseHash)
        private
        pure
        returns (bytes memory acc)
    {
        ClprStateProof.MerklePath memory cur = paths[startIndex];
        acc = computeRootOfSiblings(cur.siblings, baseHash);

        uint32 next = cur.nextPathIndex;
        uint256 hopGuard = 0;
        while (next != TERMINATOR) {
            if (++hopGuard > paths.length) revert MerkleProofChainCycle();
            if (uint256(next) >= paths.length) revert MerkleProofChainOutOfRange(next);

            cur = paths[uint256(next)];
            if (_baseHashOf(cur).length != 0) revert MerkleProofChainHasContent(next);
            acc = computeRootOfSiblings(cur.siblings, acc);
            next = cur.nextPathIndex;
        }
    }

    /// @notice Combine `startHash` with `siblings` bottom-to-top, producing the Merkle root.
    /// @dev Domain prefixes: `0x01` for a unary climb (empty sibling), `0x02` for a binary
    ///      combine. `isLeft` determines whether the sibling is prepended or appended.
    /// @param siblings Ordered sibling nodes from leaf to root.
    /// @param startHash SHA-384 hash of the leaf (or intermediate node) to start from.
    /// @return The computed Merkle root bytes (48 bytes, SHA-384).
    function computeRootOfSiblings(ClprStateProof.SiblingNode[] memory siblings, bytes memory startHash)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory computed = startHash;

        for (uint256 i = 0; i < siblings.length; i++) {
            bytes memory sib = siblings[i].hash;

            if (sib.length == 0) {
                computed = Sha384.hash(abi.encodePacked(bytes1(0x01), computed));
            } else if (siblings[i].isLeft) {
                computed = Sha384.hash(abi.encodePacked(bytes1(0x02), sib, computed));
            } else {
                computed = Sha384.hash(abi.encodePacked(bytes1(0x02), computed, sib));
            }
        }

        return computed;
    }
}
