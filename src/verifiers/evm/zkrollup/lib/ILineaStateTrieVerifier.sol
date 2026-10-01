// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ILineaStateTrieVerifier
/// @notice Stateless verifier of Linea state-trie proofs (Sparse Merkle Tree of depth 40 with sorted,
///         doubly linked leaves, hashed with Poseidon2 over KoalaBear). Used by {LineaRollupVerifier} for
///         the L2 half of a bundle; deployed separately to keep the verifier under EIP-170.
interface ILineaStateTrieVerifier {
    /// @notice A leaf as stored in the trie.
    /// @param index leaf position (< 2^40)
    /// @param prev padded index of the previous leaf in hKey order (2 words, see LineaPoseidon2 padding)
    /// @param next padded index of the next leaf in hKey order
    /// @param hKey Poseidon2 hash of the key
    /// @param hValue Poseidon2 hash of the value
    struct Leaf {
        uint256 index;
        uint256[2] prev;
        uint256[2] next;
        uint256 hKey;
        uint256 hValue;
    }

    /// @notice A Merkle multiproof of `leaves` (sorted by strictly increasing index) in one tree.
    /// @param nextFreeNode the tree's next free leaf index, padded (2 words); hashed into the root
    /// @param leaves the opened leaves
    /// @param siblings the sibling hashes not computable from `leaves`, in fold order (level by level
    ///        from the leaves up, left to right within a level)
    struct MultiProof {
        uint256[2] nextFreeNode;
        Leaf[] leaves;
        uint256[] siblings;
    }

    /// @notice A Linea account value (192 bytes in `linea_getProof`).
    struct Account {
        uint256 nonce;
        uint256 balance;
        uint256 storageRoot;
        uint256 snarkCodeHash;
        uint256 keccakCodeHash;
        uint256 codeSize;
    }

    /// @notice The claim for one storage slot: present with `value` (`leaf` is its leaf), or absent
    ///         (`leaf` and `right` are the two adjacent leaves around the slot's hKey).
    struct SlotClaim {
        uint256 slot;
        uint256 value;
        bool absent;
        uint256 leaf;
        uint256 right;
    }

    /// @notice Prove `account`'s value in the world-state trie rooted at `stateRoot`.
    /// @param proof `abi.encode(Account, MultiProof)` with exactly one leaf.
    /// @return storageRoot the account's storage-trie root
    /// @return keccakCodeHash the account's keccak256 code hash
    function verifyAccount(bytes calldata proof, bytes32 stateRoot, address account)
        external
        view
        returns (bytes32 storageRoot, bytes32 keccakCodeHash);

    /// @notice Prove every claimed slot in the storage trie rooted at `storageRoot` (one multiproof).
    /// @param proof `abi.encode(MultiProof, SlotClaim[])`.
    /// @return slots the claimed slots, in claim order
    /// @return values their proven values (zero for absent slots)
    function verifyStorage(bytes calldata proof, bytes32 storageRoot)
        external
        view
        returns (bytes32[] memory slots, bytes32[] memory values);
}
