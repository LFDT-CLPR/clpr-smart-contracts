// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IZkSyncStateTreeVerifier
/// @notice Stateless verifier of storage proofs against a ZKsync Era (EraVM) state-tree root, as returned by
///         `zks_getProof`. The tree is ZKsync's sparse Merkle tree of depth 256 hashed with Blake2s-256.
/// @dev Entry encoding (`proof`, entries back to back, one per requested key, in request order):
///      ```
///      value      32 bytes   the slot value (zero for an absent slot)
///      leafIndex   8 bytes   big-endian enumeration index of the leaf (0 for an absent slot)
///      pathLen     2 bytes   big-endian number of siblings, ≤ 256; or 0xffff (RECORDED)
///      path       32 × pathLen  sibling hashes ROOT-TO-LEAF (zks_getProof order), each in W-form
///      ```
///      A RECORDED entry carries no siblings: its value must match the one {recordStorage} stored for
///      (root, account, key).
///      The siblings for the `256 − pathLen` levels nearest the leaf are empty-subtree hashes and are not
///      sent. W-form: the hash with every 4-byte group byte-reversed (its eight little-endian Blake2s
///      message words, packed big-endian). The relayer converts; the verifier never needs to.
interface IZkSyncStateTreeVerifier {
    error AccountsKeysLengthMismatch();
    error MalformedStorageProof();
    error NonZeroValueWithoutLeafIndex(uint256 entry);
    error StorageProofRootMismatch(uint256 entry);
    error EntryNotRecorded(uint256 entry);

    /// @notice An entry was proven by {recordStorage}; later proofs may reference it with `pathLen = 0xffff`.
    event StorageRecorded(bytes32 indexed root, address indexed account, bytes32 indexed key, bytes32 value);

    /// @notice Verify one tree entry per `(accounts[i], keys[i])` under `root` and return the proven values.
    ///         Reverts unless every entry folds to `root`.
    /// @param root the state-tree root (`StoredBatchInfo.batchHash` of an executed batch), as bytes.
    function verifyStorage(bytes32 root, address[] calldata accounts, bytes32[] calldata keys, bytes calldata proof)
        external
        view
        returns (bytes32[] memory values);

    /// @notice Verify like {verifyStorage} and record every (root, account, key) → value, so that later
    ///         proofs can mark those entries RECORDED (`pathLen = 0xffff`).
    function recordStorage(bytes32 root, address[] calldata accounts, bytes32[] calldata keys, bytes calldata proof)
        external
        returns (bytes32[] memory values);

    /// @notice keccak256 of the value recorded for (root, account, key), or zero.
    function recordedValueHash(bytes32 root, address account, bytes32 key) external view returns (bytes32);
}
