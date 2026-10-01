// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {L1RollupVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/L1RollupVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ILineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/lib/ILineaStateTrieVerifier.sol";
import {L1RollupStateRoot} from "@hiero-ledger/clpr/libraries/proof/zkrollup/L1RollupStateRoot.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title LineaRollupVerifier
/// @notice {L1RollupVerifierBase} for Linea: the finalized root in `LineaRollup.stateRootHashes` is the
///         root of Linea's Poseidon2 sparse Merkle tree (not the MPT root in Linea block headers), so the
///         L2 proofs come from `linea_getProof` and are checked by {ILineaStateTrieVerifier}.
///
/// L2 proof items (RLP byte strings):
///   - `l2AccountProof`: `abi.encode(Account, MultiProof)` for the ClprService account.
///   - `l2StorageProof` / `manifestStorageProof`: `abi.encode(MultiProof, SlotClaim[])` (5 or 6 channel
///     claims; 1 manifest claim). All claimed slots are verified in one multiproof.
contract LineaRollupVerifier is L1RollupVerifierBase {
    /// @notice The Linea state-trie verifier (stateless).
    ILineaStateTrieVerifier public immutable LINEA_TRIE;

    constructor(
        IEthL1StateVerifier l1StateVerifier,
        L1RollupStateRoot.Profile memory profile_,
        ILineaStateTrieVerifier lineaTrie
    ) L1RollupVerifierBase(l1StateVerifier, profile_) {
        if (address(lineaTrie) == address(0)) revert InvalidDeployment();
        LINEA_TRIE = lineaTrie;
    }

    function _l2ServiceStorageRoot(Memory.Slice accountProof, bytes32 l2StateRoot, address service, bytes32 codeHash)
        internal
        view
        override
        returns (bytes32 storageRoot)
    {
        bytes32 keccakCodeHash;
        (storageRoot, keccakCodeHash) = LINEA_TRIE.verifyAccount(RLP.readBytes(accountProof), l2StateRoot, service);
        if (codeHash != bytes32(0) && keccakCodeHash != codeHash) revert CodeHashMismatch();
    }

    function _l2ProveSlots(Memory.Slice storageProof, bytes32 storageRoot)
        internal
        view
        override
        returns (bytes32[] memory, bytes32[] memory)
    {
        return LINEA_TRIE.verifyStorage(RLP.readBytes(storageProof), storageRoot);
    }
}
