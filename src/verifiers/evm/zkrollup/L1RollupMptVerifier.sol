// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {L1RollupVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/L1RollupVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {L1RollupStateRoot} from "@hiero-ledger/clpr/libraries/proof/zkrollup/L1RollupStateRoot.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title L1RollupMptVerifier
/// @notice {L1RollupVerifierBase} for rollups whose L2 state is Ethereum's Merkle-Patricia trie
///         (keccak256, RLP accounts `[nonce, balance, storageRoot, codeHash]`): Scroll since its Euclid
///         upgrade and Morph. The L2 proofs are plain `eth_getProof` output.
///
/// L2 proof items:
///   - `l2AccountProof`: list of MPT nodes for the ClprService account.
///   - `l2StorageProof` / `manifestStorageProof`: `[[slot, proofNodes], …]` (5 or 6 channel entries;
///     1 manifest entry). Absent slots are MPT exclusion proofs and read as zero.
contract L1RollupMptVerifier is L1RollupVerifierBase {
    constructor(IEthL1StateVerifier l1StateVerifier, L1RollupStateRoot.Profile memory profile_)
        L1RollupVerifierBase(l1StateVerifier, profile_)
    {}

    function _l2ServiceStorageRoot(Memory.Slice accountProof, bytes32 l2StateRoot, address service, bytes32 codeHash)
        internal
        pure
        override
        returns (bytes32)
    {
        return _verifyServiceStorageRoot(accountProof, l2StateRoot, service, codeHash);
    }

    function _l2ProveSlots(Memory.Slice storageProof, bytes32 storageRoot)
        internal
        pure
        override
        returns (bytes32[] memory slots, bytes32[] memory values)
    {
        Memory.Slice[] memory entries = RLP.readList(storageProof);
        slots = new bytes32[](entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            Memory.Slice[] memory entry = RLP.readList(entries[i]);
            if (entry.length != 2) revert ClprEvmStateProof.InvalidStorageEntry();
            slots[i] = RLP.readBytes32(entry[0]);
        }
        values = ClprEvmStateProof.verifyProvenSlots(entries, storageRoot, slots);
    }
}
