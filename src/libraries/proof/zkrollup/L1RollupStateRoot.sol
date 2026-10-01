// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title L1RollupStateRoot
/// @notice Reads a rollup's finalized L2 state root out of its Ethereum (L1) contract's storage, given an
///         authenticated L1 execution `state_root`.
///
/// Every rollup in this family keeps its finalized L2 state roots in a `mapping(uint256 => bytes32)` on
/// its L1 rollup contract, written only when a batch or block range is finalized:
///
/// | rollup | contract (proxy)                         | mapping                                   | key            |
/// |--------|------------------------------------------|-------------------------------------------|----------------|
/// | Linea  | LineaRollup  0xd19d4B5d…1B0876F, slot 282 | `stateRootHashes` (written by finalizeBlocks after the PLONK proof) | L2 block number |
/// | Scroll | ScrollChain  0xa13BAF47…6DAc1E556, slot 158 | `finalizedStateRoots` (written after the zk proof)      | batch index    |
/// | Morph  | Rollup       0x759894Ce…D02E3CeF60, slot 160 | `finalizedStateRoots` (written by finalizeBatch after the challenge window, or after a zk proof) | batch index |
///
/// A zero value means "not finalized" (the contracts never store a zero root). The proof also pins the
/// proxy's EIP-1967 implementation slot to the implementation the profile was checked against, so an
/// upgrade of the rollup contract stops the verifier instead of silently changing what "finalized" means.
///
/// Proof item (RLP list): `[key, l1AccountProof, l1StorageProof]`
///   - `key`: the mapping key (uint).
///   - `l1AccountProof`: MPT nodes of the rollup proxy's account against the L1 state root.
///   - `l1StorageProof`: `[[slot, proofNodes], …]` entries (as `eth_getProof`), covering
///     `keccak256(key ‖ stateRootsSlot)` and, when an implementation is pinned, the EIP-1967 slot. The
///     verifier derives both slots itself; the entries' declared slots only select the proof.
library L1RollupStateRoot {
    /// @dev `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
    bytes32 internal constant EIP1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint256 internal constant ROLLUP_PROOF_FIELDS = 3;

    /// @notice Per-rollup deployment data (immutables of the verifier).
    struct Profile {
        /// The L1 rollup contract (the proxy address users and provers call).
        address rollup;
        /// Storage slot of the `mapping(uint256 => bytes32)` of finalized L2 state roots.
        uint256 stateRootsSlot;
        /// Expected EIP-1967 implementation of `rollup`; zero disables the check.
        address implementation;
        /// Smallest accepted key: the first block/batch whose root uses the L2 state format this
        /// deployment proves (earlier roots belong to an older trie format).
        uint256 minKey;
    }

    error InvalidRollupProof();
    error KeyBelowMinimum(uint256 key, uint256 minKey);
    error StateRootNotFinalized(uint256 key);
    error ImplementationMismatch(address expected, address actual);

    /// @notice The storage slot holding the root for `key`.
    function stateRootSlot(uint256 stateRootsSlot, uint256 key) internal pure returns (bytes32) {
        // forge-lint: disable-next-line(asm-keccak256)
        return keccak256(abi.encode(key, stateRootsSlot));
    }

    /// @notice Verify `rollupProof` against `l1StateRoot` and return the finalized L2 state root.
    function verify(Profile memory p, Memory.Slice rollupProof, bytes32 l1StateRoot)
        internal
        pure
        returns (uint256 key, bytes32 l2StateRoot)
    {
        Memory.Slice[] memory items = RLP.readList(rollupProof);
        if (items.length != ROLLUP_PROOF_FIELDS) revert InvalidRollupProof();
        key = RLP.readUint256(items[0]);
        if (key < p.minKey) revert KeyBelowMinimum(key, p.minKey);

        bytes memory accountRlp = ClprEvmStateProof.verifyAccount(items[1], l1StateRoot, p.rollup);
        (bytes32 storageRoot,) = ClprEvmStateProof.decodeAccount(accountRlp);

        bool pinned = p.implementation != address(0);
        bytes32[] memory slots = new bytes32[](pinned ? 2 : 1);
        slots[0] = stateRootSlot(p.stateRootsSlot, key);
        if (pinned) slots[1] = EIP1967_IMPLEMENTATION_SLOT;
        bytes32[] memory values = ClprEvmStateProof.verifyProvenSlots(RLP.readList(items[2]), storageRoot, slots);

        l2StateRoot = values[0];
        if (l2StateRoot == bytes32(0)) revert StateRootNotFinalized(key);
        if (pinned) {
            address actual = address(uint160(uint256(values[1])));
            if (actual != p.implementation) revert ImplementationMismatch(p.implementation, actual);
        }
    }
}
