// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {L1RollupStateRoot} from "@hiero-ledger/clpr/libraries/proof/zkrollup/L1RollupStateRoot.sol";

/// @title ZkRollupProfiles
/// @notice Ethereum-mainnet deployment profiles of the L1-settled rollup verifiers. Each value was read
///         from the verified implementation source and checked against mainnet storage on 2026-10-01
///         (docs/chains/<chain>.md lists the sources). A rollup upgrade changes `implementation` and
///         stops the verifier until a new profile is deployed.
library ZkRollupProfiles {
    /// @notice Linea (chain 59144): LineaRollup proxy, `stateRootHashes` (ZkEvmV2), key = L2 block number.
    function linea() internal pure returns (L1RollupStateRoot.Profile memory) {
        return L1RollupStateRoot.Profile({
            rollup: 0xd19d4B5d358258f05D7B411E21A1460D11B0876F,
            stateRootsSlot: 282,
            implementation: 0x052b73d934E9412045Bf731574463Fd026D74645,
            minKey: 0
        });
    }

    /// @notice Scroll (chain 534352): ScrollChain proxy, `finalizedStateRoots`, key = batch index.
    function scroll() internal pure returns (L1RollupStateRoot.Profile memory) {
        return L1RollupStateRoot.Profile({
            rollup: 0xa13BAF47339d63B743e7Da8741db5456DAc1E556,
            stateRootsSlot: 158,
            implementation: 0x0a20703878E68E587c59204cc0EA86098B8c3bA7,
            minKey: 0
        });
    }

    /// @notice Morph (chain 2818): Rollup proxy, `finalizedStateRoots`, key = batch index.
    function morph() internal pure returns (L1RollupStateRoot.Profile memory) {
        return L1RollupStateRoot.Profile({
            rollup: 0x759894Ced0e6af42c26668076Ffa84d02E3CeF60,
            stateRootsSlot: 160,
            implementation: 0x213CE22b487B71Ac68a1B5b12d2b93D1AF30Ea1d,
            minKey: 0
        });
    }
}
