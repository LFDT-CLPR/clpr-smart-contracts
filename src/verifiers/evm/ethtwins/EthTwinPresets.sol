// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthBeaconTwinVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethtwins/EthBeaconTwinVerifier.sol";

/// @title EthTwinPresets
/// @notice {EthBeaconTwinVerifier} parameters per chain. Every value was read from the chain's
///         public beacon API on 2026-10-01 (`/eth/v1/beacon/genesis`, `/eth/v1/config/spec`,
///         `/eth/v1/config/fork_schedule`); the gindices were checked against live data: Gnosis and
///         Chiado through their light-client proofs (Fulu), PulseChain by re-merkleizing a full
///         Capella `BeaconState` and `BeaconBlockBody` to the roots in the signed header.
library EthTwinPresets {
    // Ethereum-family SSZ layouts.
    uint64 internal constant CAPELLA_EXECUTION_STATE_ROOT_GINDEX = 402; // body field 9 (25) · 16 + payload field 2
    uint64 internal constant CAPELLA_NEXT_SYNC_COMMITTEE_GINDEX = 55; // state field 23 of 28 → 32 leaves
    uint64 internal constant ELECTRA_EXECUTION_STATE_ROOT_GINDEX = 802; // 25 · 32 + 2 (17-field payload)
    uint64 internal constant ELECTRA_NEXT_SYNC_COMMITTEE_GINDEX = 87; // state field 23 of 37/38 → 64 leaves

    /// Gnosis Chain: SLOTS_PER_EPOCH 16 × EPOCHS_PER_SYNC_COMMITTEE_PERIOD 512, 5 s slots, Fulu (epoch 1714688).
    function gnosis() internal pure returns (EthBeaconTwinVerifier.ChainParams memory) {
        return EthBeaconTwinVerifier.ChainParams({
            genesisValidatorsRoot: 0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47,
            forkVersion: 0x06000064,
            slotsPerSyncCommitteePeriod: 16 * 512,
            executionStateRootGindex: ELECTRA_EXECUTION_STATE_ROOT_GINDEX,
            nextSyncCommitteeGindex: ELECTRA_NEXT_SYNC_COMMITTEE_GINDEX
        });
    }

    /// Gnosis Chiado testnet: same preset as Gnosis, Fulu (epoch 1353216).
    function chiado() internal pure returns (EthBeaconTwinVerifier.ChainParams memory) {
        return EthBeaconTwinVerifier.ChainParams({
            genesisValidatorsRoot: 0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e,
            forkVersion: 0x0600006f,
            slotsPerSyncCommitteePeriod: 16 * 512,
            executionStateRootGindex: ELECTRA_EXECUTION_STATE_ROOT_GINDEX,
            nextSyncCommitteeGindex: ELECTRA_NEXT_SYNC_COMMITTEE_GINDEX
        });
    }

    /// PulseChain mainnet (chain 369): SLOTS_PER_EPOCH 32 × 256, 10 s slots, Capella since epoch 3,
    /// no Deneb scheduled.
    function pulsechain() internal pure returns (EthBeaconTwinVerifier.ChainParams memory) {
        return EthBeaconTwinVerifier.ChainParams({
            genesisValidatorsRoot: 0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90,
            forkVersion: 0x0000036c,
            slotsPerSyncCommitteePeriod: 32 * 256,
            executionStateRootGindex: CAPELLA_EXECUTION_STATE_ROOT_GINDEX,
            nextSyncCommitteeGindex: CAPELLA_NEXT_SYNC_COMMITTEE_GINDEX
        });
    }

    /// PulseChain testnet v4 (chain 943): as mainnet, Capella since epoch 4200.
    function pulsechainTestnetV4() internal pure returns (EthBeaconTwinVerifier.ChainParams memory) {
        return EthBeaconTwinVerifier.ChainParams({
            genesisValidatorsRoot: 0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64,
            forkVersion: 0x00000946,
            slotsPerSyncCommitteePeriod: 32 * 256,
            executionStateRootGindex: CAPELLA_EXECUTION_STATE_ROOT_GINDEX,
            nextSyncCommitteeGindex: CAPELLA_NEXT_SYNC_COMMITTEE_GINDEX
        });
    }
}
