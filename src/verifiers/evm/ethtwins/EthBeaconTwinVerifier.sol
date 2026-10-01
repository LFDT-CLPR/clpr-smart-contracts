// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";

/// @title EthBeaconTwinVerifier
/// @notice {EthMainnetVerifier} for a beacon chain DERIVED from Ethereum's consensus specs (Gnosis
///         Chain, Chiado, PulseChain, PulseChain testnet v4). Same sync-committee light client, same
///         BLS (EIP-2537), SSZ and MPT logic; only the chain parameters differ, and they are fixed
///         per deployment:
///         - `genesisValidatorsRoot` + `forkVersion`: the sync-committee signing domain. Pinned so a
///           channel cannot be configured with another chain's identity (verifyConfig reverts).
///         - `slotsPerSyncCommitteePeriod` (SLOTS_PER_EPOCH × EPOCHS_PER_SYNC_COMMITTEE_PERIOD): the
///           trust-anchor period id.
///         - the SSZ generalized indices of `execution_payload.state_root` in `BeaconBlockBody` and
///           of `next_sync_committee` in `BeaconState`, which depend on the chain's active fork
///           (Capella: 402 / 55, Deneb: 802 / 55, Electra and Fulu: 802 / 87). Branch depths are
///           derived (floor(log2(gindex))).
///         Presets with the values recorded from each chain's live beacon API are in
///         {EthTwinPresets}. A hard fork that changes the fork version or either gindex needs a new
///         deployment (see README).
contract EthBeaconTwinVerifier is EthMainnetVerifier {
    struct ChainParams {
        bytes32 genesisValidatorsRoot;
        bytes4 forkVersion;
        uint64 slotsPerSyncCommitteePeriod;
        uint64 executionStateRootGindex;
        uint64 nextSyncCommitteeGindex;
    }

    error InvalidChainParams();
    /// @dev The config payload names a different chain (genesis validators root or fork version).
    error ChainIdentityMismatch(bytes32 gvr, bytes4 forkVersion);

    bytes32 public immutable GENESIS_VALIDATORS_ROOT;
    bytes4 public immutable FORK_VERSION;
    uint64 public immutable SLOTS_PER_PERIOD;
    uint64 public immutable EXECUTION_STATE_ROOT_GINDEX;
    uint64 public immutable NEXT_SYNC_COMMITTEE_GINDEX;
    uint256 private immutable EXECUTION_DEPTH;
    uint256 private immutable NEXT_COMMITTEE_DEPTH;

    constructor(ChainParams memory p) {
        if (
            p.genesisValidatorsRoot == bytes32(0) || p.slotsPerSyncCommitteePeriod == 0
                || p.executionStateRootGindex < 2 || p.nextSyncCommitteeGindex < 2
        ) revert InvalidChainParams();
        GENESIS_VALIDATORS_ROOT = p.genesisValidatorsRoot;
        FORK_VERSION = p.forkVersion;
        SLOTS_PER_PERIOD = p.slotsPerSyncCommitteePeriod;
        EXECUTION_STATE_ROOT_GINDEX = p.executionStateRootGindex;
        NEXT_SYNC_COMMITTEE_GINDEX = p.nextSyncCommitteeGindex;
        EXECUTION_DEPTH = _log2(p.executionStateRootGindex);
        NEXT_COMMITTEE_DEPTH = _log2(p.nextSyncCommitteeGindex);
    }

    function _executionStateRootGindex() internal view override returns (uint256, uint256) {
        return (EXECUTION_STATE_ROOT_GINDEX, EXECUTION_DEPTH);
    }

    function _nextSyncCommitteeGindex() internal view override returns (uint256, uint256) {
        return (NEXT_SYNC_COMMITTEE_GINDEX, NEXT_COMMITTEE_DEPTH);
    }

    function _slotsPerSyncCommitteePeriod() internal view override returns (uint64) {
        return SLOTS_PER_PERIOD;
    }

    function _checkChainIdentity(bytes32 gvr, bytes4 forkVersion) internal view override {
        if (gvr != GENESIS_VALIDATORS_ROOT || forkVersion != FORK_VERSION) {
            revert ChainIdentityMismatch(gvr, forkVersion);
        }
    }

    function _log2(uint256 x) private pure returns (uint256 r) {
        while (x > 1) {
            x >>= 1;
            r++;
        }
    }
}
