// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title EthL1StateVerifier
/// @notice Deployed, stateless wrapper around {EthBeaconLightClient}: sync-committee BLS over the
///         attested beacon header → SSZ branch to the execution `state_root` → optional committee
///         rotation. It is the L1 half shared by every verifier of a chain that settles on Ethereum
///         (see {OpStackVerifierBase}); keeping it in its own contract keeps those verifiers under
///         EIP-170 (the BLS/SSZ code is ~10 KB).
/// @dev The beacon layout (generalized indices, branch depths, slots per period) is constructor data,
///      not code, so a later fork that moves a field needs a new deployment with new data only
///      (clpr-spec ADR 2026-10-01, layout descriptor format 1). For Electra/Fulu:
///      `(802, 9, 87, 6, 8192)`.
contract EthL1StateVerifier is IEthL1StateVerifier {
    uint256 internal constant LC_FIELDS = 7;
    uint256 internal constant LC_IDX_ATTESTED_HEADER = 0;
    uint256 internal constant LC_IDX_SYNC_AGGREGATE = 1;
    uint256 internal constant LC_IDX_EXECUTION_STATE_ROOT = 2;
    uint256 internal constant LC_IDX_EXECUTION_BRANCH = 3;
    uint256 internal constant LC_IDX_NEXT_COMMITTEE = 4;
    uint256 internal constant LC_IDX_NEXT_COMMITTEE_BRANCH = 5;
    uint256 internal constant LC_IDX_NON_SIGNER_PROOFS = 6;

    uint256 internal constant CONFIG_FIELDS = 6;
    uint256 internal constant CONFIG_IDX_SLOT = 0;
    uint256 internal constant CONFIG_IDX_COMMITTEE = 1;
    uint256 internal constant CONFIG_IDX_GVR = 2;
    uint256 internal constant CONFIG_IDX_FORK_VERSION = 3;
    uint256 internal constant CONFIG_IDX_LEDGER = 4;
    uint256 internal constant CONFIG_IDX_CODE_HASH = 5;

    /// @dev Generalized index of `execution_payload.state_root` in `BeaconBlockBody`.
    uint256 public immutable EXECUTION_STATE_ROOT_GINDEX;
    uint256 public immutable EXECUTION_BRANCH_DEPTH;
    /// @dev Generalized index of `next_sync_committee` in `BeaconState`.
    uint256 public immutable NEXT_SYNC_COMMITTEE_GINDEX;
    uint256 public immutable NEXT_SYNC_COMMITTEE_DEPTH;
    uint64 public immutable SLOTS_PER_SYNC_COMMITTEE_PERIOD;

    error InvalidTrustAnchor();
    error InvalidLightClientProof();
    error InvalidConfigPayload();
    error InvalidBeaconLayout();

    constructor(
        uint256 executionStateRootGindex,
        uint256 executionBranchDepth,
        uint256 nextSyncCommitteeGindex,
        uint256 nextSyncCommitteeDepth,
        uint64 slotsPerSyncCommitteePeriod
    ) {
        // A generalized index of depth d lies in [2^d, 2^(d+1)).
        if (
            executionStateRootGindex >> executionBranchDepth != 1
                || nextSyncCommitteeGindex >> nextSyncCommitteeDepth != 1 || slotsPerSyncCommitteePeriod == 0
        ) revert InvalidBeaconLayout();
        EXECUTION_STATE_ROOT_GINDEX = executionStateRootGindex;
        EXECUTION_BRANCH_DEPTH = executionBranchDepth;
        NEXT_SYNC_COMMITTEE_GINDEX = nextSyncCommitteeGindex;
        NEXT_SYNC_COMMITTEE_DEPTH = nextSyncCommitteeDepth;
        SLOTS_PER_SYNC_COMMITTEE_PERIOD = slotsPerSyncCommitteePeriod;
    }

    /// @inheritdoc IEthL1StateVerifier
    function verifyL1State(bytes calldata lightClientProof, bytes calldata trustAnchor)
        external
        view
        returns (bytes32 executionStateRoot, uint64 slot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes32 gvr = bytes32(trustAnchor[EthBeaconLightClient.ANCHOR_OFF_GVR:EthBeaconLightClient.ANCHOR_OFF_GVR + 32]);
        bytes memory forkVersion = trustAnchor[
            EthBeaconLightClient.ANCHOR_OFF_FORK_VERSION:
                EthBeaconLightClient.ANCHOR_OFF_FORK_VERSION + EthBeaconLightClient.FORK_VERSION_LENGTH
        ];

        bytes memory proofMem = lightClientProof;
        Memory.Slice[] memory lc = RLP.decodeList(proofMem);
        if (lc.length != LC_FIELDS) revert InvalidLightClientProof();

        // Attested header → SSZ root → 2/3 sync-committee BLS under the anchor's committee.
        EthBeaconLightClient.BeaconHeader memory header =
            EthBeaconLightClient.decodeBeaconHeader(lc[LC_IDX_ATTESTED_HEADER]);
        (bytes memory bits, bytes memory signature) =
            EthBeaconLightClient.decodeSyncAggregate(lc[LC_IDX_SYNC_AGGREGATE]);
        EthBeaconLightClient.verifySyncCommitteeSignature(
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_COMMITTEE_ROOT:EthBeaconLightClient.ANCHOR_OFF_COMMITTEE_ROOT
                            + 32
                ]
            ),
            trustAnchor[EthBeaconLightClient.ANCHOR_OFF_AGGREGATE:EthBeaconLightClient.ANCHOR_OFF_AGGREGATE
                        + EthBeaconLightClient.BLS_PUBKEY_LENGTH
            ],
            lc[LC_IDX_NON_SIGNER_PROOFS],
            signature,
            bits,
            EthBeaconLightClient.headerRoot(header),
            forkVersion,
            gvr
        );

        // Execution state root → attested bodyRoot.
        executionStateRoot = EthBeaconLightClient.verifyExecutionStateRoot(
            lc[LC_IDX_EXECUTION_STATE_ROOT],
            lc[LC_IDX_EXECUTION_BRANCH],
            header.bodyRoot,
            EXECUTION_STATE_ROOT_GINDEX,
            EXECUTION_BRANCH_DEPTH
        );
        slot = header.slot;

        // Optional rotation: the successor keeps the channel binding and the pinned code hash.
        newTrustAnchor = EthBeaconLightClient.verifyRotation(
            lc[LC_IDX_NEXT_COMMITTEE],
            lc[LC_IDX_NEXT_COMMITTEE_BRANCH],
            header.stateRoot,
            gvr,
            forkVersion,
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID:EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID + 32]
            ),
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CODE_HASH:EthBeaconLightClient.ANCHOR_OFF_CODE_HASH + 32]
            ),
            NEXT_SYNC_COMMITTEE_GINDEX,
            NEXT_SYNC_COMMITTEE_DEPTH
        );
        if (newTrustAnchor.length != 0) {
            newTrustAnchorId = EthBeaconLightClient.periodId(header.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1);
        }
    }

    /// @inheritdoc IEthL1StateVerifier
    function genesisTrustAnchor(bytes calldata configProof, bytes32 channelId)
        external
        view
        returns (bytes memory trustAnchor, bytes memory trustAnchorId, bytes memory ledgerConfiguration)
    {
        bytes memory configMem = configProof;
        Memory.Slice[] memory cfg = RLP.decodeList(configMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidConfigPayload();

        (bytes[] memory pubkeys, bytes memory aggregatePubkey) =
            EthBeaconLightClient.decodeCommittee(cfg[CONFIG_IDX_COMMITTEE], EthBeaconLightClient.BLS_PUBKEY_LENGTH);
        ClprBeaconBls.requireOnCurveG1(pubkeys, aggregatePubkey);
        bytes memory forkVersion = RLP.readBytes(cfg[CONFIG_IDX_FORK_VERSION]);
        if (forkVersion.length != EthBeaconLightClient.FORK_VERSION_LENGTH) revert InvalidConfigPayload();

        trustAnchor = EthBeaconLightClient.encodeTrustAnchor(
            pubkeys,
            aggregatePubkey,
            RLP.readBytes32(cfg[CONFIG_IDX_GVR]),
            forkVersion,
            channelId,
            RLP.readBytes32(cfg[CONFIG_IDX_CODE_HASH])
        );
        // forge-lint: disable-next-line(unsafe-typecast)
        trustAnchorId = EthBeaconLightClient.periodId(
            uint64(RLP.readUint256(cfg[CONFIG_IDX_SLOT])) / SLOTS_PER_SYNC_COMMITTEE_PERIOD
        );
        ledgerConfiguration = RLP.readBytes(cfg[CONFIG_IDX_LEDGER]);
    }
}
