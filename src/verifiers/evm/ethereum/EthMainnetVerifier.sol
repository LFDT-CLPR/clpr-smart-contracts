// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title EthMainnetVerifier
/// @notice Verifies CLPR bundle proofs anchored to Ethereum mainnet via the consensus-layer light
///         client protocol (sync committees + BLS aggregate signatures).
///
/// ## Trust anchor (flat packed, 228 bytes)
/// `gvr32 ‖ forkVersion4 ‖ channelId32 ‖ aggregatePubkey128 ‖ committeeMerkleRoot32`.
/// The 512 committee keys are NOT stored — the anchor commits to them with a keccak Merkle root
/// ({ClprCommitteeMerkle}); per bundle the relay supplies only the NON-signers' keys (item 9),
/// each authenticated against that root. Only a rotation bundle carries the *next* committee,
/// whose root becomes the successor anchor. `channelId` (seeded in `verifyConfig`, carried
/// through every rotation) binds the storage proof to a single CLPR channel so proven slots
/// cannot be substituted positionally.
///
/// ## Bundle proof (top-level RLP list, 10 items)
/// ```
/// [ 0: attestedHeader        [slot, proposerIndex, parentRoot, stateRoot, bodyRoot]
///   1: syncAggregate         [bits(64), signature(256, uncompressed EIP-2537 G2)]
///   2: executionStateRoot32  the execution-layer state root (leaf proven into bodyRoot)
///   3: executionBranch       9 SSZ siblings (execution_payload.state_root, gindex 802)
///   4: nextCommittee         rotation committee `[uncompressed pubkeys512, aggregate]` (128-byte
///                            EIP-2537 keys), or empty (RLP string) if absent. The contract re-derives
///                            the beacon-native compressed form on-chain (`compressG1`, the cheap
///                            direction) to reconstruct the SSZ root the `nextCommitteeBranch` proof
///                            commits to; the successor anchor stores the keccak Merkle root over
///                            the uncompressed keys.
///   5: nextCommitteeBranch   6 SSZ siblings (gindex 87), or empty (RLP list) if absent
///   6: accountProof          MPT account proof against executionStateRoot32
///   7: storageProof          5 or 6 × [slotNumber, proofNodes] for the channelId-derived slots
///   8: bundleContent         protobuf ClprBundleContent
///   9: nonSignerProofs       one `key128 ‖ proof288` entry per clear participation bit, ascending
///                            index order (empty list at full participation) ]
/// ```
///
/// @dev Verification chain: sync-committee BLS over the attested header's signing root → SSZ branch
///      proving the execution state root sits in the header bodyRoot → MPT account proof (codeHash
///      pinned by config) → MPT storage proof of the queue-metadata slots → optional SSZ
///      next-sync-committee rotation against the header stateRoot.
/// @dev The light-client steps (header, BLS, SSZ execution branch, rotation, anchor encoding) live in
///      {EthBeaconLightClient}, shared with the OP Stack verifier family.
/// @dev BLS: the 2/3 supermajority + real on-chain BLS12-381 aggregate verification (EIP-2537 G1MSM
///      complement aggregation + RFC-9380 hash-to-G2 + pairing) is `ClprBeaconBls.aggregateVerifyComplement`.
/// @dev Account proof, queue-metadata decode and the `ClprBundleContent` decode are inherited from
///      {ClprEvmBundleVerifier}.
contract EthMainnetVerifier is ClprEvmBundleVerifier {
    // ── Bundle payload RLP layout (10 items) ─────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 10;
    uint256 internal constant IDX_ATTESTED_HEADER = 0;
    uint256 internal constant IDX_SYNC_AGGREGATE = 1;
    uint256 internal constant IDX_EXECUTION_STATE_ROOT = 2;
    uint256 internal constant IDX_EXECUTION_BRANCH = 3;
    uint256 internal constant IDX_NEXT_COMMITTEE = 4;
    uint256 internal constant IDX_NEXT_COMMITTEE_BRANCH = 5;
    uint256 internal constant IDX_ACCOUNT_PROOF = 6;
    uint256 internal constant IDX_STORAGE_PROOF = 7;
    uint256 internal constant IDX_BUNDLE_CONTENT = 8;
    /// @dev RLP list with ONE entry per clear bit in the participation bitvector, ascending index
    ///      order; each entry is `uncompressedKey(128) ‖ 9 Merkle siblings (288)` = 416 bytes,
    ///      authenticated against the anchor's committee Merkle root. Empty list at 512/512.
    uint256 internal constant IDX_NON_SIGNER_PROOFS = 9;
    /// @dev Optional endpoint-manifest update: storage proof of the commitment slot (index 10) plus the
    ///      manifest protobuf preimage (index 11). Present only in the 12-field shape.
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 10;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 11;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 12;

    // ── Trust anchor layout / sizes (single source of truth: {EthBeaconLightClient}) ──
    // Trust anchor: FLAT packed layout (fixed offsets — no RLP). channelId binds the storage proof
    // to a single CLPR channel (seeded in verifyConfig, carried through rotation).
    //   [0..32)     gvr (genesis validators root)
    //   [32..36)    forkVersion (4 bytes)
    //   [36..68)    channelId
    //   [68..196)   aggregate pubkey (128-byte uncompressed EIP-2537 G1)
    //   [196..228)  committee Merkle root (keccak, see ClprCommitteeMerkle)
    //   [228..260)  pinned code hash of the peer CLPR service
    // The 512 keys themselves are NOT stored: the anchor commits to them via the Merkle root, and
    // the relay supplies only the NON-signers' keys per bundle (payload item 9), each authenticated
    // against the root. 260 bytes ⇒ the service's per-bundle anchor SLOAD and per-rotation SSTORE
    // shrink from ~2,055 slots to 8.
    uint256 internal constant ANCHOR_OFF_GVR = EthBeaconLightClient.ANCHOR_OFF_GVR;
    uint256 internal constant ANCHOR_OFF_FORK_VERSION = EthBeaconLightClient.ANCHOR_OFF_FORK_VERSION;
    uint256 internal constant ANCHOR_OFF_CHANNEL_ID = EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID;
    uint256 internal constant ANCHOR_OFF_AGGREGATE = EthBeaconLightClient.ANCHOR_OFF_AGGREGATE;
    uint256 internal constant ANCHOR_OFF_COMMITTEE_ROOT = EthBeaconLightClient.ANCHOR_OFF_COMMITTEE_ROOT;
    uint256 internal constant ANCHOR_OFF_CODE_HASH = EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
    uint256 internal constant TRUST_ANCHOR_LENGTH = EthBeaconLightClient.TRUST_ANCHOR_LENGTH; // 260
    uint256 internal constant CONFIG_FIELDS = 6;

    uint256 internal constant BLS_PUBKEY_LENGTH = EthBeaconLightClient.BLS_PUBKEY_LENGTH;
    uint256 internal constant FORK_VERSION_LENGTH = EthBeaconLightClient.FORK_VERSION_LENGTH;

    // ── Beacon layout (Electra/Fulu). Passed to {EthBeaconLightClient} as data. ──
    uint256 internal constant EXECUTION_BRANCH_DEPTH = 9;
    uint256 internal constant NEXT_COMMITTEE_BRANCH_DEPTH = 6;

    // Mainnet preset: SLOTS_PER_EPOCH(32) × EPOCHS_PER_SYNC_COMMITTEE_PERIOD(256). A committee is
    // valid for one such period; `slot / this` is the period the trust-anchor id names.
    uint64 internal constant SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192;

    // Config payload RLP: [slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash].
    uint256 internal constant CONFIG_IDX_SLOT = 0;
    uint256 internal constant CONFIG_IDX_COMMITTEE = 1;
    uint256 internal constant CONFIG_IDX_GVR = 2;
    uint256 internal constant CONFIG_IDX_FORK_VERSION = 3;
    uint256 internal constant CONFIG_IDX_LEDGER = 4;
    uint256 internal constant CONFIG_IDX_CODE_HASH = 5;

    // Config-time endpoint-manifest proof RLP (verifyConfig's 3rd arg, when non-empty). A beacon
    // light-client proof signed by the CONFIG committee that authenticates the CLPR service's
    // execution storage root, then a manifest-commitment (slot 18) storage proof + preimage:
    //   [attestedHeader, syncAggregate, nonSignerProofs, executionStateRoot, executionBranch,
    //    accountProof, manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 8;
    uint256 internal constant CM_IDX_ATTESTED_HEADER = 0;
    uint256 internal constant CM_IDX_SYNC_AGGREGATE = 1;
    uint256 internal constant CM_IDX_NON_SIGNER_PROOFS = 2;
    uint256 internal constant CM_IDX_EXECUTION_STATE_ROOT = 3;
    uint256 internal constant CM_IDX_EXECUTION_BRANCH = 4;
    uint256 internal constant CM_IDX_ACCOUNT_PROOF = 5;
    uint256 internal constant CM_IDX_MANIFEST_STORAGE_PROOF = 6;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 7;

    // ── Errors (the light-client errors live in {EthBeaconLightClient}) ─────
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidConfigPayload();

    /// @inheritdoc IClprVerifier
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        // Step 1 — trust anchor (flat packed layout; scalar fields at fixed calldata offsets, the
        // committee is a 32-byte Merkle commitment — the keys themselves never touch storage).
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes32 gvr = bytes32(trustAnchor[ANCHOR_OFF_GVR:ANCHOR_OFF_GVR + 32]);
        bytes memory forkVersion = trustAnchor[ANCHOR_OFF_FORK_VERSION:ANCHOR_OFF_FORK_VERSION + FORK_VERSION_LENGTH];
        bytes32 channelId = bytes32(trustAnchor[ANCHOR_OFF_CHANNEL_ID:ANCHOR_OFF_CHANNEL_ID + 32]);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // Step 2 — attested beacon header → SSZ hash_tree_root.
        EthBeaconLightClient.BeaconHeader memory header =
            EthBeaconLightClient.decodeBeaconHeader(payload[IDX_ATTESTED_HEADER]);
        bytes32 beaconBlockRoot = EthBeaconLightClient.headerRoot(header);

        // Step 3 — supermajority + BLS aggregate signature.
        (bytes memory bits, bytes memory signature) =
            EthBeaconLightClient.decodeSyncAggregate(payload[IDX_SYNC_AGGREGATE]);
        _verifyBls(trustAnchor, payload[IDX_NON_SIGNER_PROOFS], signature, bits, beaconBlockRoot, forkVersion, gvr);

        // Step 4 — execution state root SSZ branch against the attested bodyRoot.
        bytes32 executionStateRoot = EthBeaconLightClient.verifyExecutionStateRoot(
            payload[IDX_EXECUTION_STATE_ROOT],
            payload[IDX_EXECUTION_BRANCH],
            header.bodyRoot,
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            EXECUTION_BRANCH_DEPTH
        );

        // Step 5 — MPT account proof against the proven execution state root.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        address clprService = _toAddress(ctx.remoteServiceAddress);
        bytes32 expectedCodeHash = bytes32(trustAnchor[ANCHOR_OFF_CODE_HASH:ANCHOR_OFF_CODE_HASH + 32]);
        bytes32 storageRoot =
            _verifyServiceStorageRoot(payload[IDX_ACCOUNT_PROOF], executionStateRoot, clprService, expectedCodeHash);

        // Step 6 — MPT storage proof of the queue-metadata slots, bound to channelId (the proven
        // values are tied to this channel's Channel struct, never taken positionally).
        metadata = _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, channelId);

        // Bundle content → message payloads.
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        // Optional endpoint-manifest update (12-field shape): prove the manifest-commitment slot against
        // the same execution storage root and bind the supplied preimage; absent (version 0) otherwise.
        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            newEndpointManifest = _verifyEndpointManifest(
                payload[IDX_MANIFEST_STORAGE_PROOF],
                storageRoot,
                RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]),
                ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }

        // Step 7 — optional next-sync-committee rotation against the attested header stateRoot.
        newTrustAnchor = _verifyRotation(
            payload[IDX_NEXT_COMMITTEE],
            payload[IDX_NEXT_COMMITTEE_BRANCH],
            header.stateRoot,
            gvr,
            forkVersion,
            channelId,
            expectedCodeHash
        );
        // Identifier for the successor anchor: the sync-committee period the next committee is valid
        // for, i.e. period(attested slot) + 1 (the next committee always belongs to the next period).
        // Empty when no rotation occurred.
        newTrustAnchorId = newTrustAnchor.length == 0
            ? newTrustAnchor
            : EthBeaconLightClient.periodId(header.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is RLP `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`.
    ///      The full committee can only be carried in the payload (it cannot be a constructor
    ///      immutable), so the empty-input bootstrap returns defaults with no genesis anchor.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        virtual
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();

        bytes memory configMem = configProofBytes;
        Memory.Slice[] memory cfg = RLP.decodeList(configMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidConfigPayload();

        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 slot = uint64(RLP.readUint256(cfg[CONFIG_IDX_SLOT]));
        (bytes[] memory pubkeys, bytes memory aggregatePubkey) =
            EthBeaconLightClient.decodeCommittee(cfg[CONFIG_IDX_COMMITTEE], BLS_PUBKEY_LENGTH);
        ClprBeaconBls.requireOnCurveG1(pubkeys, aggregatePubkey);
        bytes32 gvr = RLP.readBytes32(cfg[CONFIG_IDX_GVR]);
        bytes memory forkVersion = RLP.readBytes(cfg[CONFIG_IDX_FORK_VERSION]);
        if (forkVersion.length != FORK_VERSION_LENGTH) revert InvalidConfigPayload();

        ClprTypes.LedgerConfiguration memory lc =
        ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[CONFIG_IDX_LEDGER])).config;

        bytes32 codeHash = RLP.readBytes32(cfg[CONFIG_IDX_CODE_HASH]);
        initialTrustAnchor = _encodeTrustAnchor(pubkeys, aggregatePubkey, gvr, forkVersion, channelId, codeHash);
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            initialTrustAnchor,
            // The genesis committee is the current committee for the config slot's period.
            EthBeaconLightClient.periodId(slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD),
            // Verify the endpoint-manifest storage proof (when supplied) against a beacon proof signed
            // by this config committee; empty proof → empty manifest (bring-up).
            _verifyConfigEndpointManifest(
                endpointManifestProofBytes, pubkeys, aggregatePubkey, forkVersion, gvr, serviceAddress, codeHash
            )
        );
    }

    /// @dev Verify a config-time endpoint-manifest proof against the CONFIG committee. The proof is a
    ///      beacon light-client proof (attested header + sync-aggregate signed by the config committee)
    ///      that authenticates the CLPR service's execution storage root, followed by the
    ///      manifest-commitment (slot {ENDPOINT_MANIFEST_COMMITMENT_SLOT}) storage proof + preimage.
    ///      Mirrors {verifyBundle}'s beacon → execution-branch → MPT steps. An empty proof returns the
    ///      UNINITIALIZED (version 0) manifest for bring-up — the first manifest-carrying bundle then
    ///      populates the Channel via Step 1b (same as the other EVM verifiers).
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes memory forkVersion,
        bytes32 gvr,
        bytes memory serviceAddress,
        bytes32 codeHash
    ) private view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();
        // Only pay the 512-key Merkle root once the proof shape is known-good.
        bytes32 committeeRoot = ClprCommitteeMerkle.root(pubkeys);

        // Attested beacon header → SSZ root, then BLS supermajority against the config committee.
        EthBeaconLightClient.BeaconHeader memory header =
            EthBeaconLightClient.decodeBeaconHeader(p[CM_IDX_ATTESTED_HEADER]);
        bytes32 beaconBlockRoot = EthBeaconLightClient.headerRoot(header);
        (bytes memory bits, bytes memory signature) = EthBeaconLightClient.decodeSyncAggregate(p[CM_IDX_SYNC_AGGREGATE]);
        EthBeaconLightClient.verifySyncCommitteeSignature(
            committeeRoot,
            aggregatePubkey,
            p[CM_IDX_NON_SIGNER_PROOFS],
            signature,
            bits,
            beaconBlockRoot,
            forkVersion,
            gvr
        );

        // Execution state root SSZ branch against the attested bodyRoot.
        bytes32 executionStateRoot = EthBeaconLightClient.verifyExecutionStateRoot(
            p[CM_IDX_EXECUTION_STATE_ROOT],
            p[CM_IDX_EXECUTION_BRANCH],
            header.bodyRoot,
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            EXECUTION_BRANCH_DEPTH
        );

        // MPT account proof → storage root (anchored at the config-declared service address, with
        // the config's code hash), then the manifest-commitment slot proof + preimage bound to
        // that same service address.
        bytes32 storageRoot = _verifyServiceStorageRoot(
            p[CM_IDX_ACCOUNT_PROOF], executionStateRoot, _toAddress(serviceAddress), codeHash
        );
        return _verifyEndpointManifest(
            p[CM_IDX_MANIFEST_STORAGE_PROOF], storageRoot, RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal: thin adapters over {EthBeaconLightClient}
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Optional next-sync-committee rotation against the attested header stateRoot, at this
    ///      verifier's (Electra/Fulu) `next_sync_committee` gindex. See
    ///      {EthBeaconLightClient.verifyRotation}.
    function _verifyRotation(
        Memory.Slice nextCommitteeItem,
        Memory.Slice nextBranchItem,
        bytes32 stateRoot,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) internal view returns (bytes memory) {
        return EthBeaconLightClient.verifyRotation(
            nextCommitteeItem,
            nextBranchItem,
            stateRoot,
            gvr,
            forkVersion,
            channelId,
            codeHash,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            NEXT_COMMITTEE_BRANCH_DEPTH
        );
    }

    /// @dev Sync-committee BLS check with the committee taken from the flat calldata trust anchor
    ///      (committee Merkle root at `ANCHOR_OFF_COMMITTEE_ROOT`, aggregate at `ANCHOR_OFF_AGGREGATE`).
    ///      See {EthBeaconLightClient.verifySyncCommitteeSignature}.
    function _verifyBls(
        bytes calldata trustAnchor,
        Memory.Slice nonSignerItem,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 genesisValidatorsRoot
    ) internal view {
        EthBeaconLightClient.verifySyncCommitteeSignature(
            bytes32(trustAnchor[ANCHOR_OFF_COMMITTEE_ROOT:ANCHOR_OFF_COMMITTEE_ROOT + 32]),
            trustAnchor[ANCHOR_OFF_AGGREGATE:ANCHOR_OFF_AGGREGATE + BLS_PUBKEY_LENGTH],
            nonSignerItem,
            signature,
            bits,
            beaconBlockRoot,
            forkVersion,
            genesisValidatorsRoot
        );
    }

    /// @dev See {EthBeaconLightClient.encodeTrustAnchor}.
    function _encodeTrustAnchor(
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) internal pure returns (bytes memory) {
        return EthBeaconLightClient.encodeTrustAnchor(pubkeys, aggregatePubkey, gvr, forkVersion, channelId, codeHash);
    }
}
