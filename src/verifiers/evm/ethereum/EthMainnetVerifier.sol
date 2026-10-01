// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
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

    // ── Sub-field shapes / sizes ─────────────────────────────────────────────
    uint256 internal constant HEADER_FIELDS = 5;
    uint256 internal constant SYNC_AGGREGATE_FIELDS = 2;
    // Trust anchor: FLAT packed layout (fixed offsets — no RLP). channelId binds the storage proof
    // to a single CLPR channel (seeded in verifyConfig, carried through rotation).
    //   [0..32)     gvr (genesis validators root)
    //   [32..36)    forkVersion (4 bytes)
    //   [36..68)    channelId
    //   [68..196)   aggregate pubkey (128-byte uncompressed EIP-2537 G1)
    //   [196..228)  committee Merkle root (keccak, see ClprCommitteeMerkle)
    // The 512 keys themselves are NOT stored: the anchor commits to them via the Merkle root, and
    // the relay supplies only the NON-signers' keys per bundle (payload item 9), each authenticated
    // against the root. 228 bytes ⇒ the service's per-bundle anchor SLOAD and per-rotation SSTORE
    // shrink from ~2,055 slots to 8.
    uint256 internal constant ANCHOR_OFF_GVR = 0;
    uint256 internal constant ANCHOR_OFF_FORK_VERSION = 32;
    uint256 internal constant ANCHOR_OFF_CHANNEL_ID = 36;
    uint256 internal constant ANCHOR_OFF_AGGREGATE = 68;
    uint256 internal constant ANCHOR_OFF_COMMITTEE_ROOT = 196;
    uint256 internal constant ANCHOR_OFF_CODE_HASH = 228;
    uint256 internal constant CONFIG_FIELDS = 6;
    uint256 internal constant COMMITTEE_FIELDS = 2;

    // Single source of truth lives in the SSZ library (the beacon-protocol constant).
    uint256 internal constant SYNC_COMMITTEE_SIZE = ClprBeaconSsz.SYNC_COMMITTEE_SIZE;
    uint256 internal constant BLS_PUBKEY_LENGTH = 128; // uncompressed G1 (pad16||x||pad16||y)
    uint256 internal constant BLS_SIGNATURE_LENGTH = 256; // uncompressed G2
    uint256 internal constant SYNC_BITS_LENGTH = 64; // Bitvector[512] / 8
    uint256 internal constant FORK_VERSION_LENGTH = 4;
    uint256 internal constant TRUST_ANCHOR_LENGTH = ANCHOR_OFF_CODE_HASH + 32; // 260

    // Ethereum (Electra/Fulu) defaults for the chain-layout hooks below. Beacon chains derived from
    // Ethereum (Gnosis, PulseChain) override the hooks — see src/verifiers/evm/ethtwins/.
    uint256 internal constant EXECUTION_BRANCH_DEPTH = 9;
    uint256 internal constant NEXT_COMMITTEE_BRANCH_DEPTH = 6;

    // Mainnet preset: SLOTS_PER_EPOCH(32) × EPOCHS_PER_SYNC_COMMITTEE_PERIOD(256). A committee is
    // valid for one such period; `slot / this` is the period the trust-anchor id names.
    uint64 internal constant SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192;

    // Config payload RLP: [slot, syncCommittee, gvr, forkVersion, ledgerConfiguration].
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

    // RLP prefix bytes used to detect the optional rotation pair.
    uint8 internal constant RLP_EMPTY_STRING = 0x80;
    uint8 internal constant RLP_EMPTY_LIST = 0xc0;

    // Canonical RLP envelope of one non-signer entry: a 416-byte string is always prefixed
    // `0xb9 0x01a0` (long string, two length bytes). Checked in place so the payload can be
    // read as a slice — no per-entry RLP.readBytes copy.
    bytes3 internal constant ENTRY_RLP_PREFIX = 0xb901a0;
    uint256 internal constant ENTRY_RLP_PREFIX_LENGTH = 3;
    uint256 internal constant ENTRY_RLP_LENGTH = ENTRY_RLP_PREFIX_LENGTH + ClprCommitteeMerkle.ENTRY_LENGTH; // 419

    // ── Errors ───────────────────────────────────────────────────────────────
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidBeaconHeader();
    error InvalidSyncAggregate();
    error InvalidCommittee();
    error InvalidBranch();
    error InvalidConfigPayload();
    error ExecutionBranchInvalid();
    error NextCommitteeBranchInvalid();
    error RotationPairMismatch();
    /// @dev Participation is below the 2/3 supermajority required to trust the attested header.
    error InsufficientParticipation(uint256 participants, uint256 committeeSize);
    /// @dev Payload item 9 must carry exactly one entry per clear participation bit.
    error NonSignerProofCountMismatch(uint256 expected, uint256 got);
    /// @dev A non-signer entry failed Merkle authentication against the anchor's committee root.
    ///      MANDATORY security check: without it a relay could pass a forged point as a
    ///      "non-signer" and steer the complement aggregation to any key it controls.
    error NonSignerProofInvalid(uint256 index);

    struct BeaconHeader {
        uint64 slot;
        uint64 proposerIndex;
        bytes32 parentRoot;
        bytes32 stateRoot;
        bytes32 bodyRoot;
    }

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
        BeaconHeader memory header = _decodeBeaconHeader(payload[IDX_ATTESTED_HEADER]);
        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(
            header.slot, header.proposerIndex, header.parentRoot, header.stateRoot, header.bodyRoot
        );

        // Step 3 — supermajority + BLS aggregate signature (staged behind an overridable hook).
        Memory.Slice[] memory agg = RLP.readList(payload[IDX_SYNC_AGGREGATE]);
        if (agg.length != SYNC_AGGREGATE_FIELDS) revert InvalidSyncAggregate();
        bytes memory bits = RLP.readBytes(agg[0]);
        bytes memory signature = RLP.readBytes(agg[1]);
        if (bits.length != SYNC_BITS_LENGTH || signature.length != BLS_SIGNATURE_LENGTH) revert InvalidSyncAggregate();
        _verifyBls(trustAnchor, payload[IDX_NON_SIGNER_PROOFS], signature, bits, beaconBlockRoot, forkVersion, gvr);

        // Step 4 — execution state root SSZ branch against the attested bodyRoot.
        bytes32 executionStateRoot = RLP.readBytes32(payload[IDX_EXECUTION_STATE_ROOT]);
        (uint256 execGindex, uint256 execDepth) = _executionStateRootGindex();
        bytes32[] memory execBranch = _decodeBranch(payload[IDX_EXECUTION_BRANCH], execDepth);
        if (!ClprBeaconSsz.verifyProof(executionStateRoot, execBranch, header.bodyRoot, execGindex)) {
            revert ExecutionBranchInvalid();
        }

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
        newTrustAnchorId =
            newTrustAnchor.length == 0 ? newTrustAnchor : _periodId(header.slot / _slotsPerSyncCommitteePeriod() + 1);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is RLP `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration]`.
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
        (bytes[] memory pubkeys, bytes memory aggregatePubkey) = _decodeCommittee(cfg[CONFIG_IDX_COMMITTEE]);
        ClprBeaconBls.requireOnCurveG1(pubkeys, aggregatePubkey);
        bytes32 gvr = RLP.readBytes32(cfg[CONFIG_IDX_GVR]);
        bytes memory forkVersion = RLP.readBytes(cfg[CONFIG_IDX_FORK_VERSION]);
        if (forkVersion.length != FORK_VERSION_LENGTH) revert InvalidConfigPayload();
        _checkChainIdentity(gvr, _toBytes4(forkVersion));

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
            _periodId(slot / _slotsPerSyncCommitteePeriod()),
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
        BeaconHeader memory header = _decodeBeaconHeader(p[CM_IDX_ATTESTED_HEADER]);
        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(
            header.slot, header.proposerIndex, header.parentRoot, header.stateRoot, header.bodyRoot
        );
        Memory.Slice[] memory agg = RLP.readList(p[CM_IDX_SYNC_AGGREGATE]);
        if (agg.length != SYNC_AGGREGATE_FIELDS) revert InvalidSyncAggregate();
        bytes memory bits = RLP.readBytes(agg[0]);
        bytes memory signature = RLP.readBytes(agg[1]);
        if (bits.length != SYNC_BITS_LENGTH || signature.length != BLS_SIGNATURE_LENGTH) revert InvalidSyncAggregate();
        _verifyBlsCore(
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
        bytes32 executionStateRoot = RLP.readBytes32(p[CM_IDX_EXECUTION_STATE_ROOT]);
        (uint256 execGindex, uint256 execDepth) = _executionStateRootGindex();
        bytes32[] memory execBranch = _decodeBranch(p[CM_IDX_EXECUTION_BRANCH], execDepth);
        if (!ClprBeaconSsz.verifyProof(executionStateRoot, execBranch, header.bodyRoot, execGindex)) {
            revert ExecutionBranchInvalid();
        }

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
    //   Chain-layout hooks (Ethereum defaults; overridden by Ethereum-derived beacon chains)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Generalized index (and branch depth = floor(log2(gindex))) of
    ///      `execution_payload.state_root` inside `BeaconBlockBody`. Ethereum Deneb → Fulu: 802 / 9.
    function _executionStateRootGindex() internal view virtual returns (uint256 gindex, uint256 depth) {
        return (ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY, EXECUTION_BRANCH_DEPTH);
    }

    /// @dev Generalized index (and branch depth) of `next_sync_committee` inside `BeaconState`.
    ///      Ethereum Electra/Fulu: 87 / 6.
    function _nextSyncCommitteeGindex() internal view virtual returns (uint256 gindex, uint256 depth) {
        return (ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE, NEXT_COMMITTEE_BRANCH_DEPTH);
    }

    /// @dev `SLOTS_PER_EPOCH × EPOCHS_PER_SYNC_COMMITTEE_PERIOD` (names the trust-anchor period id).
    function _slotsPerSyncCommitteePeriod() internal view virtual returns (uint64) {
        return SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    }

    /// @dev Config-time check of the claimed chain identity (signing-domain inputs). The Ethereum
    ///      verifier accepts any (it serves mainnet and its testnets); a chain-pinned deployment
    ///      reverts on a foreign genesis validators root or fork version.
    function _checkChainIdentity(bytes32 gvr, bytes4 forkVersion) internal view virtual {}

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal: rotation
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Verifies the optional next-sync-committee rotation. The pair is both-present or
    ///      both-absent: an absent committee is an empty RLP string, an absent branch an empty RLP
    ///      list (matching the reference encoder).
    ///
    ///      The beacon `SyncCommittee` (and therefore the `next_sync_committee` Merkle proof) commits to
    ///      *compressed* 48-byte pubkeys, but on-chain BLS verification wants *uncompressed* keys and
    ///      on-chain decompression is gas-infeasible. So the relayer ships only the UNCOMPRESSED next
    ///      committee `[pubkeys[512], aggregate]` and:
    ///        1. the SSZ committee root is reconstructed from the derived compressed keys (each
    ///           `compressG1(uncompressed[i])` — the cheap on-chain direction) and proven against the
    ///           attested header stateRoot. This authenticates the uncompressed keys in one pass:
    ///           `compressG1` is injective on valid points, so only the real committee can reproduce the
    ///           beacon-committed root (fail-closed — a wrong key just fails the branch check);
    ///        2. the successor anchor stores those uncompressed keys, so future bundles verify BLS with
    ///           no decompression.
    ///        3. All of the pubkeys & aggregate are on the curve.
    ///      (Earlier the relayer also shipped the compressed committee and a separate compress-and-compare
    ///       bind; that was redundant — dropping it removes ~25 KB of calldata + the bind loop.)
    function _verifyRotation(
        Memory.Slice nextCommitteeItem,
        Memory.Slice nextBranchItem,
        bytes32 stateRoot,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) internal view returns (bytes memory newTrustAnchor) {
        bool committeeAbsent = _firstByte(nextCommitteeItem) == RLP_EMPTY_STRING;
        bool branchAbsent = _firstByte(nextBranchItem) == RLP_EMPTY_LIST;
        if (committeeAbsent != branchAbsent) revert RotationPairMismatch();
        if (committeeAbsent) return new bytes(0);

        (bytes[] memory nextPubkeys, bytes memory nextAggregate) = _decodeCommittee(nextCommitteeItem);

        ClprBeaconBls.requireOnCurveG1(nextPubkeys, nextAggregate);

        // Reconstruct the beacon-committed SSZ root from the uncompressed keys (compressing each on the
        // fly) and prove it against the attested state — this authenticates the uncompressed keys.
        bytes32 committeeRoot = ClprBeaconSsz.syncCommitteeRootFromUncompressed(nextPubkeys, nextAggregate);
        (uint256 nextGindex, uint256 nextDepth) = _nextSyncCommitteeGindex();
        bytes32[] memory branch = _decodeBranch(nextBranchItem, nextDepth);
        if (!ClprBeaconSsz.verifyProof(committeeRoot, branch, stateRoot, nextGindex)) {
            revert NextCommitteeBranchInvalid();
        }
        // Successor anchor commits to the uncompressed keys via the keccak Merkle root (the keys
        // themselves are re-supplied per bundle for non-signers only, authenticated against it).
        newTrustAnchor = _encodeTrustAnchor(nextPubkeys, nextAggregate, gvr, forkVersion, channelId, codeHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal: supermajority + BLS aggregate signature
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Enforces the 2/3 supermajority (from the bitvector alone — cheap failures stay cheap),
    ///      collects the NON-signers' keys from payload item 9 authenticating each against the
    ///      anchor's committee Merkle root, derives the sync-committee signing root, and runs the
    ///      real on-chain BLS12-381 verification (`ClprBeaconBls.aggregateVerifyComplement`:
    ///      EIP-2537 G1MSM complement aggregation + RFC-9380 hash-to-G2 + pairing).
    ///      All points are EIP-2537 uncompressed.
    /// @param trustAnchor the flat packed trust anchor (length pre-checked): committee aggregate at
    ///        `ANCHOR_OFF_AGGREGATE`, committee Merkle root at `ANCHOR_OFF_COMMITTEE_ROOT`.
    /// @param nonSignerItem payload item 9: one `key ‖ proof` entry per clear bit, ascending order.
    ///        With full participation the item is an empty RLP list and no key material is needed —
    ///        the stored aggregate alone feeds the pairing.
    /// @param signature the 256-byte uncompressed EIP-2537 G2 aggregate signature.
    /// @param bits the 64-byte participation bitvector.
    /// @param beaconBlockRoot the attested header hash_tree_root.
    /// @param forkVersion the 4-byte fork version (for the signing domain).
    /// @param genesisValidatorsRoot the 32-byte genesis validators root (for the signing domain).
    function _verifyBls(
        bytes calldata trustAnchor,
        Memory.Slice nonSignerItem,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 genesisValidatorsRoot
    ) internal view {
        // Thin calldata wrapper over the memory-based core: extract committeeRoot + aggregate from the
        // flat trust anchor. The core is shared with verifyConfig's in-memory config committee.
        _verifyBlsCore(
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

    /// @dev Sync-committee BLS verification against an explicit (committeeRoot, aggregatePubkey). Callable
    ///      from the hot bundle path (calldata anchor, via {_verifyBls}) and from verifyConfig (config
    ///      committee held in memory). Enforces 2/3 supermajority on the bitvector, then
    ///      complement-aggregates the authenticated non-signers.
    function _verifyBlsCore(
        bytes32 committeeRoot,
        bytes memory aggregatePubkey,
        Memory.Slice nonSignerItem,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 genesisValidatorsRoot
    ) internal view {
        // 2/3 supermajority on the participant count, decided by the bitvector before touching any
        // key material (the bits are covered by the signature check that follows: flipping a bit
        // changes the participant set and the pairing fails).
        // bits.length == 64 (pre-checked by the caller), so the vector is exactly two words.
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := mload(add(bits, 32))
            w1 := mload(add(bits, 64))
        }
        uint256 participantCount = _popcount(w0) + _popcount(w1);
        uint256 nonSignerCount = SYNC_COMMITTEE_SIZE - participantCount;
        if (3 * participantCount < 2 * SYNC_COMMITTEE_SIZE) {
            revert InsufficientParticipation(participantCount, SYNC_COMMITTEE_SIZE);
        }

        bytes[] memory nonParticipants = _collectNonSigners(nonSignerItem, bits, nonSignerCount, committeeRoot);

        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(_toBytes4(forkVersion), genesisValidatorsRoot);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);
        // Participant aggregate = committee aggregate − Σ(non-participants); at the 2/3 supermajority that
        // subtracts ≤ 1/3 of the committee instead of aggregating the ≥ 2/3 that signed.
        ClprBeaconBls.aggregateVerifyComplement(aggregatePubkey, nonParticipants, signature, signingRoot);
    }

    /// @dev Collect the NON-signers' uncompressed keys from payload item 9. The i-th entry is bound
    ///      to the i-th CLEAR bit of the `Bitvector[512]` (bit `i` is bit `i % 8` of byte `i / 8`,
    ///      LSB-first): its Merkle fold runs along that committee index, so only the key the beacon
    ///      committed at that exact position can reproduce `committeeRoot`. This authentication is
    ///      load-bearing — see {NonSignerProofInvalid}.
    function _collectNonSigners(
        Memory.Slice nonSignerItem,
        bytes memory bits,
        uint256 nonSignerCount,
        bytes32 committeeRoot
    ) private pure returns (bytes[] memory nonParticipants) {
        Memory.Slice[] memory entries = RLP.readList(nonSignerItem);
        if (entries.length != nonSignerCount) revert NonSignerProofCountMismatch(nonSignerCount, entries.length);

        nonParticipants = new bytes[](nonSignerCount);
        uint256 j;
        for (uint256 byteIdx = 0; byteIdx < SYNC_BITS_LENGTH && j < nonSignerCount; byteIdx++) {
            uint256 b = uint8(bits[byteIdx]);
            if (b == 0xFF) continue; // all eight participants signed
            for (uint256 bit = 0; bit < 8; bit++) {
                if ((b >> bit) & 1 == 0) {
                    uint256 index = (byteIdx << 3) | bit;
                    Memory.Slice item = entries[j];
                    if (Memory.length(item) != ENTRY_RLP_LENGTH || bytes3(Memory.load(item, 0)) != ENTRY_RLP_PREFIX) {
                        revert NonSignerProofInvalid(index);
                    }
                    (bool ok, bytes memory key) = ClprCommitteeMerkle.verifyAndExtractKey(
                        Memory.slice(item, ENTRY_RLP_PREFIX_LENGTH), index, committeeRoot
                    );
                    if (!ok) revert NonSignerProofInvalid(index);
                    nonParticipants[j++] = key;
                }
            }
        }
    }

    /// @dev Number of set bits in a 256-bit word (SWAR fold).
    function _popcount(uint256 x) private pure returns (uint256) {
        unchecked {
            x -= (x >> 1) & 0x5555555555555555555555555555555555555555555555555555555555555555;
            x = (x & 0x3333333333333333333333333333333333333333333333333333333333333333)
                + ((x >> 2) & 0x3333333333333333333333333333333333333333333333333333333333333333);
            x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F;
            // Fold bytes into 16-bit lanes (each ≤ 16) so the lane-sum below (≤ 256) cannot carry.
            x = (x + (x >> 8)) & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF;
            return (x * 0x0001000100010001000100010001000100010001000100010001000100010001) >> 240;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal: decoders
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Decode an `[pubkeys[512], aggregate]` committee whose keys are uncompressed (128-byte).
    function _decodeCommittee(Memory.Slice committeeItem)
        internal
        pure
        returns (bytes[] memory pubkeys, bytes memory aggregatePubkey)
    {
        return _decodeCommitteeWithLen(committeeItem, BLS_PUBKEY_LENGTH);
    }

    /// @dev Decode an `[pubkeys[512], aggregate]` committee enforcing a fixed per-key byte length
    ///      (128 uncompressed, or 48 compressed for the beacon-native rotation committee).
    function _decodeCommitteeWithLen(Memory.Slice committeeItem, uint256 pubkeyLen)
        internal
        pure
        returns (bytes[] memory pubkeys, bytes memory aggregatePubkey)
    {
        Memory.Slice[] memory committee = RLP.readList(committeeItem);
        if (committee.length != COMMITTEE_FIELDS) revert InvalidCommittee();

        Memory.Slice[] memory pubkeyItems = RLP.readList(committee[0]);
        if (pubkeyItems.length != SYNC_COMMITTEE_SIZE) revert InvalidCommittee();
        pubkeys = new bytes[](SYNC_COMMITTEE_SIZE);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            pubkeys[i] = RLP.readBytes(pubkeyItems[i]);
            if (pubkeys[i].length != pubkeyLen) revert InvalidCommittee();
        }
        aggregatePubkey = RLP.readBytes(committee[1]);
        if (aggregatePubkey.length != pubkeyLen) revert InvalidCommittee();
    }

    function _decodeBeaconHeader(Memory.Slice headerItem) internal pure returns (BeaconHeader memory header) {
        Memory.Slice[] memory fields = RLP.readList(headerItem);
        if (fields.length != HEADER_FIELDS) revert InvalidBeaconHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        header.slot = uint64(RLP.readUint256(fields[0]));
        // forge-lint: disable-next-line(unsafe-typecast)
        header.proposerIndex = uint64(RLP.readUint256(fields[1]));
        header.parentRoot = RLP.readBytes32(fields[2]);
        header.stateRoot = RLP.readBytes32(fields[3]);
        header.bodyRoot = RLP.readBytes32(fields[4]);
    }

    function _decodeBranch(Memory.Slice branchItem, uint256 expectedDepth)
        internal
        pure
        returns (bytes32[] memory branch)
    {
        Memory.Slice[] memory items = RLP.readList(branchItem);
        if (items.length != expectedDepth) revert InvalidBranch();
        branch = new bytes32[](expectedDepth);
        for (uint256 i = 0; i < expectedDepth; i++) {
            branch[i] = RLP.readBytes32(items[i]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal: trust-anchor encoding + small helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Build the flat packed trust anchor (see the layout constants):
    ///      `gvr ‖ forkVersion ‖ channelId ‖ aggregate ‖ committeeMerkleRoot ‖ codeHash` — 260 bytes.
    ///      The keys are committed via `ClprCommitteeMerkle.root` (1,023 keccaks, once per
    ///      rotation/genesis), never stored. The Java implementation mirrors this byte-for-byte.
    function _encodeTrustAnchor(
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) internal pure returns (bytes memory anchor) {
        // Lengths are enforced upstream (_decodeCommittee / verifyConfig): 512 keys × 128 bytes,
        // 128-byte aggregate, 4-byte forkVersion.
        bytes32 committeeRoot = ClprCommitteeMerkle.root(pubkeys);
        anchor = new bytes(TRUST_ANCHOR_LENGTH);
        uint256 keyLen = BLS_PUBKEY_LENGTH; // inline assembly only accepts direct number constants
        assembly ("memory-safe") {
            let dst := add(anchor, 32)
            mstore(add(dst, ANCHOR_OFF_GVR), gvr)
            mcopy(add(dst, ANCHOR_OFF_FORK_VERSION), add(forkVersion, 32), FORK_VERSION_LENGTH)
            mstore(add(dst, ANCHOR_OFF_CHANNEL_ID), channelId)
            mcopy(add(dst, ANCHOR_OFF_AGGREGATE), add(aggregatePubkey, 32), keyLen)
            mstore(add(dst, ANCHOR_OFF_COMMITTEE_ROOT), committeeRoot)
            mstore(add(dst, ANCHOR_OFF_CODE_HASH), codeHash)
        }
    }

    /// @dev First RLP prefix byte of an item — used to distinguish an empty string (0x80) from an
    ///      empty list (0xc0) for the optional rotation pair.
    function _firstByte(Memory.Slice item) private pure returns (uint8) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(bytes1(Memory.load(item, 0)));
    }

    /// @dev Encode a sync-committee period as the trust-anchor identifier (`Channel.trustAnchorId`):
    ///      the protocol-native, monotonic handle for "which committee", rather than an opaque hash of
    ///      the ~66 KB anchor. 8-byte big-endian; never empty for a real period, so the interface
    ///      invariant "id non-empty iff anchor non-empty" holds at every call site (anchor present ⇒
    ///      a period is encoded; absent ⇒ caller passes through the empty anchor).
    function _periodId(uint64 period) private pure returns (bytes memory) {
        return abi.encodePacked(period);
    }
}
