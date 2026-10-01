// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {GrandpaCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaCommitAccumulator.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";

/// @title GrandpaPalletVerifier
/// @notice "Substrate solo chain → Hiero" verifier for a chain without an EVM, where the CLPR
///         Service is a native pallet. GRANDPA finality comes from {GrandpaLightClient}; the queue
///         state is read from the pallet's own storage in the Substrate state trie. Built for
///         Chainflip (Aura + GRANDPA, 139 authorities): a commit there needs about 92 ed25519
///         signatures (~54M gas), so a step may leave `votes` empty and rely on the signed weight
///         that {GrandpaCommitAccumulator} recorded for that exact commit over several transactions.
///         See README.md in this directory.
///
/// ## Pallet storage layout (proposed `pallet-clpr`; pallet name is a profile parameter)
///   Queues:  StorageMap<_, Blake2_128Concat, H256 (channel id), QueueRecord>
///            key   = twox128(pallet) ‖ twox128("Queues") ‖ blake2_128(channelId) ‖ channelId (80 B)
///            value = SCALE QueueRecord, 89 B:
///                    status u8 ‖ next_message_id u64 ‖ received_message_id u64 ‖
///                    endpoint_manifest_version u64 ‖ sent_running_hash [u8; 32] ‖
///                    received_running_hash [u8; 32]                       (integers little-endian)
///            An absent key reads as an empty (PENDING, zero) queue.
///   Service: StorageValue<_, ServiceRecord>
///            key   = twox128(pallet) ‖ twox128("Service")                              (32 B)
///            value = SCALE ServiceRecord, 80 B:
///                    service_address AccountId32 ‖ manifest_commitment [u8; 32] ‖ config_nanos u128
///            `manifest_commitment` = keccak256(ClprProtobuf.encodeEndpointManifest(manifest)), zero
///            when unset; `config_nanos` = the LedgerConfiguration timestamp the pallet publishes.
contract GrandpaPalletVerifier is ClprEvmBundleVerifier, GrandpaLightClient {
    struct BundleProof {
        Step[] steps;
        bytes[] stateProof;
        bytes bundleContent;
        bytes manifestPreimage;
    }

    struct ConfigProof {
        Step[] steps;
        bytes[] stateProof;
        bytes ledgerConfig;
    }

    /// @dev Finality steps plus a state proof, for {verifyStorageEntry}.
    struct EntryProof {
        Step[] steps;
        bytes[] stateProof;
    }

    /// @dev twox128("Queues").
    bytes16 internal constant QUEUES_PREFIX = 0xb5cd230cad01da4acb0378dad6ed82e9;
    /// @dev twox128("Service").
    bytes16 internal constant SERVICE_PREFIX = 0x221b4c4483eae1aedca119452a71c709;
    uint256 internal constant QUEUE_RECORD_LENGTH = 89;
    uint256 internal constant SERVICE_RECORD_LENGTH = 80;
    uint256 internal constant SERVICE_ADDRESS_LENGTH = 32;

    /// @notice twox128 of the CLPR pallet's name in the runtime.
    bytes16 public immutable PALLET_PREFIX;
    /// @notice keccak256 of the CAIP-2 chain id the peer service must report.
    bytes32 public immutable CHAIN_ID_HASH;
    /// @notice Optional accumulator for steps whose votes were verified in earlier transactions.
    GrandpaCommitAccumulator public immutable ACCUMULATOR;

    error InvalidQueueRecord();
    error InvalidServiceRecord();
    error ServiceRecordMissing();
    error ChainIdMismatch();
    error ServiceAddressMismatch();
    error ConfigNanosMismatch();
    error AccumulatorNotConfigured();

    /// @param ed25519Verifier          Pure-Solidity Ed25519 verifier.
    /// @param accumulator              GrandpaCommitAccumulator, or address(0) to require inline votes.
    /// @param palletPrefix             twox128 of the CLPR pallet name.
    /// @param chainId                  CAIP-2 id the peer service reports (e.g. "polkadot:<genesis prefix>").
    /// @param bootstrapSetId           Weak-subjectivity checkpoint: GRANDPA set id …
    /// @param bootstrapAuthoritiesHash … keccak256 of its packed authority list …
    /// @param bootstrapMinHeight       … and the first block number it justifies.
    constructor(
        address ed25519Verifier,
        address accumulator,
        bytes16 palletPrefix,
        string memory chainId,
        uint64 bootstrapSetId,
        bytes32 bootstrapAuthoritiesHash,
        uint32 bootstrapMinHeight
    ) GrandpaLightClient(ed25519Verifier, bootstrapSetId, bootstrapAuthoritiesHash, bootstrapMinHeight) {
        if (palletPrefix == bytes16(0) || bytes(chainId).length == 0) revert InvalidProfile();
        ACCUMULATOR = GrandpaCommitAccumulator(accumulator);
        PALLET_PREFIX = palletPrefix;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
    }

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof); trustAnchor = 44-byte anchor (GrandpaLightClient).
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
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (proofBytes.length == 0) revert InvalidPayloadShape();
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (Anchor memory next, bytes32 stateRoot,) = _applySteps(p.steps, anchor);
        SubstrateTrie.Proof memory proof = SubstrateTrie.load(p.stateProof);
        (bool exists, bytes memory record) = SubstrateTrie.get(proof, stateRoot, queueKey(ctx.channelId));
        if (exists) metadata = _decodeQueueRecord(record);

        if (p.manifestPreimage.length > 0) {
            (bytes memory service, bytes32 commitment,) = _readService(proof, stateRoot);
            if (keccak256(service) != keccak256(ctx.remoteServiceAddress)) revert ServiceAddressMismatch();
            newEndpointManifest = _bindManifest(p.manifestPreimage, commitment, service);
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (next.setId != anchor.setId) {
            newTrustAnchor = _encodeAnchor(next);
            newTrustAnchorId = abi.encodePacked(next.setId);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), followed from the deploy-time bootstrap
    ///      checkpoint; endpointManifestProofBytes = the manifest preimage (or empty), bound to the
    ///      Service record at the same state root.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
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
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        (Anchor memory anchor, bytes32 stateRoot,) = _applySteps(p.steps, _bootstrapAnchor());

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(p.ledgerConfig).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert ChainIdMismatch();
        (bytes memory service, bytes32 commitment, uint256 nanos) =
            _readService(SubstrateTrie.load(p.stateProof), stateRoot);
        if (keccak256(service) != keccak256(lc.serviceAddress)) revert ServiceAddressMismatch();
        if (nanos != lc.nanosSinceEpoch) revert ConfigNanosMismatch();

        serviceAddress = service;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = _encodeAnchor(anchor);
        initialTrustAnchorId = abi.encodePacked(anchor.setId);
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _bindManifest(endpointManifestProofBytes, commitment, serviceAddress);
    }

    /// @notice Proves any raw storage key of the chain under GRANDPA finality: the value (or its
    ///         absence) at the state root of the last justified block. Lets a client read other
    ///         pallets' state through the same light client; the CLPR flows do not use it.
    /// @param proofBytes  abi.encode(EntryProof).
    /// @param trustAnchor 44-byte anchor, as for verifyBundle.
    /// @param key         Full storage key (e.g. twox128(pallet) ‖ twox128(item) ‖ hashed map key).
    /// @return exists     False when the proof shows the key is absent.
    /// @return value      The raw SCALE value.
    /// @return number     Number of the justified block whose state was read.
    function verifyStorageEntry(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata key)
        external
        view
        returns (bool exists, bytes memory value, uint32 number)
    {
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        if (proofBytes.length == 0) revert InvalidPayloadShape();
        EntryProof memory p = abi.decode(proofBytes, (EntryProof));
        bytes32 stateRoot;
        (, stateRoot, number) = _applySteps(p.steps, anchor);
        (exists, value) = SubstrateTrie.get(SubstrateTrie.load(p.stateProof), stateRoot, key);
    }

    // ── Storage keys ─────────────────────────────────────────────────────────

    /// @notice `Queues` key of `channelId` (Blake2_128Concat).
    function queueKey(bytes32 channelId) public view returns (bytes memory) {
        return abi.encodePacked(PALLET_PREFIX, QUEUES_PREFIX, Blake2b.hash128Word(channelId), channelId);
    }

    /// @notice `Service` key.
    function serviceKey() public view returns (bytes memory) {
        return abi.encodePacked(PALLET_PREFIX, SERVICE_PREFIX);
    }

    // ── Finality: inline votes or accumulated weight ─────────────────────────

    /// @dev Empty `votes` means the votes were verified by {ACCUMULATOR} for this exact commit
    ///      (set id, authority-list hash, round, target); its recorded weight must meet the threshold.
    function _checkCommit(GrandpaLib.Commit memory c, bytes memory authorities) internal view override {
        if (c.votes.length != 0) {
            GrandpaLib.verifyCommit(c, authorities, ED25519);
            return;
        }
        if (address(ACCUMULATOR) == address(0)) revert AccumulatorNotConfigured();
        uint256 need = GrandpaLib.threshold(GrandpaLib.totalWeight(authorities));
        uint256 signed = ACCUMULATOR.signedWeight(
            ACCUMULATOR.commitKey(
                c.setId, GrandpaLib.authoritiesHash(authorities), c.round, c.targetHash, c.targetNumber
            )
        );
        if (signed < need) revert GrandpaLib.GrandpaThresholdNotMet(signed, need);
    }

    // ── Records ──────────────────────────────────────────────────────────────

    function _decodeQueueRecord(bytes memory r) internal pure returns (ClprTypes.QueueMetadata memory m) {
        if (r.length != QUEUE_RECORD_LENGTH) revert InvalidQueueRecord();
        if (uint8(r[0]) > uint8(type(ClprTypes.ChannelStatus).max)) revert InvalidQueueRecord();
        m.state = ClprTypes.ChannelStatus(uint8(r[0]));
        m.nextMessageId = ScaleCodec.readU64(r, 1);
        m.receivedMessageId = ScaleCodec.readU64(r, 9);
        m.endpointManifestVersion = ScaleCodec.readU64(r, 17);
        m.sentRunningHash = ScaleCodec.readBytes32(r, 25);
        m.receivedRunningHash = ScaleCodec.readBytes32(r, 57);
    }

    /// @dev The Service record must exist: a channel cannot be configured against a chain without it.
    function _readService(SubstrateTrie.Proof memory proof, bytes32 stateRoot)
        internal
        view
        returns (bytes memory service, bytes32 commitment, uint256 nanos)
    {
        (bool exists, bytes memory r) = SubstrateTrie.get(proof, stateRoot, serviceKey());
        if (!exists) revert ServiceRecordMissing();
        if (r.length != SERVICE_RECORD_LENGTH) revert InvalidServiceRecord();
        service = ScaleCodec.slice(r, 0, SERVICE_ADDRESS_LENGTH);
        commitment = ScaleCodec.readBytes32(r, 32);
        nanos = uint256(ScaleCodec.readU64(r, 64)) | (uint256(ScaleCodec.readU64(r, 72)) << 64);
    }

    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory service)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (commitment == bytes32(0) || keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(service)) revert ManifestServiceAddressMismatch();
    }
}
