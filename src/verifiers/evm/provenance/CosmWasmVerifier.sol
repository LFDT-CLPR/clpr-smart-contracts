// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftStoreProofBase} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftStoreProofBase.sol";

/// @title CosmWasmVerifier
/// @notice "CosmWasm chain → Hiero" verifier: CometBFT finality plus an ICS-23 proof of the peer
///         CLPR Service's storage in the wasmd `wasm` IAVL store. Built for Provenance
///         (pio-mainnet-1); any CometBFT + wasmd chain fits through the deploy-time profile.
///         See README.md in this directory.
///
/// ## Verification chain (verifyBundle)
///   0. Trust anchor = validatorSetHash(32) ‖ height(8, big-endian), as in {CometBftVerifier}.
///   1. Hops, then the bundle header. Each is a `HeaderRef`: either inline (validator set + signed
///      header, checked by {CometBftCommitAccumulator.checkHeader} in this call) or the hash of a
///      header whose commit was already accumulated over earlier transactions
///      ({CometBftCommitAccumulator.finalizedHeader}). Both must be signed by the working set at or
///      above the working height.
///   2. ICS-23 multistore proof (Tendermint spec): store `wasm` → store root, under app_hash.
///   3. ICS-23 IAVL proof (existence or non-existence) of the channel's queue record, key
///      `0x03 ‖ service ‖ 0x000a ‖ "clpr_queue" ‖ channelId`. Absent reads as all-zero metadata.
///   4. Optional: IAVL existence proof of the service item `0x03 ‖ service ‖ "clpr_service"`
///      (service address ‖ manifest commitment) plus the manifest preimage.
///   5. New anchor (next_validators_hash, height + 1) when the set changes.
///
/// ## Peer storage layout (fixed by this verifier; README §4)
///   wasmd keeps every contract's storage in store `wasm` under `0x03 ‖ contract address`
///   (x/wasm/types/keys.go `GetContractStorePrefix`). Inside it the CLPR Service writes, with
///   `deps.storage.set` (raw bytes, not JSON):
///     queue record  key  cw-storage-plus Map("clpr_queue")[channelId] = 0x000a ‖ "clpr_queue" ‖ channelId
///                   value 90 B: 0x01 ‖ status u8 ‖ next_message_id u64 ‖ received_message_id u64 ‖
///                         endpoint_manifest_version u64 ‖ sent_running_hash ‖ received_running_hash
///                         (integers big-endian)
///     service item  key  "clpr_service" (cw-storage-plus Item)
///                   value own canonical address ‖ manifest commitment (keccak256 of the protobuf
///                         ClprEndpointManifest, or 32 zero bytes when none is set)
contract CosmWasmVerifier is ClprEvmBundleVerifier, CometBftStoreProofBase {
    /// @param accumulator              {CometBftCommitAccumulator} deployed for this chain.
    /// @param storeKey                 IAVL store of wasmd ("wasm").
    /// @param bootstrapValidatorsHash  Validator-set hash trusted at `bootstrapHeight`.
    /// @param bootstrapHeight          First height the bootstrap set signs.
    struct Profile {
        CometBftCommitAccumulator accumulator;
        bytes storeKey;
        bytes32 bootstrapValidatorsHash;
        uint64 bootstrapHeight;
    }

    /// @dev Decoded CosmWasmProof (README §5). One message for every entry point.
    struct Payload {
        bytes bundleContent; // 1
        bytes header; // 2  HeaderRef
        bytes[] hops; // 3  repeated HeaderRef
        bytes multistoreProof; // 4
        bytes entry; // 5  StorageProofEntry
        bytes serviceEntry; // 6  StorageProofEntry (bundle, optional)
        bytes manifestPreimage; // 7  (bundle, optional)
        bytes ledgerConfiguration; // 8  (config)
    }

    uint8 internal constant CONTRACT_STORE_PREFIX = 0x03;
    bytes internal constant QUEUE_NAMESPACE = hex"000a636c70725f7175657565"; // len16 ‖ "clpr_queue"
    bytes internal constant SERVICE_ITEM_KEY = "clpr_service";
    uint256 internal constant QUEUE_RECORD_LENGTH = 90;
    uint8 internal constant QUEUE_RECORD_VERSION = 1;

    error MissingBundleContent();
    error MissingLedgerConfig();
    error EntryNotFound();
    error InvalidQueueRecord();
    error InvalidServiceEntry();
    error ManifestProofPairMismatch();

    constructor(Profile memory p)
        CometBftStoreProofBase(p.accumulator, p.storeKey, p.bootstrapValidatorsHash, p.bootstrapHeight)
    {}

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = CosmWasmProof{1 bundle_content, 2 header, 3 hops, 4 multistore proof,
    ///      5 queue-record entry, 6 service entry?, 7 manifest preimage?}.
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
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        _checkAddress(ctx.remoteServiceAddress);
        Payload memory p = _parsePayload(proofBytes);
        if (p.bundleContent.length == 0) revert MissingBundleContent();

        (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) = _verifiedStoreRoot(p, anchorHash, anchorHeight);
        (bool exists, bytes memory record) =
            _proveEntry(p.entry, storeRoot, _queueKey(ctx.remoteServiceAddress, ctx.channelId));
        if (exists) metadata = _decodeQueueRecord(record);

        if (p.serviceEntry.length == 0 && p.manifestPreimage.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            if (p.serviceEntry.length == 0 || p.manifestPreimage.length == 0) revert ManifestProofPairMismatch();
            bytes32 commitment = _proveServiceEntry(p.serviceEntry, storeRoot, ctx.remoteServiceAddress);
            newEndpointManifest = _bindManifest(p.manifestPreimage, commitment, ctx.remoteServiceAddress);
        }

        if (h.nextValidatorsHash != anchorHash) {
            newTrustAnchor = _nextAnchor(h);
            newTrustAnchorId = newTrustAnchor;
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = CosmWasmProof{2 header, 3 hops from the bootstrap checkpoint,
    ///      4 multistore proof, 5 service entry, 8 ledger configuration}. The service entry must
    ///      exist and start with the configured service address. endpointManifestProofBytes is the
    ///      manifest preimage (empty → UNINITIALIZED manifest), bound to the commitment in that entry.
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
        Payload memory p = _parsePayload(configProofBytes);
        if (p.ledgerConfiguration.length == 0) revert MissingLedgerConfig();
        (serviceAddress, peerConfigNanos, throttles) = _parseLedgerConfiguration(p.ledgerConfiguration);
        _checkAddress(serviceAddress);

        (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) =
            _verifiedStoreRoot(p, BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT);
        bytes32 commitment = _proveServiceEntry(p.entry, storeRoot, serviceAddress);

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = ACCUMULATOR.chainId();
        initialTrustAnchor = _nextAnchor(h);
        initialTrustAnchorId = initialTrustAnchor;
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _bindManifest(endpointManifestProofBytes, commitment, serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic CosmWasm storage read
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Prove one storage entry of any CosmWasm contract under a verified commit: the raw
    ///         wasm-store value at `0x03 ‖ contractAddress ‖ key`, or absence.
    /// @param proofBytes   CosmWasmProof{2 header, 3 hops, 4 multistore proof, 5 entry}.
    /// @param trustAnchor  validatorSetHash(32) ‖ height(8), as for verifyBundle.
    /// @param contractAddress Canonical contract address (20 or 32 bytes).
    /// @param key          The contract's own storage key (e.g. cw2 "contract_info").
    /// @return exists      False when the proof is a non-existence proof.
    /// @return value       The raw stored bytes (CosmWasm contracts usually store JSON).
    /// @return height      Height of the header whose app_hash commits to that state.
    function verifyContractEntry(
        bytes calldata proofBytes,
        bytes calldata trustAnchor,
        bytes calldata contractAddress,
        bytes calldata key
    ) external view returns (bool exists, bytes memory value, uint64 height) {
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        _checkAddress(contractAddress);
        Payload memory p = _parsePayload(proofBytes);
        (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) = _verifiedStoreRoot(p, anchorHash, anchorHeight);
        (exists, value) =
            _proveEntry(p.entry, storeRoot, bytes.concat(bytes1(CONTRACT_STORE_PREFIX), contractAddress, key));
        height = h.height;
    }

    /// @dev Hops, then the state header, then app_hash → `wasm` store root.
    function _verifiedStoreRoot(Payload memory p, bytes32 setHash, uint64 minHeight)
        internal
        view
        returns (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot)
    {
        return _verifiedStoreRoot(p.header, p.hops, p.multistoreProof, setHash, minHeight);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Storage
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev The service item must exist and hold `service ‖ commitment(32)`. Returns the
    ///      commitment (zero when no manifest is set).
    function _proveServiceEntry(bytes memory entry, bytes32 storeRoot, bytes memory service)
        internal
        pure
        returns (bytes32 commitment)
    {
        (bool exists, bytes memory value) =
            _proveEntry(entry, storeRoot, bytes.concat(bytes1(CONTRACT_STORE_PREFIX), service, SERVICE_ITEM_KEY));
        if (!exists) revert EntryNotFound();
        uint256 n = service.length;
        if (value.length != n + 32) revert InvalidServiceEntry();
        for (uint256 i; i < n; ++i) {
            if (value[i] != service[i]) revert InvalidServiceEntry();
        }
        commitment = Codec.load32(value, n);
    }

    function _queueKey(bytes memory service, bytes32 channelId) internal pure returns (bytes memory) {
        return bytes.concat(bytes1(CONTRACT_STORE_PREFIX), service, QUEUE_NAMESPACE, channelId);
    }

    /// @dev 90-byte record: version ‖ status ‖ next ‖ received ‖ manifest version ‖ sent hash ‖ received hash.
    function _decodeQueueRecord(bytes memory r) internal pure returns (ClprTypes.QueueMetadata memory m) {
        if (r.length != QUEUE_RECORD_LENGTH || uint8(r[0]) != QUEUE_RECORD_VERSION) revert InvalidQueueRecord();
        if (uint8(r[1]) > uint8(type(ClprTypes.ChannelStatus).max)) revert InvalidQueueRecord();
        bytes32 w = Codec.load32(r, 2); // next(8) ‖ received(8) ‖ manifestVersion(8) ‖ 8 B of sent hash
        m.state = ClprTypes.ChannelStatus(uint8(r[1]));
        // forge-lint: disable-next-line(unsafe-typecast)
        m.nextMessageId = uint64(bytes8(w));
        // forge-lint: disable-next-line(unsafe-typecast)
        m.receivedMessageId = uint64(bytes8(w << 64));
        // forge-lint: disable-next-line(unsafe-typecast)
        m.endpointManifestVersion = uint64(bytes8(w << 128));
        m.sentRunningHash = Codec.load32(r, 26);
        m.receivedRunningHash = Codec.load32(r, 58);
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

    // ─────────────────────────────────────────────────────────────────────────
    //   Decoding
    // ─────────────────────────────────────────────────────────────────────────

    function _parsePayload(bytes memory data) internal pure returns (Payload memory p) {
        uint256 hopCount;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            if (fn_ == 3 && wt == 2) ++hopCount;
            off = PB.skipField(data, off2, wt);
        }
        p.hops = new bytes[](hopCount);
        uint256 h;
        off = 0;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) off = PB.skipField(data, off, wt);
            else if (fn_ == 1) (p.bundleContent, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 2) (p.header, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 3) (p.hops[h++], off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 4) (p.multistoreProof, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 5) (p.entry, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 6) (p.serviceEntry, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 7) (p.manifestPreimage, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 8) (p.ledgerConfiguration, off) = PB.decodeLengthDelimited(data, off);
            else off = PB.skipField(data, off, wt);
        }
    }

    /// @dev ClprLedgerConfiguration{1 chain_id, 2 service_address, 3 config nanos, 4 throttles}.
    ///      The service address is a CosmWasm canonical address (20 or 32 bytes).
    function _parseLedgerConfiguration(bytes memory data)
        internal
        pure
        returns (bytes memory service, uint96 nanos, ClprTypes.Throttles memory throttles)
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 2 && wt == 2) {
                (service, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                nanos = uint96(v);
            } else if (fn_ == 4 && wt == 2) {
                bytes memory t;
                (t, off) = PB.decodeLengthDelimited(data, off);
                throttles = Codec.parseThrottles(t);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev wasmd builds 32-byte contract addresses (`BuildContractAddressClassic`). Provenance
    ///      also still has early contracts with 20-byte addresses (e.g. code 33, checked live).
    function _checkAddress(bytes memory a) internal pure {
        if (a.length != 20 && a.length != 32) revert InvalidServiceAddressLength();
    }
}
