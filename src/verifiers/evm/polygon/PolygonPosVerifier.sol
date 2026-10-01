// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftStoreProofBase} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftStoreProofBase.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title PolygonPosVerifier
/// @notice "Polygon PoS → Hiero" verifier. Bor (the EVM chain) has no finality of its own that a
///         light client can check cheaply; its finality is the Heimdall v2 **milestone**: Heimdall
///         validators (CometBFT, secp256k1eth keys) vote Bor block hashes in vote extensions, and
///         a hash backed by more than 2/3 of their power is written to Heimdall's `milestone` store.
///         This verifier follows that path end to end. See README.md in this directory.
///
/// ## Verification chain (verifyBundle)
///   0. Trust anchor = Heimdall validatorSetHash(32) ‖ height(8, big-endian), as in {CometBftVerifier}.
///   1. Hops, then the Heimdall header, each a `HeaderRef` checked through the
///      {CometBftCommitAccumulator} deployed for `heimdallv2-137` with SECP256K1_ETH keys (inline:
///      ~10 ecrecovers, since the set is sorted by power).
///   2. ICS-23 multistore proof: store `milestone` → store root, under the header's app_hash.
///   3. ICS-23 IAVL existence proof of one milestone: key `0x81 ‖ count(u64 BE)`
///      (collections.Map[uint64, Milestone], x/milestone/types/keys.go), value the protobuf
///      `Milestone{3 end_block, 4 hash, 5 bor_chain_id, …}`.
///   4. The Bor header: RLP with keccak256 == milestone.hash and number == milestone.end_block.
///      Its stateRoot (field 3) is the Bor state root at that block.
///   5. MPT account proof of the ClprService → storage root; MPT storage proofs of the channel's
///      slots ({ClprEvmBundleVerifier}), as on every other EVM chain.
///   6. New anchor (next_validators_hash, height + 1) when the Heimdall set changes.
contract PolygonPosVerifier is ClprEvmBundleVerifier, CometBftStoreProofBase {
    /// @param accumulator              {CometBftCommitAccumulator} for the Heimdall chain id, SECP256K1_ETH.
    /// @param storeKey                 Heimdall store holding milestones ("milestone").
    /// @param borChainId               Milestone.bor_chain_id the verifier accepts ("137" on mainnet).
    /// @param bootstrapValidatorsHash  Heimdall validator-set hash trusted at `bootstrapHeight`.
    /// @param bootstrapHeight          First Heimdall height the bootstrap set signs.
    struct Profile {
        CometBftCommitAccumulator accumulator;
        bytes storeKey;
        string borChainId;
        bytes32 bootstrapValidatorsHash;
        uint64 bootstrapHeight;
    }

    /// @dev Decoded PolygonPosProof (README §4). One message for every entry point.
    struct Payload {
        bytes bundleContent; // 1
        bytes header; // 2  HeaderRef (Heimdall)
        bytes[] hops; // 3  repeated HeaderRef
        bytes multistoreProof; // 4  ICS-23, store "milestone"
        bytes milestoneEntry; // 5  StorageProofEntry
        bytes borHeader; // 6  RLP block header
        bytes accountProof; // 7  RLP list of MPT nodes
        bytes storageProof; // 8  RLP list of [slot, [nodes]]
        bytes manifestStorageProof; // 9  RLP list with one [slot, [nodes]]
        bytes manifestPreimage; // 10
        bytes ledgerConfiguration; // 11 (config)
    }

    /// @dev Bor's view of a verified milestone.
    struct BorBlock {
        uint64 number;
        bytes32 hash;
        bytes32 stateRoot;
    }

    uint8 internal constant MILESTONE_PREFIX = 0x81;
    uint256 internal constant MILESTONE_KEY_LENGTH = 9;
    uint256 internal constant BOR_HEADER_MIN_FIELDS = 15;
    uint256 internal constant BOR_STATE_ROOT_INDEX = 3;
    uint256 internal constant BOR_NUMBER_INDEX = 8;
    /// @dev ClprService `_config.serviceAddress` (storage-layout.json), as in {CometBftVerifier}.
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;

    bytes32 public immutable BOR_CHAIN_ID_HASH;

    error MissingBundleContent();
    error MissingLedgerConfig();
    error MissingBorProof();
    error InvalidMilestoneKey();
    error MilestoneNotFound();
    error InvalidMilestone();
    error BorChainIdMismatch();
    error InvalidBorHeader();
    error BorHeaderHashMismatch();
    error BorBlockNumberMismatch();
    error ServiceAddressSlotMismatch();
    error ManifestProofPairMismatch();

    constructor(Profile memory p)
        CometBftStoreProofBase(p.accumulator, p.storeKey, p.bootstrapValidatorsHash, p.bootstrapHeight)
    {
        if (bytes(p.borChainId).length == 0) revert InvalidProfile();
        BOR_CHAIN_ID_HASH = keccak256(bytes(p.borChainId));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = PolygonPosProof{1 bundle_content, 2 header, 3 hops, 4 multistore proof,
    ///      5 milestone entry, 6 Bor header, 7 account proof, 8 channel storage proof (5 or 6
    ///      slots), 9 manifest storage proof?, 10 manifest preimage?}.
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
        address service = _toAddress(ctx.remoteServiceAddress);
        Payload memory p = _parsePayload(proofBytes);
        if (p.bundleContent.length == 0) revert MissingBundleContent();

        (CometBftCommitAccumulator.Header memory h, BorBlock memory bor) =
            _verifiedBorBlock(p, anchorHash, anchorHeight);
        bytes32 storageRoot = _verifyServiceStorageRoot(Memory.asSlice(p.accountProof), bor.stateRoot, service, 0);
        metadata = _verifyChannelStorage(Memory.asSlice(p.storageProof), storageRoot, ctx.channelId);

        if (p.manifestStorageProof.length == 0 && p.manifestPreimage.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            if (p.manifestStorageProof.length == 0 || p.manifestPreimage.length == 0) {
                revert ManifestProofPairMismatch();
            }
            newEndpointManifest = _verifyEndpointManifest(
                Memory.asSlice(p.manifestStorageProof), storageRoot, p.manifestPreimage, ctx.remoteServiceAddress
            );
        }

        if (h.nextValidatorsHash != anchorHash) {
            newTrustAnchor = _nextAnchor(h);
            newTrustAnchorId = newTrustAnchor;
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = PolygonPosProof{2 header, 3 hops from the bootstrap checkpoint,
    ///      4 multistore proof, 5 milestone entry, 6 Bor header, 7 account proof, 8 storage proof of
    ///      exactly slot 25 (`_config.serviceAddress`), 9 manifest storage proof?, 11 ledger
    ///      configuration}. endpointManifestProofBytes is the manifest preimage (empty →
    ///      UNINITIALIZED manifest), bound to the commitment proven by field 9.
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
        bytes20 service;
        (, service, peerConfigNanos, throttles,) = Codec.parseLedgerConfiguration(p.ledgerConfiguration);
        serviceAddress = abi.encodePacked(service);

        (CometBftCommitAccumulator.Header memory h, BorBlock memory bor) =
            _verifiedBorBlock(p, BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT);
        bytes32 storageRoot =
            _verifyServiceStorageRoot(Memory.asSlice(p.accountProof), bor.stateRoot, address(service), 0);

        Memory.Slice[] memory entries = RLP.readList(Memory.asSlice(p.storageProof));
        if (entries.length != 1) revert InvalidStorageProofShape();
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(SERVICE_ADDRESS_SLOT);
        // Short `bytes` (20 B) layout: data left-aligned, length*2 = 0x28 in the low byte.
        if (
            ClprEvmStateProof.verifyProvenSlots(entries, storageRoot, slots)[0]
                != bytes32(uint256(bytes32(service)) | 0x28)
        ) {
            revert ServiceAddressSlotMismatch();
        }

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = ACCUMULATOR.chainId();
        initialTrustAnchor = _nextAnchor(h);
        initialTrustAnchorId = initialTrustAnchor;
        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            if (p.manifestStorageProof.length == 0) revert ManifestProofPairMismatch();
            endpointManifest = _verifyEndpointManifest(
                Memory.asSlice(p.manifestStorageProof), storageRoot, endpointManifestProofBytes, serviceAddress
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic Bor storage read
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Prove storage slots of any Bor contract at a milestone-finalized block.
    /// @param proofBytes  PolygonPosProof{2 header, 3 hops, 4 multistore proof, 5 milestone entry,
    ///                    6 Bor header, 7 account proof, 8 storage proof (one entry per slot)}.
    /// @param trustAnchor Heimdall validatorSetHash(32) ‖ height(8), as for verifyBundle.
    /// @param account     The Bor contract.
    /// @param slots       Storage slots to read; absent slots read as zero.
    /// @return values     Proven slot values, in `slots` order.
    /// @return borBlock   The Bor block the milestone finalized (its state root holds `values`).
    /// @return heimdallHeight Height of the Heimdall header that committed the milestone.
    function verifyContractSlots(
        bytes calldata proofBytes,
        bytes calldata trustAnchor,
        address account,
        bytes32[] calldata slots
    ) external view returns (bytes32[] memory values, uint64 borBlock, uint64 heimdallHeight) {
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        Payload memory p = _parsePayload(proofBytes);
        (CometBftCommitAccumulator.Header memory h, BorBlock memory bor) =
            _verifiedBorBlock(p, anchorHash, anchorHeight);
        bytes32 storageRoot = _verifyServiceStorageRoot(Memory.asSlice(p.accountProof), bor.stateRoot, account, 0);
        values = ClprEvmStateProof.verifyProvenSlots(RLP.readList(Memory.asSlice(p.storageProof)), storageRoot, slots);
        borBlock = bor.number;
        heimdallHeight = h.height;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Heimdall milestone → Bor block
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Heimdall header → `milestone` store root → milestone → Bor header → Bor state root.
    function _verifiedBorBlock(Payload memory p, bytes32 setHash, uint64 minHeight)
        internal
        view
        returns (CometBftCommitAccumulator.Header memory h, BorBlock memory bor)
    {
        if (p.borHeader.length == 0 || p.accountProof.length == 0 || p.storageProof.length == 0) {
            revert MissingBorProof();
        }
        bytes32 storeRoot;
        (h, storeRoot) = _verifiedStoreRoot(p.header, p.hops, p.multistoreProof, setHash, minHeight);
        (bor.number, bor.hash) = _proveMilestone(p.milestoneEntry, storeRoot);
        bor.stateRoot = _borStateRoot(p.borHeader, bor.hash, bor.number);
    }

    /// @dev The milestone entry must exist under key 0x81 ‖ count(8). Returns (end_block, hash).
    ///      The count itself is free: every milestone in the store was backed by >2/3 of Heimdall's
    ///      power when it was added, and an older one only yields older (stale) Bor state, which
    ///      ClprService's progress checks reject.
    function _proveMilestone(bytes memory entry, bytes32 storeRoot)
        internal
        view
        returns (uint64 endBlock, bytes32 hash)
    {
        if (entry.length == 0) revert MissingStorageEntry();
        (bytes memory key,,) = Codec.parseStorageProofEntry(entry);
        if (key.length != MILESTONE_KEY_LENGTH || uint8(key[0]) != MILESTONE_PREFIX) revert InvalidMilestoneKey();
        (bool exists, bytes memory value) = _proveEntry(entry, storeRoot, key);
        if (!exists) revert MilestoneNotFound();
        (endBlock, hash) = _decodeMilestone(value);
    }

    /// @dev heimdallv2.milestone.Milestone{1 proposer, 2 start_block, 3 end_block, 4 hash,
    ///      5 bor_chain_id, 6 milestone_id, 7 timestamp, 8 total_difficulty}. end_block > 0, a
    ///      32-byte hash and the profile's bor_chain_id are required.
    function _decodeMilestone(bytes memory m) internal view returns (uint64 endBlock, bytes32 hash) {
        bytes memory h;
        bytes memory borChainId;
        uint256 off;
        while (off < m.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(m, off);
            off = off2;
            if (fn_ == 3 && wt == 0) (endBlock, off) = PB.decodeVarint(m, off);
            else if (fn_ == 4 && wt == 2) (h, off) = PB.decodeLengthDelimited(m, off);
            else if (fn_ == 5 && wt == 2) (borChainId, off) = PB.decodeLengthDelimited(m, off);
            else off = PB.skipField(m, off, wt);
        }
        if (endBlock == 0 || h.length != 32) revert InvalidMilestone();
        if (keccak256(borChainId) != BOR_CHAIN_ID_HASH) revert BorChainIdMismatch();
        hash = Codec.load32(h, 0);
    }

    /// @dev The Bor header is the RLP whose keccak256 is the milestone hash; its number must be the
    ///      milestone's end_block. Field order is go-ethereum's (Bor core/types/block.go): 15
    ///      legacy fields, then optional baseFee, withdrawalsHash, … (all covered by the hash).
    function _borStateRoot(bytes memory header, bytes32 expectedHash, uint64 expectedNumber)
        internal
        pure
        returns (bytes32 stateRoot)
    {
        if (keccak256(header) != expectedHash) revert BorHeaderHashMismatch();
        Memory.Slice[] memory f = RLP.decodeList(header);
        if (f.length < BOR_HEADER_MIN_FIELDS) revert InvalidBorHeader();
        if (RLP.readUint256(f[BOR_NUMBER_INDEX]) != expectedNumber) revert BorBlockNumberMismatch();
        stateRoot = RLP.readBytes32(f[BOR_STATE_ROOT_INDEX]);
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
        uint256 hi;
        off = 0;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) off = PB.skipField(data, off, wt);
            else if (fn_ == 1) (p.bundleContent, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 2) (p.header, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 3) (p.hops[hi++], off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 4) (p.multistoreProof, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 5) (p.milestoneEntry, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 6) (p.borHeader, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 7) (p.accountProof, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 8) (p.storageProof, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 9) (p.manifestStorageProof, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 10) (p.manifestPreimage, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 11) (p.ledgerConfiguration, off) = PB.decodeLengthDelimited(data, off);
            else off = PB.skipField(data, off, wt);
        }
    }
}
