// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprParlia} from "@hiero-ledger/clpr/libraries/proof/parlia/ClprParlia.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title BscParliaVerifier
/// @notice CLPR verifier for BNB Smart Chain (and Parlia forks): accepts only headers finalized by a
///         BEP-126 fast-finality vote attestation (BLS12-381 aggregate of ≥ 2/3 of the active
///         validator set), tracks the validator set epoch by epoch from the BLS keys published in
///         epoch blocks, then proves the ClprService queue storage against the finalized state root.
///
/// ## Trust anchor (flat packed, 162 bytes)
/// ```
///   [0..32)    channelId        binds the storage proof to one CLPR channel
///   [32..64)   codeHash         pinned ClprService runtime code hash
///   [64..96)   validatorsHash   keccak256 of the epoch block's `n × (address ‖ blsPubkey48)` section
///   [96..128)  keysHash         keccak256(concat(address20 ‖ uncompressedBlsKey128)) of the same set
///   [128..136) chainId          EIP-155 chain id the header seals are bound to
///   [136..144) epochLength      blocks per epoch (1000 since Maxwell)
///   [144..152) epochBlock       epoch block that published the current set
///   [152..160) activeFrom       first block produced (and voted on) by the current set
///   [160]      turnLength       consecutive blocks per proposer turn (BEP-341)
///   [161]      validatorCount
/// ```
///
/// ## Bundle proof (RLP list, 6 items; 8 with an endpoint-manifest update)
/// ```
/// [ 0: rotations    [[epochHeaderChain, attestation, newKeys], …] — one step per epoch, in order
///   1: validators   anchor set: one byte string of n × (address20 ‖ uncompressedKey128), whose
///                   keccak256 must equal the anchor's keysHash
///   2: finality     [headerChain, attestation] — headerChain[0] carries the proven state root
///   3: accountProof MPT account proof for the ClprService
///   4: storageProof 5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   5: bundleContent protobuf ClprBundleContent
///   6: manifestStorageProof, 7: manifestPreimage (optional) ]
/// ```
/// `headerChain` is `[h_0, …, h_m]` with each header the parent of the next; the attestation must
/// have `source = h_m` and `target = source + 1`, so h_m (and by hash link every h_i) is final.
/// `attestation` is `[voteAddressSet, signature(256-byte uncompressed G2), srcNum, srcHash, tgtNum,
/// tgtHash]`. A rotation's `newKeys` is one byte string of the epoch block's validators as 128-byte
/// uncompressed keys in header order, or empty when the epoch block republishes the current set.
///
/// ## Tenure window
/// The set published in epoch block E votes on targets T with `activeFrom ≤ T − 1` and
/// `T ≤ E + epochLength + checkLen`, where checkLen = (n/2 + 1)·turnLength − 1 (Parlia
/// `minerHistoryCheckLen`, the block after which the next set takes over). Outside that window the
/// verifier reverts (stale or not-yet-rotated anchor).
contract BscParliaVerifier is ClprEvmBundleVerifier {
    // ── Bundle layout ─────────────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 6;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 8;
    uint256 internal constant IDX_ROTATIONS = 0;
    uint256 internal constant IDX_VALIDATORS = 1;
    uint256 internal constant IDX_FINALITY = 2;
    uint256 internal constant IDX_ACCOUNT_PROOF = 3;
    uint256 internal constant IDX_STORAGE_PROOF = 4;
    uint256 internal constant IDX_BUNDLE_CONTENT = 5;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 6;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 7;
    uint256 internal constant ROTATION_FIELDS = 3;
    uint256 internal constant FINALITY_FIELDS = 2;

    // ── Trust anchor layout ───────────────────────────────────────────────────
    uint256 internal constant ANCHOR_OFF_CHANNEL_ID = 0;
    uint256 internal constant ANCHOR_OFF_CODE_HASH = 32;
    uint256 internal constant ANCHOR_OFF_VALIDATORS_HASH = 64;
    uint256 internal constant ANCHOR_OFF_KEYS_HASH = 96;
    uint256 internal constant ANCHOR_OFF_CHAIN_ID = 128;
    uint256 internal constant ANCHOR_OFF_EPOCH_LENGTH = 136;
    uint256 internal constant ANCHOR_OFF_EPOCH_BLOCK = 144;
    uint256 internal constant ANCHOR_OFF_ACTIVE_FROM = 152;
    uint256 internal constant ANCHOR_OFF_TURN_LENGTH = 160;
    uint256 internal constant ANCHOR_OFF_VALIDATOR_COUNT = 161;
    uint256 internal constant TRUST_ANCHOR_LENGTH = 162;

    // ── Config payload: [ledgerConfiguration, chainId, epochLength, epochHeader, activeFrom, keys, codeHash]
    uint256 internal constant CONFIG_FIELDS = 7;
    uint256 internal constant CONFIG_IDX_LEDGER = 0;
    uint256 internal constant CONFIG_IDX_CHAIN_ID = 1;
    uint256 internal constant CONFIG_IDX_EPOCH_LENGTH = 2;
    uint256 internal constant CONFIG_IDX_EPOCH_HEADER = 3;
    uint256 internal constant CONFIG_IDX_ACTIVE_FROM = 4;
    uint256 internal constant CONFIG_IDX_KEYS = 5;
    uint256 internal constant CONFIG_IDX_CODE_HASH = 6;
    /// @dev Config-time manifest proof: [finality, accountProof, manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 4;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error ChainIdMismatch();
    error ValidatorSetMismatch();
    error EpochOutOfSequence(uint256 expected, uint256 got);
    error StaleAttestation(uint64 sourceNumber, uint64 activeFrom);
    error AttestationBeyondTenure(uint256 targetNumber, uint256 lastTarget);

    /// @dev Decoded trust anchor plus the anchor set's keys (once supplied).
    struct Anchor {
        bytes32 channelId;
        bytes32 codeHash;
        bytes32 validatorsHash;
        bytes32 keysHash;
        uint64 chainId;
        uint64 epochLength;
        uint64 epochBlock;
        uint64 activeFrom;
        uint8 turnLength;
        uint8 validatorCount;
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
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // 1. Anchor set keys, bound to the anchor's commitment.
        (ClprParlia.ValidatorSet memory set, bytes32 keysHash) =
            ClprParlia.decodeValidatorEntries(payload[IDX_VALIDATORS]);
        if (set.addrs.length != anchor.validatorCount || keysHash != anchor.keysHash) revert ValidatorSetMismatch();

        // 2. Epoch-by-epoch validator-set rotation, each epoch block finalized by the outgoing set.
        Memory.Slice[] memory rotations = RLP.readList(payload[IDX_ROTATIONS]);
        for (uint256 i = 0; i < rotations.length; i++) {
            set = _rotate(anchor, set, rotations[i]);
        }

        // 3. Finalized state header under the (possibly rotated) set.
        bytes32 stateRoot = _verifyFinality(payload[IDX_FINALITY], anchor, set).stateRoot;

        // 4. Account proof (codeHash pinned) → 5. channel storage slots bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _verifyServiceStorageRoot(
            payload[IDX_ACCOUNT_PROOF], stateRoot, _toAddress(ctx.remoteServiceAddress), anchor.codeHash
        );
        metadata = _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, anchor.channelId);

        // 6. Bundle content → message payloads.
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        // 7. Optional endpoint-manifest update against the same storage root.
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

        // 8. Successor anchor only when at least one epoch was rotated through.
        if (rotations.length > 0) {
            newTrustAnchor = _encodeAnchor(anchor);
            newTrustAnchorId = abi.encodePacked(anchor.epochBlock);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP([ledgerConfiguration (ClprMessagePayload control protobuf), chainId,
    ///      epochLength, epochHeader, activeFrom, packedUncompressedKeys (n × 128 bytes), codeHash]). Like every light client
    ///      this is a trusted (weak-subjectivity) bootstrap: the epoch block and `activeFrom` are taken
    ///      as given, only their internal consistency is checked here.
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
        bytes memory cfgMem = configProofBytes;
        Memory.Slice[] memory cfg = RLP.decodeList(cfgMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidConfigPayload();

        ClprTypes.LedgerConfiguration memory lc =
        ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[CONFIG_IDX_LEDGER])).config;

        Anchor memory anchor;
        anchor.channelId = channelId;
        anchor.codeHash = RLP.readBytes32(cfg[CONFIG_IDX_CODE_HASH]);
        anchor.chainId = _readUint64(cfg[CONFIG_IDX_CHAIN_ID]);
        anchor.epochLength = _readUint64(cfg[CONFIG_IDX_EPOCH_LENGTH]);
        anchor.activeFrom = _readUint64(cfg[CONFIG_IDX_ACTIVE_FROM]);
        if (anchor.epochLength == 0) revert InvalidConfigPayload();
        // The CAIP-2 id the peer advertises must name the chain the seals are bound to.
        if (
            keccak256(bytes(lc.chainId)) != keccak256(bytes(string.concat("eip155:", Strings.toString(anchor.chainId))))
        ) {
            revert ChainIdMismatch();
        }

        ClprParlia.Header memory epoch = ClprParlia.decodeHeader(cfg[CONFIG_IDX_EPOCH_HEADER]);
        if (epoch.number % anchor.epochLength != 0) revert InvalidConfigPayload();
        if (anchor.activeFrom <= epoch.number || anchor.activeFrom > uint256(epoch.number) + anchor.epochLength) {
            revert InvalidConfigPayload();
        }
        ClprParlia.EpochInfo memory info = ClprParlia.parseEpoch(epoch.extra);
        (ClprParlia.ValidatorSet memory set, bytes32 keysHash) =
            ClprParlia.bindEpochKeys(epoch.extra, info, RLP.readBytes(cfg[CONFIG_IDX_KEYS]));
        anchor.epochBlock = epoch.number;
        anchor.validatorsHash = info.validatorsHash;
        anchor.keysHash = keysHash;
        anchor.turnLength = info.turnLength;
        // forge-lint: disable-next-line(unsafe-typecast)
        anchor.validatorCount = uint8(info.addrs.length);

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, anchor, set, serviceAddress);
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            _encodeAnchor(anchor),
            abi.encodePacked(anchor.epochBlock),
            endpointManifest
        );
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    /// @dev One epoch rotation: the next epoch block (strictly `epochBlock + epochLength`) must be
    ///      finalized by the CURRENT set; its validator section becomes the new set, effective after
    ///      the current set's checkLen. Mutates `anchor` in place and returns the new set.
    function _rotate(Anchor memory anchor, ClprParlia.ValidatorSet memory set, Memory.Slice stepItem)
        internal
        view
        returns (ClprParlia.ValidatorSet memory newSet)
    {
        Memory.Slice[] memory step = RLP.readList(stepItem);
        if (step.length != ROTATION_FIELDS) revert InvalidPayloadShape();

        ClprParlia.Header memory epoch =
            _verifyFinalizedChain(step[0], ClprParlia.decodeAttestation(step[1]), anchor, set);
        uint256 expected = uint256(anchor.epochBlock) + anchor.epochLength;
        if (epoch.number != expected) revert EpochOutOfSequence(expected, epoch.number);

        ClprParlia.EpochInfo memory info = ClprParlia.parseEpoch(epoch.extra);
        bytes32 keysHash;
        bytes memory packedKeys = RLP.readBytes(step[2]);
        if (packedKeys.length == 0) {
            // Epoch block republishes the current set (same addresses and BLS keys).
            if (info.validatorsHash != anchor.validatorsHash) revert ValidatorSetMismatch();
            newSet = set;
            keysHash = anchor.keysHash;
        } else {
            (newSet, keysHash) = ClprParlia.bindEpochKeys(epoch.extra, info, packedKeys);
        }

        // The new set takes over after the OUTGOING set's minerHistoryCheckLen.
        uint256 activeFrom = uint256(epoch.number) + ClprParlia.checkLen(anchor.validatorCount, anchor.turnLength) + 1;
        if (activeFrom > type(uint64).max) revert InvalidTrustAnchor();
        // forge-lint: disable-next-line(unsafe-typecast)
        anchor.activeFrom = uint64(activeFrom);
        anchor.epochBlock = epoch.number;
        anchor.validatorsHash = info.validatorsHash;
        anchor.keysHash = keysHash;
        anchor.turnLength = info.turnLength;
        // forge-lint: disable-next-line(unsafe-typecast)
        anchor.validatorCount = uint8(info.addrs.length);
    }

    /// @dev `[headerChain, attestation]` → the finalized header at the chain's head (h_0).
    function _verifyFinality(Memory.Slice item, Anchor memory anchor, ClprParlia.ValidatorSet memory set)
        internal
        view
        returns (ClprParlia.Header memory)
    {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != FINALITY_FIELDS) revert InvalidPayloadShape();
        return _verifyFinalizedChain(f[0], ClprParlia.decodeAttestation(f[1]), anchor, set);
    }

    /// @dev Verify `headerChain` links, that `att` finalizes its newest header (sealed by a member of
    ///      `set` under `anchor.chainId`), and that `att` falls inside the set's tenure window.
    function _verifyFinalizedChain(
        Memory.Slice chainItem,
        ClprParlia.Attestation memory att,
        Anchor memory anchor,
        ClprParlia.ValidatorSet memory set
    ) internal view returns (ClprParlia.Header memory first) {
        ClprParlia.Header memory last;
        (first, last) = ClprParlia.decodeHeaderChain(chainItem);

        // Tenure: the source block was produced, and the target voted on, by this set.
        if (att.sourceNumber < anchor.activeFrom) revert StaleAttestation(att.sourceNumber, anchor.activeFrom);
        // uint256 sums: anchor fields are uint64 and must never overflow into a Panic.
        uint256 lastTarget = uint256(anchor.epochBlock) + anchor.epochLength
            + ClprParlia.checkLen(anchor.validatorCount, anchor.turnLength);
        if (att.targetNumber > lastTarget) revert AttestationBeyondTenure(att.targetNumber, lastTarget);

        ClprParlia.verifyFinalizing(att, last, set);
        ClprParlia.requireSealedBy(last, anchor.chainId, set.addrs);
    }

    /// @dev Optional config-time manifest proof, verified under the configured validator set.
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        Anchor memory anchor,
        ClprParlia.ValidatorSet memory set,
        bytes memory serviceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();
        bytes32 stateRoot = _verifyFinality(p[0], anchor, set).stateRoot;
        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, _toAddress(serviceAddress), anchor.codeHash);
        return _verifyEndpointManifest(p[2], storageRoot, RLP.readBytes(p[3]), serviceAddress);
    }

    function _decodeAnchor(bytes calldata ta) internal pure returns (Anchor memory a) {
        if (ta.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.channelId = bytes32(ta[ANCHOR_OFF_CHANNEL_ID:ANCHOR_OFF_CHANNEL_ID + 32]);
        a.codeHash = bytes32(ta[ANCHOR_OFF_CODE_HASH:ANCHOR_OFF_CODE_HASH + 32]);
        a.validatorsHash = bytes32(ta[ANCHOR_OFF_VALIDATORS_HASH:ANCHOR_OFF_VALIDATORS_HASH + 32]);
        a.keysHash = bytes32(ta[ANCHOR_OFF_KEYS_HASH:ANCHOR_OFF_KEYS_HASH + 32]);
        a.chainId = uint64(bytes8(ta[ANCHOR_OFF_CHAIN_ID:ANCHOR_OFF_CHAIN_ID + 8]));
        a.epochLength = uint64(bytes8(ta[ANCHOR_OFF_EPOCH_LENGTH:ANCHOR_OFF_EPOCH_LENGTH + 8]));
        a.epochBlock = uint64(bytes8(ta[ANCHOR_OFF_EPOCH_BLOCK:ANCHOR_OFF_EPOCH_BLOCK + 8]));
        a.activeFrom = uint64(bytes8(ta[ANCHOR_OFF_ACTIVE_FROM:ANCHOR_OFF_ACTIVE_FROM + 8]));
        a.turnLength = uint8(ta[ANCHOR_OFF_TURN_LENGTH]);
        a.validatorCount = uint8(ta[ANCHOR_OFF_VALIDATOR_COUNT]);
        if (a.epochLength == 0 || a.turnLength == 0 || a.validatorCount == 0) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            a.channelId,
            a.codeHash,
            a.validatorsHash,
            a.keysHash,
            a.chainId,
            a.epochLength,
            a.epochBlock,
            a.activeFrom,
            a.turnLength,
            a.validatorCount
        );
    }

    function _readUint64(Memory.Slice item) internal pure returns (uint64) {
        uint256 v = RLP.readUint256(item);
        if (v > type(uint64).max) revert InvalidConfigPayload();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v);
    }
}
