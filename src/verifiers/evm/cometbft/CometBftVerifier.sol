// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";

/// @title CometBftVerifier
/// @notice One verifier for every CometBFT (Tendermint) chain whose CLPR Service is an EVM contract
///         kept in a Cosmos SDK IAVL store: Cronos and Mezo (Ethermint `evm` store, key prefix
///         0x02), Sei (`evm` store, prefix 0x03). The chain is a deploy-time {Profile}; the code is
///         the same for all of them. See README.md in this directory.
///
/// ## Verification chain (verifyBundle)
///   0. Trust anchor = validatorSetHash(32) ‖ height(8, big-endian): the set trusted to sign every
///      header at or above `height`.
///   1. Optional hops: each hop is a header signed (>2/3) by the current set; it moves the working
///      anchor to (header.next_validators_hash, header.height + 1). This is how a relay catches up
///      across validator-set changes.
///   2. The supplied validator set (raw CometBFT SimpleValidator leaves) must hash to the working
///      anchor hash, and equal the header's validators_hash.
///   3. Header hash (14-field simple Merkle) is rebuilt on-chain; commit signatures from >2/3 of the
///      set's voting power must sign the canonical precommit for that hash.
///   4. ICS-23 multistore proof: store key → store root, rooted at header.app_hash.
///   5. ICS-23 IAVL proof per storage slot: key = prefix ‖ serviceAddress(20) ‖ slot(32).
///   6. If header.next_validators_hash differs from the anchor, the new anchor is
///      (next_validators_hash, header.height + 1).
///
/// ## Signature schemes ({KeyScheme})
///   ED25519        Standard CometBFT keys (Cronos, Mezo, Sei, dYdX, Provenance, THORChain). No
///                  EVM precompile exists on Hedera, so verification is delegated to an
///                  {IEd25519Verifier} (pure-Solidity, ~0.6M gas per signature).
///   SECP256K1_ETH  Polygon's CometBFT fork (Heimdall v2): 65-byte uncompressed keys in PublicKey
///                  oneof field 3, signature = r‖s‖v over keccak256(signBytes), validator address =
///                  Ethereum address. Verified with `ecrecover` (~3k gas per signature).
///
/// ## Trust model
///   Bootstrap: `verifyConfig` starts from the deploy-time weak-subjectivity checkpoint
///   (BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT) and must hop to the config header. It never
///   accepts a validator set the proof itself supplies.
///   After that, the usual light-client assumption: no set the verifier trusts ever had >2/3 of its
///   power sign two conflicting headers. Like every sequential light client without a trusting
///   period, a set that has fully unbonded could forge a hop; relays must keep channels within the
///   chain's unbonding period (README §5).
contract CometBftVerifier is ClprEvmBundleVerifier, CometBftLightClient {
    // ── Types ─────────────────────────────────────────────────────────────────

    /// @param chainId                 CometBFT chain id (header.chain_id), e.g. "cronosmainnet_25-1".
    /// @param storeKey                IAVL store holding EVM contract storage, e.g. "evm".
    /// @param evmStateKeyPrefix       Storage key prefix inside that store (Ethermint 0x02, Sei 0x03).
    /// @param keyScheme               Consensus key type of the validator set.
    /// @param ed25519Verifier         {IEd25519Verifier}; required iff keyScheme == ED25519.
    /// @param bootstrapValidatorsHash Validator-set hash trusted at `bootstrapHeight` (checkpoint).
    /// @param bootstrapHeight         First height the bootstrap set signs.
    struct Profile {
        string chainId;
        bytes storeKey;
        uint8 evmStateKeyPrefix;
        KeyScheme keyScheme;
        address ed25519Verifier;
        bytes32 bootstrapValidatorsHash;
        uint64 bootstrapHeight;
    }

    /// @dev Decoded CometBftBundlePayload (README §4).
    struct BundlePayload {
        bytes stateProof;
        bytes bundleContent;
        bytes validatorSet;
        bytes manifestStorageProof;
        bytes manifestPreimage;
        bytes[] hops;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 internal constant ANCHOR_LENGTH = 40;
    /// @dev ClprService `_config.serviceAddress` (LedgerConfiguration member 2 at slot 23; see
    ///      storage-layout.json). verifyConfig proves this exact slot.
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;
    uint8 internal constant STORAGE_PROOF_MIN_ENTRIES = 5;
    uint8 internal constant STORAGE_PROOF_MAX_ENTRIES = 6;

    // ── Profile (immutable) ───────────────────────────────────────────────────

    bytes32 public immutable STORE_KEY_HASH;
    uint8 public immutable EVM_STATE_KEY_PREFIX;
    bytes32 public immutable BOOTSTRAP_VALIDATORS_HASH;
    uint64 public immutable BOOTSTRAP_HEIGHT;

    // ── Errors ────────────────────────────────────────────────────────────────

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error MissingStateProof();
    error MissingBundleContent();
    error MissingValidatorSet();
    error MissingLedgerConfig();
    error InvalidStoreKey();
    error InvalidStoreRoot();
    error StorageKeyMismatch();
    error StorageProofFailed();
    error InvalidStorageValueLength();
    error NonExistenceSlotNotEmpty();
    error InvalidStorageProofCount();
    error ServiceAddressSlotMismatch();
    error ManifestProofPairMismatch();
    error OnlyExistenceProofsSupported();

    constructor(Profile memory p) CometBftLightClient(keccak256(bytes(p.chainId)), p.keyScheme, p.ed25519Verifier) {
        if (bytes(p.chainId).length == 0 || p.storeKey.length == 0 || p.bootstrapValidatorsHash == bytes32(0)) {
            revert InvalidProfile();
        }
        if (p.keyScheme == KeyScheme.ED25519 && p.ed25519Verifier == address(0)) revert InvalidProfile();
        STORE_KEY_HASH = keccak256(p.storeKey);
        EVM_STATE_KEY_PREFIX = p.evmStateKeyPrefix;
        BOOTSTRAP_VALIDATORS_HASH = p.bootstrapValidatorsHash;
        BOOTSTRAP_HEIGHT = p.bootstrapHeight;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = CometBftBundlePayload; trustAnchor = validatorSetHash(32) ‖ height(8).
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
        bytes20 serviceAddr = _toBytes20(ctx.remoteServiceAddress);
        BundlePayload memory p = _parseBundlePayload(proofBytes);

        (bytes32 setHash, uint64 minHeight) = _applyHops(p.hops, anchorHash, anchorHeight);
        Validator[] memory vals = _parseValidatorSet(p.validatorSet, setHash);

        (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        ) = _verifyStateProof(p.stateProof, vals, setHash, minHeight, serviceAddr);

        if (slotValues.length < STORAGE_PROOF_MIN_ENTRIES || slotValues.length > STORAGE_PROOF_MAX_ENTRIES) {
            revert StorageProofFailed();
        }
        metadata = _bindChannelSlots(slotNumbers, slotValues, ctx.channelId);
        newEndpointManifest = _verifyManifest(
            p.manifestStorageProof, p.manifestPreimage, storeRoot, serviceAddr, ctx.remoteServiceAddress
        );

        if (header.nextValidatorsHash != anchorHash) {
            // forge-lint: disable-next-line(unsafe-typecast)
            newTrustAnchor = _encodeAnchor(header.nextValidatorsHash, uint64(header.height) + 1);
            newTrustAnchorId = newTrustAnchor;
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = CometBftConfigPayload. Trust starts at the deploy-time bootstrap
    ///      checkpoint and follows hops to the config header; the proven slot must be ClprService's
    ///      `_config.serviceAddress` holding the declared address.
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
        (bytes memory valSetBytes, bytes memory ledgerConfig, bytes memory stateProof, bytes[] memory hops) =
            _parseConfigPayload(configProofBytes);

        bytes20 lServiceAddr;
        (, lServiceAddr, peerConfigNanos, throttles,) = Codec.parseLedgerConfiguration(ledgerConfig);

        (bytes32 setHash, uint64 minHeight) = _applyHops(hops, BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT);
        Validator[] memory vals = _parseValidatorSet(valSetBytes, setHash);
        (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        ) = _verifyStateProof(stateProof, vals, setHash, minHeight, lServiceAddr);

        if (slotValues.length != 1) revert InvalidStorageProofCount();
        // Short `bytes` (20 B) layout: data left-aligned, length*2 = 0x28 in the low byte.
        if (
            slotNumbers[0] != bytes32(SERVICE_ADDRESS_SLOT)
                || slotValues[0] != bytes32(uint256(bytes32(lServiceAddr)) | 0x28)
        ) {
            revert ServiceAddressSlotMismatch();
        }

        serviceAddress = abi.encodePacked(lServiceAddr);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = header.chainId;
        // forge-lint: disable-next-line(unsafe-typecast)
        initialTrustAnchor = _encodeAnchor(header.nextValidatorsHash, uint64(header.height) + 1);
        initialTrustAnchorId = initialTrustAnchor;
        endpointManifest = _verifyConfigManifest(endpointManifestProofBytes, storeRoot, lServiceAddr, serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   State proof
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Signed header → app_hash → store root (ICS-23 Tendermint spec) → one IAVL proof per
    ///      storage entry of `serviceAddr`. Returns each proven slot number and value (absent = 0).
    function _verifyStateProof(
        bytes memory stateProofBytes,
        Validator[] memory vals,
        bytes32 setHash,
        uint64 minHeight,
        bytes20 serviceAddr
    )
        internal
        view
        returns (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        )
    {
        (bytes memory signedHeader, bytes memory storeKey, bytes memory multistoreProof, bytes[] memory entries) =
            Codec.parseStateProof(stateProofBytes);
        CometBftLib.SeiCommit memory commit;
        (header, commit) = Codec.parseSignedHeader(signedHeader);
        _verifySignedHeader(header, commit, vals, setHash, minHeight);

        if (keccak256(storeKey) != STORE_KEY_HASH) revert InvalidStoreKey();
        Ics23Lib.ExistenceProof memory ms = Codec.parseExistenceProof(multistoreProof);
        Ics23Lib.verifyMembershipTendermint(ms, header.appHash, storeKey, ms.value);
        if (ms.value.length != 32) revert InvalidStoreRoot();
        storeRoot = Codec.load32(ms.value, 0);

        uint256 n = entries.length;
        slotValues = new bytes32[](n);
        slotNumbers = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            (bytes memory key, bytes memory value, bytes memory proof) = Codec.parseStorageProofEntry(entries[i]);
            _checkStorageKey(key, serviceAddr);
            slotNumbers[i] = Codec.load32(key, 21);
            (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep) =
                Codec.parseCommitmentProof(proof);
            if (isExistence) {
                if (value.length != 32) revert InvalidStorageValueLength();
                Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
                slotValues[i] = Codec.load32(value, 0);
            } else {
                // Never-written (or deleted) slot: absent from the tree, reads as zero.
                if (value.length != 0) revert NonExistenceSlotNotEmpty();
                Ics23Lib.verifyNonMembershipIavl(nep, storeRoot, key);
            }
        }
    }

    /// @dev key = EVM_STATE_KEY_PREFIX ‖ serviceAddr(20) ‖ slot(32).
    function _checkStorageKey(bytes memory key, bytes20 serviceAddr) internal view {
        if (key.length != 53 || uint8(key[0]) != EVM_STATE_KEY_PREFIX) revert StorageKeyMismatch();
        bytes20 a;
        assembly {
            a := mload(add(key, 33))
        }
        if (a != serviceAddr) revert StorageKeyMismatch();
    }

    /// @dev Binds proven slots to the channel's layout: indices 0..4 are
    ///      {_channelMetadataSlots}; an optional 6th is the last sent message's running hash.
    function _bindChannelSlots(bytes32[] memory slotNumbers, bytes32[] memory slotValues, bytes32 channelId)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        bytes32[] memory channelSlots = _channelMetadataSlots(channelId);
        for (uint256 i; i < channelSlots.length; ++i) {
            if (slotNumbers[i] != channelSlots[i]) revert StorageKeyMismatch();
        }
        metadata = _buildQueueMetadata(slotValues);
        if (slotNumbers.length == STORAGE_PROOF_MAX_ENTRIES) {
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            if (slotNumbers[5] != _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1))) {
                revert StorageKeyMismatch();
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Endpoint manifest
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Config-time manifest proof: protobuf {1: StorageProofEntry, 2: preimage}; empty →
    ///      UNINITIALIZED (version 0) manifest.
    function _verifyConfigManifest(
        bytes calldata proofBytes,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) {
            return _uninitializedEndpointManifest(expectedServiceAddress);
        }
        bytes memory entry;
        bytes memory preimage;
        bytes memory data = proofBytes;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) (entry, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 2 && wt == 2) (preimage, off) = PB.decodeLengthDelimited(data, off);
            else off = PB.skipField(data, off, wt);
        }
        return _verifyManifest(entry, preimage, storeRoot, serviceAddr, expectedServiceAddress);
    }

    /// @dev IAVL existence proof of the manifest-commitment slot, preimage bound by keccak256.
    ///      Both inputs empty → absent manifest (version 0, "no update").
    function _verifyManifest(
        bytes memory entryBytes,
        bytes memory preimage,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory manifest) {
        if (entryBytes.length == 0 && preimage.length == 0) {
            return _absentEndpointManifest();
        }
        if (entryBytes.length == 0 || preimage.length == 0) revert ManifestProofPairMismatch();

        (bytes memory key, bytes memory value, bytes memory proof) = Codec.parseStorageProofEntry(entryBytes);
        _checkStorageKey(key, serviceAddr);
        if (Codec.load32(key, 21) != bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT)) revert StorageKeyMismatch();
        if (value.length != 32) revert InvalidStorageValueLength();
        (bool isExistence, Ics23Lib.ExistenceProof memory ep,) = Codec.parseCommitmentProof(proof);
        if (!isExistence) revert OnlyExistenceProofsSupported();
        Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
        if (keccak256(preimage) != Codec.load32(value, 0)) revert ManifestCommitmentMismatch();

        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Payload decoding
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev CometBftBundlePayload: 1 state_proof, 2 bundle_content, 3 validator_set,
    ///      4 manifest storage proof, 5 manifest preimage, 6 repeated hop.
    function _parseBundlePayload(bytes memory data) internal pure returns (BundlePayload memory p) {
        p.hops = new bytes[](_countField(data, 6));
        uint256 h;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) {
                off = PB.skipField(data, off, wt);
            } else if (fn_ == 1) {
                (p.stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2) {
                (p.bundleContent, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3) {
                (p.validatorSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4) {
                (p.manifestStorageProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 5) {
                (p.manifestPreimage, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 6) {
                (p.hops[h++], off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (p.stateProof.length == 0) revert MissingStateProof();
        if (p.bundleContent.length == 0) revert MissingBundleContent();
        if (p.validatorSet.length == 0) revert MissingValidatorSet();
    }

    /// @dev CometBftConfigPayload: 1 validator_set, 2 ledger_configuration, 3 state_proof,
    ///      4 repeated hop (from the bootstrap checkpoint).
    function _parseConfigPayload(bytes memory data)
        internal
        pure
        returns (bytes memory valSet, bytes memory ledgerConfig, bytes memory stateProof, bytes[] memory hops)
    {
        hops = new bytes[](_countField(data, 4));
        uint256 h;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) {
                off = PB.skipField(data, off, wt);
            } else if (fn_ == 1) {
                (valSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2) {
                (ledgerConfig, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3) {
                (stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4) {
                (hops[h++], off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (valSet.length == 0) revert MissingValidatorSet();
        if (ledgerConfig.length == 0) revert MissingLedgerConfig();
        if (stateProof.length == 0) revert MissingStateProof();
    }

    function _countField(bytes memory data, uint64 field) private pure returns (uint256 n) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            if (fn_ == field && wt == 2) ++n;
            off = PB.skipField(data, off2, wt);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata anchor) internal pure returns (bytes32 setHash, uint64 height) {
        if (anchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        setHash = bytes32(anchor[0:32]);
        height = uint64(bytes8(anchor[32:40]));
        if (setHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(bytes32 setHash, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(setHash, height);
    }

    function _toBytes20(bytes memory b) internal pure returns (bytes20 addr) {
        if (b.length != 20) revert InvalidServiceAddressLength();
        assembly {
            addr := mload(add(b, 32))
        }
    }
}
