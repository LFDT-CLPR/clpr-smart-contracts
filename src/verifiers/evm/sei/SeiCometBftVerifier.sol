// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CometBftProofCodec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";

/// @title SeiCometBftVerifier
/// @notice Verifies CLPR bundle and config proofs anchored to Sei (CometBFT consensus).
///
/// ## Verification chain
///   1. Trusted validator set simple-Merkle hash == signed header's `validators_hash`.
///   2. Header hash recomputed from 14 cdc-encoded fields == commit's BlockID hash.
///   3. Every selected Ed25519 signature valid; signers' voting power > 2/3 total.
///   4. ICS-23 Tendermint-spec multistore proof: ("evm" -> store root) up to app_hash.
///   5. ICS-23 IAVL proof per storage slot; keys 0x03 || serviceAddress || slot32.
///
/// ## Trust anchor encoding
/// `abi.encode(string chainId, CometBftLib.SeiValidator[] validatorSet)`
/// where `CometBftLib.SeiValidator` is `(bytes32 ed25519PubKey, int64 votingPower)`.
///
/// ## Bundle proof encoding (protobuf ClprSeiBundlePayload fields)
///   field 1 (LEN): ClprSeiBundlePayload.state_proof   — SeiStateProof proto
///   field 2 (LEN): ClprSeiBundlePayload.bundle_content — ClprBundleContent proto
///   field 3 (LEN): ClprSeiBundlePayload.next_validator_set — optional SeiValidatorSet proto
///   field 4 (LEN): endpoint_manifest_storage_proof — optional StorageProofEntry proving the peer
///                  service's manifest-commitment slot (ENDPOINT_MANIFEST_COMMITMENT_SLOT)
///   field 5 (LEN): endpoint_manifest_preimage — ClprEndpointManifest protobuf bytes whose keccak256
///                  must equal the proven commitment (present iff field 4 is present)
///
/// ## Config proof encoding (protobuf ClprSeiLedgerConfigurationPayload fields)
///   field 1 (LEN): validator_set
///   field 2 (LEN): ledger_configuration
///   field 3 (LEN): state_proof
///
/// ## Config-time endpoint-manifest proof (verifyConfig's 3rd arg, when non-empty)
///   field 1 (LEN): manifest storage-proof entry (StorageProofEntry, commitment slot)
///   field 2 (LEN): manifest protobuf preimage
/// Verified against the same storeRoot the config's state proof authenticates.
///
/// @dev Ed25519 verification is injected as a dependency ({IEd25519Verifier}), decoupling the
///      consensus/proof logic from any single chain's Ed25519 mechanism. On Sei (whose 0x09 is
///      BLAKE2F, not the EIP-665 Ed25519 precompile) pass the pure-Solidity {Ed25519Verifier};
///      on a chain with an EIP-665 precompile, pass a thin precompile-backed adapter. Test
///      harnesses may override the internal `_verifyEd25519` to bypass the call entirely.
///
/// @dev Extends {ClprEvmBundleVerifier} to reuse the downstream EVM-state decode: the proven `Channel` storage-slot
///      values are decoded into queue metadata via {ClprEvmBundleVerifier._buildQueueMetadata}, and
///      the `ClprBundleContent` protobuf via {ClprEvmBundleVerifier._decodeBundleContent}. Only the *state commitment*
///      differs — Sei authenticates slots with ICS-23/IAVL proofs against the CometBFT `appHash` (there is no EVM
///      state root / MPT account trie on Sei), so the base's MPT account-proof helpers are unused here.
contract SeiCometBftVerifier is ClprEvmBundleVerifier {
    // ── Storage proof layout ─────────────────────────────────────────────────
    // The proven slot values are ordered to match the relay's slotsToProve construction
    // (SeiBundleConstructor): the five Channel slots first (+1, +2, +4, +5, +16 — see
    // {ClprEvmBundleVerifier._channelMetadataSlots}), then the last message's running-hash
    // slot (present only when the bundle carries messages) — so ACK-only bundles have 5 entries and
    // message-bearing bundles have 6. Queue metadata is decoded from the first five (indices 0..4) by
    // the shared {ClprEvmBundleVerifier._buildQueueMetadata}; the sixth is the relay's own consistency
    // anchor, proven for membership but not surfaced in metadata.
    uint8 internal constant STORAGE_PROOF_MIN_ENTRIES = 5;
    uint8 internal constant STORAGE_PROOF_EXPECTED_ENTRIES = 6;

    // ── Sei-chain EVM module constants ────────────────────────────────────────
    /// @dev x/evm/types/keys.go: StateKeyPrefix for contract storage.
    uint8 internal constant EVM_STATE_KEY_PREFIX = 0x03;
    bytes3 internal constant EXPECTED_STORE_KEY = "evm"; // 3 bytes

    // ── CometBFT canonical vote constants ────────────────────────────────────
    uint8 internal constant PRECOMMIT_TYPE = 2;

    // ── Errors ────────────────────────────────────────────────────────────────
    error InvalidTrustAnchor();
    error ValidatorSetHashMismatch();
    error InvalidSignature();
    error InvalidStoreKey();
    error StorageProofFailed();
    error StorageKeyMismatch();
    error ChainIdMismatch();
    error HeightTooOld();
    error NextValidatorSetHashMismatch();
    error MissingNextValidatorSet();
    error InvalidPayloadShape();
    error ZeroEd25519Verifier();
    error InvalidStorageProofCount();
    error ServiceAddressSlotMismatch();
    error InvalidStorageValueLength();
    error NonExistenceSlotNotEmpty();
    error InvalidSignersBitsLength();
    error SignersBitOutOfRange();
    error TooFewSignatures();
    error ExtraSignatures();
    error QuorumNotMet();
    error EmptyValidatorSet();
    error KeyMismatch();
    error ValueMismatch();
    error RootMismatch();
    error NonExistenceKeyMismatch();
    error NonExistenceMissingNeighbour();
    error LeftNeighbourRootMismatch();
    error LeftNeighbourNotBeforeKey();
    error RightNeighbourRootMismatch();
    error RightNeighbourNotAfterKey();
    error RightNeighbourNotLeftMost();
    error LeftNeighbourNotRightMost();
    error LeavesNotNeighbours();
    error EmptyKey();
    error EmptyValue();
    error PathContainsLeafOp();
    error LeafPrefixMismatch();
    error LeafOpSpecMismatch();
    error HashOpNotSha256();
    error PrefixCollidesWithLeaf();
    error InvalidPrefixLength();
    error InvalidSuffixLength();
    error MissingStateProof();
    /// @dev A manifest storage proof and its preimage must be supplied together (both or neither).
    error ManifestProofPairMismatch();
    error MissingBundleContent();
    error MissingValidatorSet();
    error MissingLedgerConfig();
    error InvalidProposerAddressLength();
    error InvalidEd25519KeyLength();
    error OnlyExistenceProofsSupported();
    error UnsupportedProofType();
    error Load32OutOfBounds();

    /// @dev Injected Ed25519 verifier used to check CometBFT commit signatures.
    IEd25519Verifier public immutable ED25519;

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address ed25519Verifier) {
        if (ed25519Verifier == address(0)) revert ZeroEd25519Verifier();
        ED25519 = IEd25519Verifier(ed25519Verifier);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier: verifyBundle
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes is a protobuf-encoded ClprSeiBundlePayload.
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
        (string memory anchorChainId, CometBftLib.SeiValidator[] memory validators) = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes20 serviceAddr = _toBytes20(ctx.remoteServiceAddress);

        // ── Parse bundle payload ──────────────────────────────────────────────
        bytes memory proofMem = proofBytes;
        BundlePayload memory payload = _parseBundlePayload(proofMem);
        bytes memory nextValidatorSetBytes = payload.nextValidatorSet;

        // ── Verify state proof ────────────────────────────────────────────────
        // Every proven slot must match the channel's real metadata layout — the relay cannot
        // substitute an unrelated (or another channel's) slot at any position.
        (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            ClprTypes.QueueMetadata memory parsedMetadata,
            bytes32 storeRoot
        ) = _verifyChannelStateProof(payload.stateProof, validators, serviceAddr, ctx.channelId);

        // ── Optional endpoint-manifest update ─────────────────────────────────
        // An IAVL proof of the peer service's manifest-commitment slot against the same storeRoot,
        // plus the committed manifest preimage. Absent → version 0 ("no update"; Step 1b skips it).
        newEndpointManifest = _verifySeiEndpointManifest(
            payload.manifestStorageProof, payload.manifestPreimage, storeRoot, serviceAddr, ctx.remoteServiceAddress
        );

        // chain-id and height checks
        if (keccak256(bytes(header.chainId)) != keccak256(bytes(anchorChainId))) revert ChainIdMismatch();

        // ── Trust-anchor rotation ─────────────────────────────────────────────
        bytes32 currentSetHash = CometBftLib.validatorSetHash(validators);
        if (nextValidatorSetBytes.length > 0) {
            CometBftLib.SeiValidator[] memory nextValidators = _parseValidatorSet(nextValidatorSetBytes);
            bytes32 nextSetHash = CometBftLib.validatorSetHash(nextValidators);
            if (nextSetHash != header.nextValidatorsHash) revert NextValidatorSetHashMismatch();
            newTrustAnchor = abi.encode(header.chainId, nextValidators);
            newTrustAnchorId = abi.encodePacked(sha256(newTrustAnchor));
        } else {
            if (currentSetHash != header.nextValidatorsHash) revert MissingNextValidatorSet();
            newTrustAnchor = new bytes(0);
            newTrustAnchorId = new bytes(0);
        }

        // ── Decode queue metadata ─────────────────────────────────────────────
        // The proven slot values are laid out as the five Channel slots (indices 0..4) followed by
        // the optional last-message running-hash slot; `_buildQueueMetadata` reads exactly indices 0..4.
        if (slotValues.length < STORAGE_PROOF_MIN_ENTRIES || slotValues.length > STORAGE_PROOF_EXPECTED_ENTRIES) {
            revert StorageProofFailed();
        }
        metadata = parsedMetadata;

        // ── Bundle content ────────────────────────────────────────────────────
        messagePayloads = _decodeBundleContent(payload.bundleContent);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier: verifyConfig
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is a protobuf-encoded ClprSeiLedgerConfigurationPayload.
    ///      If empty, returns the genesis trust anchor (bootstrapping mode).
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

        bytes memory proofMem = configProofBytes;
        (bytes memory validatorSetBytes, bytes memory ledgerConfigBytes, bytes memory stateProofBytes) =
            _parseConfigPayload(proofMem);

        // Parse ledger configuration fields (protobuf LedgerConfiguration)
        (, bytes20 lServiceAddr, uint96 lConfigNanos, ClprTypes.Throttles memory lThrottles,) =
            _parseLedgerConfiguration(ledgerConfigBytes);

        CometBftLib.SeiValidator[] memory validators = _parseValidatorSet(validatorSetBytes);

        // Verify state proof — must contain exactly 1 storage slot (service_address slot, a
        // fixed contract-level variable, not one of the channelId-derived Channel slots).
        // Uses the channel-agnostic primitive directly (not {_verifyChannelStateProof}): this
        // proof carries no channelId-derived expected slot number at all; the service-address
        // slot is validated separately below by its expected *value*.
        //
        // Multi-service model: the state proof is anchored at the service address the config proof
        // itself declares (`lServiceAddr`), so one verifier instance can bootstrap channels to
        // any peer CLPR service. Peer identity is authenticated at the ClprService channel layer
        // (operator pubKey commitment/reveal), not pinned here. This call still enforces full proof
        // integrity — real CometBFT consensus, commit-signature quorum, and ICS-23/IAVL membership —
        // and the slot-value check below confirms the anchored contract self-declares `lServiceAddr`.
        (CometBftLib.SeiHeader memory header, bytes32[] memory slotValues,, bytes32 storeRoot) =
            _verifyStateProof(stateProofBytes, validators, lServiceAddr);

        if (slotValues.length != 1) revert InvalidStorageProofCount();

        // Verify the service_address storage slot encoding:
        // Short-bytes(20) Solidity layout: [addr 20B left-aligned][zeros 11B][length*2 = 0x28]
        bytes32 expectedSlot;
        assembly {
            // store address in top 20 bytes, then 0x28 in last byte
            expectedSlot := or(shl(96, lServiceAddr), 0x28)
        }
        if (slotValues[0] != expectedSlot) revert ServiceAddressSlotMismatch();

        bytes memory anchor = abi.encode(header.chainId, validators);
        bytes32 anchorId = sha256(anchor);
        serviceAddress = abi.encodePacked(lServiceAddr);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );

        return (
            channelContext,
            header.chainId,
            serviceAddress,
            lConfigNanos,
            lThrottles,
            anchor,
            abi.encodePacked(anchorId),
            // Verify the manifest commitment-slot proof (when supplied) against the same storeRoot
            // the config's state proof authenticates; empty proof → uninitialized (version 0)
            // manifest for bring-up.
            _verifyConfigEndpointManifest(endpointManifestProofBytes, storeRoot, lServiceAddr, serviceAddress)
        );
    }

    /// @dev Config-time manifest proof: protobuf `[field1 = StorageProofEntry, field2 = preimage]`
    ///      verified against the config state proof's `storeRoot`. Empty input returns the
    ///      UNINITIALIZED (version 0) manifest (bring-up; see {_uninitializedEndpointManifest}).
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory) {
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
            if (fn_ == 1 && wt == 2) {
                (entry, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                (preimage, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        return _verifySeiEndpointManifest(entry, preimage, storeRoot, serviceAddr, expectedServiceAddress);
    }

    /// @dev Verify an IAVL existence proof of the peer service's manifest-commitment slot
    ///      (key `0x03 || serviceAddr || ENDPOINT_MANIFEST_COMMITMENT_SLOT`, full-key match) against
    ///      `storeRoot`, bind `preimage` to the proven commitment (keccak256), then decode and bind
    ///      the manifest (version >= 1; service_address must match `expectedServiceAddress`).
    ///      Both inputs empty → the absent (version 0) manifest.
    function _verifySeiEndpointManifest(
        bytes memory entryBytes,
        bytes memory preimage,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory manifest) {
        if (entryBytes.length == 0 && preimage.length == 0) {
            return _absentEndpointManifest();
        }
        if (entryBytes.length == 0 || preimage.length == 0) revert ManifestProofPairMismatch();

        (bytes memory spKey, bytes memory spValue, bytes memory iavlProofBytes) = _parseStorageProofEntry(entryBytes);

        // Full-key check: prefix, service address, AND the exact commitment slot number.
        bytes memory expectedKey =
            abi.encodePacked(bytes1(EVM_STATE_KEY_PREFIX), serviceAddr, bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT));
        if (keccak256(spKey) != keccak256(expectedKey)) revert StorageKeyMismatch();
        if (spValue.length != 32) revert InvalidStorageValueLength();

        (bool isExistence, Ics23Lib.ExistenceProof memory iavlProof,) = _parseCommitmentProof(iavlProofBytes);
        if (!isExistence) revert OnlyExistenceProofsSupported();
        Ics23Lib.verifyMembershipIavl(iavlProof, storeRoot, spKey, spValue);

        if (keccak256(preimage) != _load32(spValue, 0)) revert ManifestCommitmentMismatch();

        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (
            expectedServiceAddress.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)
        ) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Core state proof verification
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Runs the full 5-step CometBFT state proof verification for `serviceAddr`'s storage.
    ///      Channel-agnostic: verifies that every entry in the proof authenticates SOME storage
    ///      slot of `serviceAddr` (correct prefix/length/address), and returns each slot's proven
    ///      number and value — it has no notion of what those slots mean.
    ///      `verifyConfig` (which proves an unrelated, channelId-independent `service_address`
    ///      slot) calls this primitive directly and checks the proven *value* itself.
    function _verifyStateProof(
        bytes memory stateProofBytes,
        CometBftLib.SeiValidator[] memory trustedValidators,
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
        // Parse state proof proto
        (
            bytes memory signedHeaderBytes,
            bytes memory storeKeyBytes,
            bytes memory multistoreProofBytes,
            bytes[] memory storageProofEntries
        ) = _parseStateProof(stateProofBytes);

        // Parse signed header
        CometBftLib.SeiCommit memory commit;
        (header, commit) = _parseSignedHeader(signedHeaderBytes);

        // Step 1: validator set hash
        bytes32 validatorSetHash = CometBftLib.validatorSetHash(trustedValidators);
        if (validatorSetHash != header.validatorsHash) revert ValidatorSetHashMismatch();

        // Step 2: header hash
        bytes32 headerHash = CometBftLib.headerHash(header);

        // Step 3: verify commit (>2/3 voting power, all Ed25519 sigs)
        _verifyCommit(commit, headerHash, header, trustedValidators);

        // Step 4: multistore proof (ICS-23 Tendermint spec): "evm" -> storeRoot, root = app_hash
        if (keccak256(storeKeyBytes) != keccak256(abi.encodePacked(EXPECTED_STORE_KEY))) {
            revert InvalidStoreKey();
        }
        (Ics23Lib.ExistenceProof memory multistoreProof) = _parseExistenceProof(multistoreProofBytes);
        if (keccak256(multistoreProof.key) != keccak256(storeKeyBytes)) revert InvalidStoreKey();
        Ics23Lib.verifyMembershipTendermint(multistoreProof, header.appHash, storeKeyBytes, multistoreProof.value);
        storeRoot = _load32(multistoreProof.value, 0);

        // Step 5: one IAVL proof per storage slot
        (slotValues, slotNumbers) = _verifyStorageSlotEntries(storageProofEntries, storeRoot, serviceAddr);
    }

    /// @dev Step 5 of {_verifyStateProof}: verify one IAVL proof per storage entry against
    ///      `storeRoot` and return each entry's proven slot number and value.
    function _verifyStorageSlotEntries(bytes[] memory storageProofEntries, bytes32 storeRoot, bytes20 serviceAddr)
        private
        pure
        returns (bytes32[] memory slotValues, bytes32[] memory slotNumbers)
    {
        uint256 storageProofEntriesLength = storageProofEntries.length;
        slotValues = new bytes32[](storageProofEntriesLength);
        slotNumbers = new bytes32[](storageProofEntriesLength);

        for (uint256 i = 0; i < storageProofEntriesLength;) {
            (bytes memory spKey, bytes memory spValue, bytes memory iavlProofBytes) =
                _parseStorageProofEntry(storageProofEntries[i]);

            // key = 0x03 || serviceAddr(20) || slot(32)
            if (
                spKey.length != 53 || uint8(spKey[0]) != EVM_STATE_KEY_PREFIX || !_addressMatches(spKey, 1, serviceAddr)
            ) {
                revert StorageKeyMismatch();
            }
            slotNumbers[i] = _load32(spKey, 21);

            // A zero EVM storage slot is deleted from Sei's IAVL tree, so the ABCI query returns an
            // ICS-23 non-existence proof (and an empty value) rather than a 32-byte word. Branch on
            // the CommitmentProof type: existence → prove the 32-byte value; non-existence → prove
            // the key is absent and treat the slot as zero.
            (
                bool isExistence,
                Ics23Lib.ExistenceProof memory iavlProof,
                Ics23Lib.NonExistenceProof memory iavlNonProof
            ) = _parseCommitmentProof(iavlProofBytes);
            if (isExistence) {
                if (spValue.length != 32) revert InvalidStorageValueLength();
                Ics23Lib.verifyMembershipIavl(iavlProof, storeRoot, spKey, spValue);
                slotValues[i] = _load32(spValue, 0);
            } else {
                if (spValue.length != 0) revert NonExistenceSlotNotEmpty();
                Ics23Lib.verifyNonMembershipIavl(iavlNonProof, storeRoot, spKey);
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Wraps {_verifyStateProof} for the `verifyBundle` path: binds every proven slot to
    ///      `channelId`'s real metadata layout — indices 0..3 must match
    ///      `_channelMetadataSlots(channelId)`, and any slot beyond index 3 must match the
    ///      derived last-message running-hash slot — so a relay cannot substitute an unrelated or
    ///      foreign-channel slot at any position, then decodes indices 0..3 into `metadata`.
    ///      Kept separate from the channel-agnostic primitive so callers with no channel
    ///      semantics (`verifyConfig`) never carry this logic.
    function _verifyChannelStateProof(
        bytes memory stateProofBytes,
        CometBftLib.SeiValidator[] memory trustedValidators,
        bytes20 serviceAddr,
        bytes32 channelId
    )
        internal
        view
        returns (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            ClprTypes.QueueMetadata memory metadata,
            bytes32 storeRoot
        )
    {
        bytes32[] memory slotNumbers;
        (header, slotValues, slotNumbers, storeRoot) =
            _verifyStateProof(stateProofBytes, trustedValidators, serviceAddr);
        metadata = _bindChannelSlots(slotNumbers, slotValues, channelId);
    }

    /// @dev The slot-binding half of {_verifyChannelStateProof}: every proven slot number must
    ///      match the channel's real metadata layout, then the values decode into `metadata`
    ///      (the message running-hash slot is derived from the proven nextMessageId - 1; the
    ///      bundle-scoped ackedMessageId + payloadCount form was reverted on main by #379).
    function _bindChannelSlots(bytes32[] memory slotNumbers, bytes32[] memory slotValues, bytes32 channelId)
        private
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        bytes32[] memory channelSlots = _channelMetadataSlots(channelId);
        uint256 slotCount = slotNumbers.length;

        // Indices 0..3 (or however many entries are present, if fewer — the caller rejects a
        // too-short proof separately) must match this channel's real Channel-struct slots.
        for (uint256 i = 0; i < slotCount && i < channelSlots.length; i++) {
            if (slotNumbers[i] != channelSlots[i]) revert StorageKeyMismatch();
        }

        // Once all four Channel slots are present, decode `metadata` so it's ready both as the
        // return value and to derive the optional 5th-and-beyond entry's expected slot below.
        if (slotCount >= channelSlots.length) {
            metadata = _buildQueueMetadata(slotValues);
        }
        // A 5th-and-beyond entry claims to prove the *last sent* message's running hash, which only
        // exists once nextMessageId > 0 (per the CLPR spec, a channel's nextMessageId starts at 1
        // and only increments — 0 means no message was ever sent, so no last-message slot exists to
        // derive). Guard explicitly instead of letting `nextMessageId - 1` underflow into an opaque
        // panic: the proof is invalid either way, but this keeps the revert reason consistent with
        // every other proof-shape check in this function.
        // TODO(clpr-spec#50): switch to bundle-scoped bundleLastMessageId = ackedMessageId + payloadCount
        //                     once spec PR #50 is merged.
        if (slotCount > channelSlots.length && metadata.nextMessageId == 0) revert StorageKeyMismatch();
        for (uint256 i = channelSlots.length; i < slotCount; i++) {
            bytes32 expectedSlot = _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1));
            if (slotNumbers[i] != expectedSlot) revert StorageKeyMismatch();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   CometBFT commit verification
    // ─────────────────────────────────────────────────────────────────────────

    function _verifyCommit(
        CometBftLib.SeiCommit memory commit,
        bytes32 headerHash,
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiValidator[] memory validators
    ) internal view {
        uint256 n = validators.length;
        uint256 expectedBitBytes = (n + 7) / 8;
        if (commit.signersBits.length != expectedBitBytes) revert InvalidSignersBitsLength();

        // Check padding bits beyond n are zero
        for (uint256 bit = n; bit < commit.signersBits.length * 8; bit++) {
            if (_bitSet(commit.signersBits, bit)) revert SignersBitOutOfRange();
        }

        bytes memory prefix;
        bytes memory suffix;
        {
            bytes memory partSetHeader = abi.encodePacked(
                CometBftLib.pbVarintField(1, commit.partSetTotal),
                CometBftLib.pbBytesField(2, abi.encodePacked(commit.partSetHash))
            );
            bytes memory canonicalBlockId = bytes.concat(
                CometBftLib.pbBytesField(1, abi.encodePacked(headerHash)), CometBftLib.pbMessageField(2, partSetHeader)
            );
            prefix = abi.encodePacked(
                CometBftLib.pbVarintField(1, PRECOMMIT_TYPE),
                header.height != 0
                    ? abi.encodePacked(CometBftLib.pbTag(2, 1), CometBftLib.sfixed64LE(header.height))
                    : bytes(""),
                commit.round != 0
                    ? abi.encodePacked(CometBftLib.pbTag(3, 1), CometBftLib.sfixed64LE(commit.round))
                    : bytes(""),
                CometBftLib.pbMessageField(4, canonicalBlockId)
            );
            suffix = CometBftLib.pbBytesField(6, bytes(header.chainId));
        }

        // Pre-pass: total power over the FULL trusted set (the quorum denominator — never shrunk by
        // the bits) and the bits↔signatures shape check, both before any Ed25519 work.
        int128 totalPower;
        uint256 setBits;
        for (uint256 vi = 0; vi < n; vi++) {
            totalPower += int128(validators[vi].votingPower);
            if (_bitSet(commit.signersBits, vi)) setBits++;
        }
        if (commit.signatures.length < setBits) revert TooFewSignatures();
        if (commit.signatures.length > setBits) revert ExtraSignatures();

        // Verify signatures in validator order, stopping as soon as the >2/3 quorum is met — each
        // Ed25519 check costs ~600K gas, and power beyond the quorum adds no security.
        // Signatures positioned after the quorum point are NEVER verified, so an
        // invalid signature there does not revert. CometBFT orders validator sets by descending
        // voting power, so index order ≈ optimal order and the exit comes as early as possible.
        int128 signedPower;
        uint256 sigIdx;
        for (uint256 vi = 0; vi < n; vi++) {
            if (signedPower * 3 > totalPower * 2) break; // quorum met - ignore the rest
            if (!_bitSet(commit.signersBits, vi)) continue;

            CometBftLib.CommitSig memory sig = commit.signatures[sigIdx++];

            // Build precommit sign bytes
            // The precommit votes on THIS block, so block_id.hash is the proven header hash
            // (the #180 SeiCommit proto carries no block_id; it is derived here).
            bytes memory signBytes =
                CometBftLib.precommitSignBytesHoisted(prefix, suffix, sig.timestampSeconds, sig.timestampNanos);

            if (!_verifyEd25519(validators[vi].ed25519PubKey, signBytes, sig.signature)) {
                revert InvalidSignature();
            }

            signedPower += int128(validators[vi].votingPower);
        }

        // signedPower * 3 > totalPower * 2
        if (signedPower * 3 <= totalPower * 2) revert QuorumNotMet();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Protobuf parsing — state proof, signed header, commit, storage entries
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Parsed ClprSeiBundlePayload fields (see the contract-level proof-encoding doc).
    struct BundlePayload {
        bytes stateProof;
        bytes bundleContent;
        bytes nextValidatorSet;
        bytes manifestStorageProof;
        bytes manifestPreimage;
    }

    /// @dev Parses ClprSeiBundlePayload proto fields.
    function _parseBundlePayload(bytes memory data) internal pure returns (BundlePayload memory p) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                (p.stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                (p.bundleContent, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 2) {
                (p.nextValidatorSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4 && wt == 2) {
                (p.manifestStorageProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 5 && wt == 2) {
                (p.manifestPreimage, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (p.stateProof.length == 0) revert MissingStateProof();
        if (p.bundleContent.length == 0) revert MissingBundleContent();
    }

    /// @dev Parses ClprSeiLedgerConfigurationPayload proto fields.
    function _parseConfigPayload(bytes memory data)
        internal
        pure
        returns (bytes memory validatorSet, bytes memory ledgerConfig, bytes memory stateProof)
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                (validatorSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                (ledgerConfig, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 2) {
                (stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (validatorSet.length == 0) revert MissingValidatorSet();
        if (ledgerConfig.length == 0) revert MissingLedgerConfig();
        if (stateProof.length == 0) revert MissingStateProof();
    }

    /// @dev Parses SeiStateProof proto fields.
    function _parseStateProof(bytes memory data)
        internal
        pure
        returns (
            bytes memory signedHeader,
            bytes memory storeKey,
            bytes memory multistoreProof,
            bytes[] memory storageProofEntries
        )
    {
        return CometBftProofCodec.parseStateProof(data);
    }

    /// @dev Parses SeiSignedHeader proto: returns header and commit.
    function _parseSignedHeader(bytes memory data)
        internal
        pure
        returns (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit)
    {
        return CometBftProofCodec.parseSignedHeader(data);
    }

    /// @dev Parses SeiHeader proto.
    function _parseHeader(bytes memory data) internal pure returns (CometBftLib.SeiHeader memory h) {
        return CometBftProofCodec.parseHeader(data);
    }

    function _parseTimestamp(bytes memory data) internal pure returns (int64 seconds_, int32 nanos_) {
        return CometBftProofCodec.parseTimestamp(data);
    }

    function _parseBlockId(bytes memory data)
        internal
        pure
        returns (bytes32 hash_, uint32 partTotal_, bytes32 partHash_)
    {
        return CometBftProofCodec.parseBlockId(data);
    }

    function _parsePartSetHeader(bytes memory data) internal pure returns (uint32 total_, bytes32 hash_) {
        return CometBftProofCodec.parsePartSetHeader(data);
    }

    /// @dev Parses SeiCommit proto.
    function _parseCommit(bytes memory data) internal pure returns (CometBftLib.SeiCommit memory c) {
        return CometBftProofCodec.parseCommit(data);
    }

    function _parseCommitSig(bytes memory data) internal pure returns (CometBftLib.CommitSig memory sig) {
        return CometBftProofCodec.parseCommitSig(data);
    }

    /// @dev Parses SeiValidatorSet proto → CometBftLib.SeiValidator[].
    function _parseValidatorSet(bytes memory data)
        internal
        pure
        returns (CometBftLib.SeiValidator[] memory validators)
    {
        // Count validators (field 1, repeated)
        uint256 n;
        {
            uint256 cOff;
            while (cOff < data.length) {
                (uint64 fn_, uint8 wt, uint256 cOff2) = PB.decodeFieldKey(data, cOff);
                cOff = cOff2;
                if (fn_ == 1 && wt == 2) n++;
                cOff = PB.skipField(data, cOff, wt);
            }
        }
        validators = new CometBftLib.SeiValidator[](n);
        uint256 idx;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                bytes memory eb;
                (eb, off) = PB.decodeLengthDelimited(data, off);
                validators[idx++] = _parseValidatorEntry(eb);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function _parseValidatorEntry(bytes memory data) internal pure returns (CometBftLib.SeiValidator memory v) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                // ed25519_pub_key: bytes
                bytes memory kb;
                (kb, off) = PB.decodeLengthDelimited(data, off);
                if (kb.length != 32) revert InvalidEd25519KeyLength();
                v.ed25519PubKey = _load32(kb, 0);
            } else if (fn_ == 2 && wt == 0) {
                uint64 vp;
                (vp, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                v.votingPower = int64(vp);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev Parses SeiStorageProofEntry proto.
    function _parseStorageProofEntry(bytes memory data)
        internal
        pure
        returns (bytes memory key, bytes memory value, bytes memory iavlProof)
    {
        return CometBftProofCodec.parseStorageProofEntry(data);
    }

    /// @dev Parses ClprLedgerConfiguration proto.
    function _parseLedgerConfiguration(bytes memory data)
        internal
        pure
        returns (
            string memory chainId,
            bytes20 serviceAddr,
            uint96 configNanos,
            ClprTypes.Throttles memory throttles,
            ClprTypes.Endpoint[] memory endpoints
        )
    {
        return CometBftProofCodec.parseLedgerConfiguration(data);
    }

    function _parseThrottles(bytes memory data) internal pure returns (ClprTypes.Throttles memory t) {
        return CometBftProofCodec.parseThrottles(data);
    }

    /// @dev Parses ICS-23 CommitmentProof (existence proof only).
    function _parseExistenceProof(bytes memory data) internal pure returns (Ics23Lib.ExistenceProof memory proof) {
        return CometBftProofCodec.parseExistenceProof(data);
    }

    /// @dev Parses an ICS-23 CommitmentProof, distinguishing existence (field 1) from
    ///      non-existence (field 2). Batch/compressed proofs are unsupported.
    function _parseCommitmentProof(bytes memory data)
        internal
        pure
        returns (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep)
    {
        return CometBftProofCodec.parseCommitmentProof(data);
    }

    function _parseNonExistenceProof(bytes memory data) internal pure returns (Ics23Lib.NonExistenceProof memory nep) {
        return CometBftProofCodec.parseNonExistenceProof(data);
    }

    function _parseExistenceProofInner(bytes memory data) internal pure returns (Ics23Lib.ExistenceProof memory proof) {
        return CometBftProofCodec.parseExistenceProofInner(data);
    }

    function _parseLeafOp(bytes memory data) internal pure returns (Ics23Lib.LeafOp memory leaf) {
        return CometBftProofCodec.parseLeafOp(data);
    }

    function _parseInnerOp(bytes memory data) internal pure returns (Ics23Lib.InnerOp memory op) {
        return CometBftProofCodec.parseInnerOp(data);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Trust anchor
    // ─────────────────────────────────────────────────────────────────────────

    function _decodeTrustAnchor(bytes calldata anchor)
        internal
        pure
        returns (string memory chainId, CometBftLib.SeiValidator[] memory validators)
    {
        if (anchor.length == 0) revert InvalidTrustAnchor();
        (chainId, validators) = abi.decode(anchor, (string, CometBftLib.SeiValidator[]));
        if (validators.length == 0) revert InvalidTrustAnchor();
    }

    /// @dev Converts an opaque service-address byte string (from ChannelContext) to bytes20.
    function _toBytes20(bytes memory b) internal pure returns (bytes20 addr) {
        if (b.length != 20) revert InvalidServiceAddressLength();
        assembly {
            addr := mload(add(b, 32))
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Ed25519 signature verification (injected IEd25519Verifier)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Delegates to the injected {IEd25519Verifier}. Virtual so test harnesses can override
    ///      to bypass the external call.
    function _verifyEd25519(bytes32 pubKey, bytes memory message, bytes memory sig)
        internal
        view
        virtual
        returns (bool)
    {
        if (sig.length != 64) return false;
        return ED25519.verify(pubKey, message, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Utility helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _bitSet(bytes memory bits, uint256 idx) internal pure returns (bool) {
        uint256 mask = 0x80;
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(bits[idx / 8]) & uint8(mask >> (idx % 8)) != 0;
    }

    function _addressMatches(bytes memory key, uint256 offset, bytes20 addr) internal pure returns (bool) {
        for (uint256 i; i < 20; i++) {
            if (key[offset + i] != addr[i]) return false;
        }
        return true;
    }

    function _load32(bytes memory data, uint256 offset) internal pure returns (bytes32 result) {
        return CometBftProofCodec.load32(data, offset);
    }
}
