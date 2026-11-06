// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprTempoCertificate} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoCertificate.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title TempoVerifier
/// @notice Verifier for bundles from a Tempo chain. A Tempo block is final when one BLS threshold
///         signature over its hash exists. The verifier checks that signature against the epoch
///         group key, then proves the peer service storage with the shared Merkle-Patricia tail.
/// @dev The key changes only at a full DKG. The last block of an epoch names the next key in its
///      `extraData`. The relay crosses each key change with a rotation: that block, its certificate,
///      and the next key uncompressed. See tempo-verifier.md.
contract TempoVerifier is ClprEvmBundleVerifier {
    /**
     * Bundle proof: RLP list of 5 fields, or 7 with a manifest update.
     * [header, finalitySource, accountProof, storageProof, bundleContent, manifestProof?, manifestPreimage?]
     */
    uint8 internal constant PAYLOAD_SHAPE_EXPECTED_FIELDS = 5;
    uint8 internal constant PAYLOAD_SHAPE_WITH_MANIFEST = 7;
    uint8 internal constant PAYLOAD_CURRENT_BLOCK_HEADER_INDEX = 0;
    uint8 internal constant PAYLOAD_FINALITY_SOURCE_INDEX = 1;
    uint8 internal constant PAYLOAD_ACCOUNT_PROOF_INDEX = 2;
    uint8 internal constant PAYLOAD_STORAGE_PROOF_INDEX = 3;
    uint8 internal constant PAYLOAD_BUNDLE_CONTENT_INDEX = 4;
    uint8 internal constant PAYLOAD_MANIFEST_STORAGE_PROOF_INDEX = 5;
    uint8 internal constant PAYLOAD_MANIFEST_PREIMAGE_INDEX = 6;

    /// @dev Field 1: [proposal, sigCompressed, sigUncompressed, rotations[]].
    uint8 internal constant SOURCE_FIELDS = 4;
    uint8 internal constant SOURCE_PROPOSAL_INDEX = 0;
    uint8 internal constant SOURCE_SIG_COMPRESSED_INDEX = 1;
    uint8 internal constant SOURCE_SIG_UNCOMPRESSED_INDEX = 2;
    uint8 internal constant SOURCE_ROTATIONS_INDEX = 3;

    /// @dev A rotation: [boundaryHeader, proposal, sigCompressed, sigUncompressed, newKeyUncompressed].
    uint8 internal constant ROTATION_FIELDS = 5;
    uint8 internal constant ROTATION_NEW_KEY_INDEX = 4;

    /**
     * Tempo header: RLP([generalGasLimit, sharedGasLimit, timestampMillisPart, innerHeader, consensusContext?]).
     */
    uint8 internal constant TEMPO_HEADER_MIN_FIELDS = 4;
    uint8 internal constant TEMPO_HEADER_MAX_FIELDS = 5;
    uint8 internal constant TEMPO_HEADER_INNER_INDEX = 3;
    uint8 internal constant INNER_HEADER_MIN_FIELDS = 15;
    uint8 internal constant INNER_HEADER_STATE_ROOT_INDEX = 3;
    uint8 internal constant INNER_HEADER_NUMBER_INDEX = 8;
    uint8 internal constant INNER_HEADER_EXTRA_DATA_INDEX = 12;

    /**
     * Config proof: RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor, certificate, header]).
     */
    uint8 internal constant CONFIG_FIELDS = 7;
    uint8 internal constant CONFIG_SERVICE_ADDRESS_INDEX = 0;
    uint8 internal constant CONFIG_CHAIN_ID_INDEX = 1;
    uint8 internal constant CONFIG_PEER_NANOS_INDEX = 2;
    uint8 internal constant CONFIG_THROTTLES_INDEX = 3;
    uint8 internal constant CONFIG_DESCRIPTOR_INDEX = 4;
    uint8 internal constant CONFIG_CERTIFICATE_INDEX = 5;
    uint8 internal constant CONFIG_HEADER_INDEX = 6;
    uint8 internal constant DESCRIPTOR_FIELDS = 4;
    uint8 internal constant DESCRIPTOR_CODE_HASH_INDEX = 0;
    uint8 internal constant DESCRIPTOR_EPOCH_LENGTH_INDEX = 1;
    uint8 internal constant DESCRIPTOR_KEY_COMPRESSED_INDEX = 2;
    uint8 internal constant DESCRIPTOR_KEY_UNCOMPRESSED_INDEX = 3;
    uint8 internal constant CERTIFICATE_FIELDS = 3;

    /// @dev Config-time manifest proof: header, certificate items, account proof, manifest proof, preimage.
    uint8 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 7;

    /// @dev abi.encode(bytes32 codeHash, uint64 epochLength, uint64 anchorBlockNumber, bytes identity).
    uint256 internal constant ANCHOR_LENGTH = 416;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidProofPayloadShape();
    error InvalidHeader();
    error InvalidConfigThrottleFieldCount();
    error InvalidTrustAnchorFields();
    error InvalidEpochLength();
    error InvalidSignatureEncoding();
    error SignatureEncodingMismatch();
    error KeyEncodingMismatch();
    error InvalidKeyLength();
    error BlockDigestMismatch();
    error EpochMismatch(uint64 height, uint64 expected, uint64 actual);
    error HandoffHeaderNotAscending(uint64 got, uint64 lastSeen);
    /// @dev Thrown when a rotation's boundary header, at height `got`, is not the last block of an epoch.
    error RotationNotEpochBoundary(uint64 got);
    error OutcomeEpochMismatch(uint64 expected, uint64 actual);
    error CurrentHeaderBehindWalk(uint64 got, uint64 lastSeen);
    /// @dev Thrown when a key or signature is the point at infinity; an infinity key and signature verify any message.
    error InfinityPoint();

    struct TempoAnchor {
        bytes32 codeHash;
        uint64 epochLength;
        uint64 anchorBlockNumber;
        bytes identity;
    }

    /// @dev Result of a certificate check.
    struct CertifiedHeader {
        uint64 number;
        uint64 epoch;
        bytes32 stateRoot;
        Memory.Slice[] inner;
    }

    /// @dev The three certificate items.
    struct Certificate {
        Memory.Slice proposal;
        Memory.Slice sigCompressed;
        Memory.Slice sigUncompressed;
    }

    // ── verifyBundle ─────────────────────────────────────────────────────────

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
        TempoAnchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);

        Memory.Slice[] memory payload = RLP.decodeList(proofBytes);
        if (payload.length != PAYLOAD_SHAPE_EXPECTED_FIELDS && payload.length != PAYLOAD_SHAPE_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }
        Memory.Slice[] memory source = RLP.readList(payload[PAYLOAD_FINALITY_SOURCE_INDEX]);
        if (source.length != SOURCE_FIELDS) revert InvalidPayloadShape();

        (bytes memory key, uint64 anchorBlockNumber, bool rotated) =
            _walkRotations(RLP.readList(source[SOURCE_ROTATIONS_INDEX]), anchor);

        CertifiedHeader memory current = _verifyCertifiedHeader(
            payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX],
            Certificate({
                proposal: source[SOURCE_PROPOSAL_INDEX],
                sigCompressed: source[SOURCE_SIG_COMPRESSED_INDEX],
                sigUncompressed: source[SOURCE_SIG_UNCOMPRESSED_INDEX]
            }),
            key,
            anchor.epochLength
        );
        if (current.number <= anchorBlockNumber) revert CurrentHeaderBehindWalk(current.number, anchorBlockNumber);

        (metadata, messagePayloads, newEndpointManifest) =
            _verifyStorageAndContent(payload, ctx, current.stateRoot, anchor.codeHash);

        if (rotated) {
            newTrustAnchor = _encodeAnchor(anchor.codeHash, anchor.epochLength, current.number, key);
            newTrustAnchorId = abi.encodePacked(current.number);
        }
    }

    /// @dev Each rotation is an epoch-boundary block, certified under the key it replaces, that names the
    ///      next key. Returns the final key and the block it is anchored at: the last rotation, or the
    ///      anchor block when there is none. `rotated` is true only when the final key differs from the
    ///      anchor key.
    function _walkRotations(Memory.Slice[] memory rotations, TempoAnchor memory anchor)
        internal
        view
        returns (bytes memory key, uint64 anchorBlockNumber, bool rotated)
    {
        key = anchor.identity;
        anchorBlockNumber = anchor.anchorBlockNumber;
        for (uint256 i = 0; i < rotations.length;) {
            Memory.Slice[] memory rotation = RLP.readList(rotations[i]);
            if (rotation.length != ROTATION_FIELDS) revert InvalidPayloadShape();
            CertifiedHeader memory boundary = _verifyCertifiedHeader(
                rotation[0],
                Certificate({proposal: rotation[1], sigCompressed: rotation[2], sigUncompressed: rotation[3]}),
                key,
                anchor.epochLength
            );
            // The anchor key certified the anchor block, so the first rotation can be that block.
            if (boundary.number < anchorBlockNumber || (i != 0 && boundary.number == anchorBlockNumber)) {
                revert HandoffHeaderNotAscending(boundary.number, anchorBlockNumber);
            }
            if ((boundary.number + 1) % anchor.epochLength != 0) revert RotationNotEpochBoundary(boundary.number);

            (uint64 outcomeEpoch, bytes memory committedKey) =
                ClprTempoCertificate.dkgOutcomeKey(RLP.readBytes(boundary.inner[INNER_HEADER_EXTRA_DATA_INDEX]));
            if (outcomeEpoch != boundary.epoch + 1) revert OutcomeEpochMismatch(boundary.epoch + 1, outcomeEpoch);

            bytes memory newKey = RLP.readBytes(rotation[ROTATION_NEW_KEY_INDEX]);
            _requireKeyBinding(newKey, committedKey);
            key = newKey;
            anchorBlockNumber = boundary.number;
            unchecked {
                i++;
            }
        }
        rotated = rotations.length != 0 && keccak256(key) != keccak256(anchor.identity);
    }

    /// @dev Decode a Tempo header and check its certificate under `key`.
    function _verifyCertifiedHeader(
        Memory.Slice headerItem,
        Certificate memory cert,
        bytes memory key,
        uint64 epochLength
    ) internal view returns (CertifiedHeader memory h) {
        bytes32 hash;
        (h.inner, hash) = _decodeTempoHeader(headerItem);
        h.stateRoot = RLP.readBytes32(h.inner[INNER_HEADER_STATE_ROOT_INDEX]);
        // Block numbers fit in 64 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        h.number = uint64(RLP.readUint256(h.inner[INNER_HEADER_NUMBER_INDEX]));

        bytes memory proposalBytes = RLP.readBytes(cert.proposal);
        ClprTempoCertificate.Proposal memory proposal = ClprTempoCertificate.parseProposal(proposalBytes);
        if (proposal.payload != hash) revert BlockDigestMismatch();
        uint64 expectedEpoch = h.number / epochLength;
        if (proposal.epoch != expectedEpoch) revert EpochMismatch(h.number, expectedEpoch, proposal.epoch);
        h.epoch = proposal.epoch;

        bytes memory sigUncompressed = _boundSignature(cert);
        ClprTempoBls.verifyMinSig(sigUncompressed, ClprTempoCertificate.finalizeMessage(proposalBytes), key);
    }

    /// @dev The uncompressed signature must compress to the 48 bytes from the certificate.
    function _boundSignature(Certificate memory cert) internal pure returns (bytes memory sigUncompressed) {
        bytes memory sigCompressed = RLP.readBytes(cert.sigCompressed);
        sigUncompressed = RLP.readBytes(cert.sigUncompressed);
        if (
            sigCompressed.length != ClprBls12381.G1_COMPRESSED_LENGTH
                || sigUncompressed.length != ClprBls12381.G1_POINT_LENGTH
        ) revert InvalidSignatureEncoding();
        if ((uint8(sigCompressed[0]) & ClprBls12381.FLAG_INFINITY) != 0) revert InfinityPoint();
        if (keccak256(ClprBls12381.compressG1(sigUncompressed)) != keccak256(sigCompressed)) {
            revert SignatureEncodingMismatch();
        }
    }

    /// @dev The uncompressed key must compress to the committed 96 bytes.
    function _requireKeyBinding(bytes memory keyUncompressed, bytes memory keyCompressed) internal pure {
        if (
            keyUncompressed.length != ClprBls12381.G2_POINT_LENGTH
                || keyCompressed.length != ClprBls12381.G2_COMPRESSED_LENGTH
        ) revert InvalidKeyLength();
        if ((uint8(keyCompressed[0]) & ClprBls12381.FLAG_INFINITY) != 0) revert InfinityPoint();
        if (keccak256(ClprBls12381.compressG2(keyUncompressed)) != keccak256(keyCompressed)) {
            revert KeyEncodingMismatch();
        }
    }

    /// @dev Outer list of 4 or 5 items, Ethereum header at index 3. The block hash is the keccak of
    ///      the outer list.
    function _decodeTempoHeader(Memory.Slice headerItem)
        internal
        pure
        returns (Memory.Slice[] memory inner, bytes32 hash)
    {
        Memory.Slice[] memory outer = RLP.readList(headerItem);
        if (outer.length < TEMPO_HEADER_MIN_FIELDS || outer.length > TEMPO_HEADER_MAX_FIELDS) revert InvalidHeader();
        inner = RLP.readList(outer[TEMPO_HEADER_INNER_INDEX]);
        if (inner.length < INNER_HEADER_MIN_FIELDS) revert InvalidHeader();
        (uint256 ptr, uint256 end) = RlpCursor.bounds(headerItem);
        hash = RlpCursor.keccakOf(ptr, end - ptr);
    }

    /// @dev The shared EVM tail: service account, channel slots, bundle content, optional manifest.
    function _verifyStorageAndContent(
        Memory.Slice[] memory payload,
        ClprTypes.ChannelContext memory ctx,
        bytes32 stateRoot,
        bytes32 codeHash
    )
        internal
        pure
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        bytes32 storageRoot = _verifyServiceStorageRoot(
            payload[PAYLOAD_ACCOUNT_PROOF_INDEX], stateRoot, _toAddress(ctx.remoteServiceAddress), codeHash
        );
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[PAYLOAD_BUNDLE_CONTENT_INDEX]));
        metadata = _verifyChannelStorage(
            payload[PAYLOAD_STORAGE_PROOF_INDEX], storageRoot, ctx.channelId, messagePayloads.length
        );
        if (payload.length == PAYLOAD_SHAPE_WITH_MANIFEST) {
            newEndpointManifest = _verifyEndpointManifest(
                payload[PAYLOAD_MANIFEST_STORAGE_PROOF_INDEX],
                storageRoot,
                RLP.readBytes(payload[PAYLOAD_MANIFEST_PREIMAGE_INDEX]),
                ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev The declared key is trust-on-first-use. Its certificate must finalize the config header.
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
        Memory.Slice[] memory proof = RLP.decodeList(configProofBytes);
        if (proof.length != CONFIG_FIELDS) revert InvalidProofPayloadShape();

        throttles = _decodeConfigThrottles(RLP.readList(proof[CONFIG_THROTTLES_INDEX]));
        serviceAddress = RLP.readBytes(proof[CONFIG_SERVICE_ADDRESS_INDEX]);
        if (serviceAddress.length != 20) revert InvalidServiceAddressLength();

        TempoAnchor memory anchor = _configAnchor(proof);
        initialTrustAnchor =
            _encodeAnchor(anchor.codeHash, anchor.epochLength, anchor.anchorBlockNumber, anchor.identity);
        initialTrustAnchorId = abi.encodePacked(anchor.anchorBlockNumber);

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, anchor, serviceAddress);
        return (
            channelContext,
            string(RLP.readBytes(proof[CONFIG_CHAIN_ID_INDEX])),
            serviceAddress,
            uint96(RLP.readUint256(proof[CONFIG_PEER_NANOS_INDEX])),
            throttles,
            initialTrustAnchor,
            initialTrustAnchorId,
            endpointManifest
        );
    }

    /// @dev Descriptor: [codeHash, epochLength, identityCompressed, identityUncompressed].
    function _configAnchor(Memory.Slice[] memory proof) internal view returns (TempoAnchor memory anchor) {
        Memory.Slice[] memory d = RLP.decodeList(RLP.readBytes(proof[CONFIG_DESCRIPTOR_INDEX]));
        if (d.length != DESCRIPTOR_FIELDS) revert InvalidTrustAnchorFields();
        anchor.codeHash = RLP.readBytes32(d[DESCRIPTOR_CODE_HASH_INDEX]);
        uint256 epochLength = RLP.readUint256(d[DESCRIPTOR_EPOCH_LENGTH_INDEX]);
        if (epochLength < 2 || epochLength > type(uint64).max) revert InvalidEpochLength();
        // forge-lint: disable-next-line(unsafe-typecast)
        anchor.epochLength = uint64(epochLength);
        anchor.identity = RLP.readBytes(d[DESCRIPTOR_KEY_UNCOMPRESSED_INDEX]);
        _requireKeyBinding(anchor.identity, RLP.readBytes(d[DESCRIPTOR_KEY_COMPRESSED_INDEX]));

        CertifiedHeader memory h = _verifyCertifiedHeader(
            proof[CONFIG_HEADER_INDEX],
            _readCertificate(proof[CONFIG_CERTIFICATE_INDEX]),
            anchor.identity,
            anchor.epochLength
        );
        anchor.anchorBlockNumber = h.number;
    }

    /// @dev RLP([proposal, sigCompressed, sigUncompressed]).
    function _readCertificate(Memory.Slice item) internal pure returns (Certificate memory cert) {
        Memory.Slice[] memory c = RLP.readList(item);
        if (c.length != CERTIFICATE_FIELDS) revert InvalidProofPayloadShape();
        cert = Certificate({proposal: c[0], sigCompressed: c[1], sigUncompressed: c[2]});
    }

    /// @dev Empty bytes return the uninitialized manifest. Otherwise the shape is
    ///      RLP([header, proposal, sigCompressed, sigUncompressed, accountProof, manifestProof, preimage]).
    function _verifyConfigEndpointManifest(
        bytes calldata endpointManifestProofBytes,
        TempoAnchor memory anchor,
        bytes memory serviceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        if (endpointManifestProofBytes.length == 0) {
            return _uninitializedEndpointManifest(serviceAddress);
        }
        Memory.Slice[] memory p = RLP.decodeList(endpointManifestProofBytes);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidProofPayloadShape();

        CertifiedHeader memory h = _verifyCertifiedHeader(
            p[0],
            Certificate({proposal: p[1], sigCompressed: p[2], sigUncompressed: p[3]}),
            anchor.identity,
            anchor.epochLength
        );
        bytes32 storageRoot = _verifyServiceStorageRoot(p[4], h.stateRoot, _toAddress(serviceAddress), anchor.codeHash);
        return _verifyEndpointManifest(p[5], storageRoot, RLP.readBytes(p[6]), serviceAddress);
    }

    /// @dev Five throttles is the legacy shape. Seven adds the two endpoint limits.
    function _decodeConfigThrottles(Memory.Slice[] memory t)
        internal
        pure
        returns (ClprTypes.Throttles memory throttles)
    {
        if (t.length != 5 && t.length != 7) revert InvalidConfigThrottleFieldCount();
        uint32 maxLocal;
        uint32 maxPeer;
        if (t.length == 7) {
            // The endpoint limits are small caps.
            // forge-lint: disable-next-line(unsafe-typecast)
            maxLocal = uint32(RLP.readUint256(t[5]));
            // forge-lint: disable-next-line(unsafe-typecast)
            maxPeer = uint32(RLP.readUint256(t[6]));
        }
        throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: uint32(RLP.readUint256(t[0])),
            maxMessagePayloadBytes: uint64(RLP.readUint256(t[1])),
            maxGasPerMessage: uint64(RLP.readUint256(t[2])),
            maxQueueDepth: uint32(RLP.readUint256(t[3])),
            maxSyncBytes: uint64(RLP.readUint256(t[4])),
            maxLocalEndpoints: maxLocal,
            maxPeerEndpoints: maxPeer
        });
    }

    // ── Trust anchor codec ───────────────────────────────────────────────────

    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (TempoAnchor memory a) {
        if (trustAnchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (bytes32 codeHash, uint64 epochLength, uint64 anchorBlockNumber, bytes memory identity) =
            abi.decode(trustAnchor, (bytes32, uint64, uint64, bytes));
        if (identity.length != ClprBls12381.G2_POINT_LENGTH || epochLength < 2) revert InvalidTrustAnchor();
        a.codeHash = codeHash;
        a.epochLength = epochLength;
        a.anchorBlockNumber = anchorBlockNumber;
        a.identity = identity;
    }

    function _encodeAnchor(bytes32 codeHash, uint64 epochLength, uint64 anchorBlockNumber, bytes memory identity)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(codeHash, epochLength, anchorBlockNumber, identity);
    }
}
