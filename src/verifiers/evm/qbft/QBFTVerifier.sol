// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QBFTVerifier
/// @dev Account proof, channel storage-slot proof, queue-metadata decode and the
///      `ClprBundleContent` decode are inherited from {ClprEvmBundleVerifier}.
contract QBFTVerifier is ClprEvmBundleVerifier {
    /**
     * Aligned with QbftBundlePayload record field order:
     * [
     *  0: current block header,
     *  1: epoch block headers [],
     *  2: account proof for CLPR service address,
     *  3: storage proof (5 or 6 entries),
     *  4: bundle content protobuf (ClprBundleContent)
     * ]
     */
    uint8 internal constant PAYLOAD_SHAPE_EXPECTED_FIELDS = 5;
    /// @dev Shape when the bundle also carries an endpoint-manifest update: the base 5 fields plus a
    ///      manifest storage-proof (index 5) and the manifest protobuf preimage (index 6).
    uint8 internal constant PAYLOAD_SHAPE_WITH_MANIFEST = 7;
    uint8 internal constant PAYLOAD_CURRENT_BLOCK_HEADER_INDEX = 0;
    uint8 internal constant PAYLOAD_EPOCH_HEADERS_INDEX = 1;
    uint8 internal constant PAYLOAD_ACCOUNT_PROOF_INDEX = 2;
    uint8 internal constant PAYLOAD_STORAGE_PROOF_INDEX = 3;
    uint8 internal constant PAYLOAD_BUNDLE_CONTENT_INDEX = 4;
    uint8 internal constant PAYLOAD_MANIFEST_STORAGE_PROOF_INDEX = 5;
    uint8 internal constant PAYLOAD_MANIFEST_PREIMAGE_INDEX = 6;

    /**
     * Block header fields
     */
    uint8 internal constant MIN_BLOCK_HEADER_FIELDS = 15;
    uint8 internal constant MAX_BLOCK_HEADER_FIELDS = 22;
    uint8 internal constant BLOCK_HEADER_STATE_ROOT_INDEX = 3;
    uint8 internal constant BLOCK_HEADER_NUMBER_INDEX = 8;
    uint8 internal constant BLOCK_HEADER_EXTRA_DATA_INDEX = 12;

    /// @dev Config-time endpoint-manifest proof shape:
    ///      RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage]).
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 4;

    // Trust anchor: abi.encode(validator, codeHash, epochLength, epochNumber) = 4 x 32 bytes
    uint256 internal constant TRUST_ANCHOR_LENGTH = 128;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidProofPayloadShape();
    error InvalidHeader();
    error InvalidConfigHeader();
    error InvalidConfigThrottleFieldCount();
    error InvalidTrustAnchorFields();
    error EpochMismatch();
    error EmptyValidator();
    error MultiValidatorNotSupported();
    error InvalidNumberOfSealSignatures();

    /// @dev Minimum number of committed seals required.
    uint8 public immutable MIN_COMMITTED_SEALS;

    IClprVerifier public immutable CONTRACT_MODE;

    constructor(uint8 _sealSignatures) {
        if (_sealSignatures == 0) revert InvalidNumberOfSealSignatures();
        MIN_COMMITTED_SEALS = _sealSignatures;
        CONTRACT_MODE = new QbftContractModeVerifier();
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
        if (_isContractModeAnchor(trustAnchor)) {
            return CONTRACT_MODE.verifyBundle(proofBytes, trustAnchor, channelContext);
        }

        (address validator, bytes32 expectedCodeHash, uint64 epochLength, uint64 trustAnchorEpoch) =
            _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 channelId = ctx.channelId;

        Memory.Slice[] memory payload = RLP.decodeList(proofBytes);
        if (payload.length != PAYLOAD_SHAPE_EXPECTED_FIELDS && payload.length != PAYLOAD_SHAPE_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // 1. Process epoch block headers (index 0)
        uint256 epochHeaderCount;
        {
            Memory.Slice[] memory epochHeaders = RLP.readList(payload[PAYLOAD_EPOCH_HEADERS_INDEX]);
            epochHeaderCount = epochHeaders.length;
            // Each epoch header advances the trust anchor to a new validator
            for (uint256 i = 0; i < epochHeaderCount;) {
                Memory.Slice[] memory epochHeader = RLP.readList(epochHeaders[i]);
                if (epochHeader.length < MIN_BLOCK_HEADER_FIELDS) {
                    revert InvalidHeader();
                }
                // validate the block numbers of the epoch headers
                // casting to 'uint64' is safe because the source type (uint256) is larger than the destination type
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64 expectedBlockNumber = (trustAnchorEpoch + uint64(i) + 1) * epochLength;
                if (uint64(RLP.readUint256(epochHeader[BLOCK_HEADER_NUMBER_INDEX])) != expectedBlockNumber) {
                    revert InvalidHeader();
                }
                // validate the seal of each epoch header against the current validator
                ClprQbftSeal.verify(MIN_COMMITTED_SEALS, epochHeader, validator);
                // generate new validator
                validator = _extractValidatorFromEpochHeader(epochHeader);
                unchecked {
                    i++;
                }
            }
        }

        // 2. Decode current block header (index 1) and verify against the validator.
        // 3. Epoch boundary check.
        // 4. Account proof (index 2).
        uint64 currentEpoch;
        bytes32 storageRoot;
        {
            address clprService = _toAddress(ctx.remoteServiceAddress);
            Memory.Slice[] memory header = RLP.readList(payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX]);
            if (header.length < MIN_BLOCK_HEADER_FIELDS || header.length > MAX_BLOCK_HEADER_FIELDS) {
                revert InvalidHeader();
            }
            bytes32 stateRoot = RLP.readBytes32(header[BLOCK_HEADER_STATE_ROOT_INDEX]);
            ClprQbftSeal.verify(MIN_COMMITTED_SEALS, header, validator);

            // 3. Epoch boundary check: the current block must be in the epoch that the trust anchor
            //    has advanced to (original epoch + number of epoch headers processed).
            currentEpoch = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX])) / epochLength;
            // forge-lint: disable-next-line(unsafe-typecast)
            if (currentEpoch != trustAnchorEpoch + uint64(epochHeaderCount)) revert EpochMismatch();

            // 4. Account proof (index 2): authenticate the service account and pin its code hash.
            storageRoot = _verifyServiceStorageRoot(
                payload[PAYLOAD_ACCOUNT_PROOF_INDEX], stateRoot, clprService, expectedCodeHash
            );
        }

        // 5. Storage proof (index 3): prove the Channel metadata slots using channelId from trust anchor.
        metadata = _verifyChannelStorage(payload[PAYLOAD_STORAGE_PROOF_INDEX], storageRoot, channelId);

        // 6. Bundle content (protobuf) → message payloads.
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[PAYLOAD_BUNDLE_CONTENT_INDEX]));

        // 6b. Optional endpoint-manifest update: when the bundle carries a manifest proof (7-field
        //     shape), prove the peer's manifest-commitment slot against the same storage root and bind
        //     the supplied preimage. Absent otherwise (version 0 = "no update").
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

        // 7. Trust-anchor rotation: if epoch headers were processed, return the updated trust anchor
        //    and the new trust-anchor ID (epoch number as big-endian uint64 bytes). Otherwise the
        //    named returns stay empty (no rotation). All other returns are set above.
        if (epochHeaderCount > 0) {
            newTrustAnchor = abi.encode(validator, expectedCodeHash, epochLength, currentEpoch);
            newTrustAnchorId = abi.encodePacked(currentEpoch);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof is RLP([validator, serviceAddr, codeHash, chainId, peerConfigNanos,
    ///      throttles, trustAnchor, trustAnchorId, latestEpochBlockHeader, epochLength]).
    ///      The validator is validated against the latestEpochBlockHeader seal.
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
        if (_isContractModeConfig(configProofBytes)) {
            return CONTRACT_MODE.verifyConfig(configProofBytes, channelId, endpointManifestProofBytes);
        }

        Memory.Slice[] memory proof = RLP.decodeList(configProofBytes);
        if (proof.length != 10) revert InvalidProofPayloadShape();

        // Validate validator against the latest epoch block header seal (field 8).
        address validator = RLP.readAddress(proof[0]);
        Memory.Slice[] memory header = RLP.readList(proof[8]);
        if (header.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();

        ClprQbftSeal.verify(MIN_COMMITTED_SEALS, header, validator);

        uint64 epochLength = uint64(RLP.readUint256(proof[9]));
        uint64 epochNumber = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX])) / epochLength;

        Memory.Slice[] memory t = RLP.readList(proof[5]);
        // The throttle list carries the 5 core positional slots and, since the endpoint-limit
        // spec, the two endpoint-limit throttles (maxLocalEndpoints, maxPeerEndpoints) appended
        // as slots 5 and 6 — mirroring the 7-field protobuf ClprThrottles (fields 6/7). A 5-entry
        // list (pre-endpoint-limit config proofs) stays accepted with the two limits defaulting
        // to 0.
        if (t.length != 5 && t.length != 7) revert InvalidConfigThrottleFieldCount();
        uint32 maxLocal;
        uint32 maxPeer;
        if (t.length == 7) {
            // casting to 'uint32' is safe: endpoint limits are small caps; oversized values truncate.
            // forge-lint: disable-next-line(unsafe-typecast)
            maxLocal = uint32(RLP.readUint256(t[5]));
            // forge-lint: disable-next-line(unsafe-typecast)
            maxPeer = uint32(RLP.readUint256(t[6]));
        }

        serviceAddress = RLP.readBytes(proof[1]);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        // Verify the endpoint-manifest proof against the config's block (sealed by the same validator).
        // Empty proof → UNINITIALIZED manifest at version 0 (bring-up); the real manifest then arrives
        // via the first bundle's Step 1b. The trust anchor's codeHash pins the proven account.
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, validator, serviceAddress);
        return (
            channelContext,
            string(RLP.readBytes(proof[3])),
            serviceAddress,
            uint96(RLP.readUint256(proof[4])),
            ClprTypes.Throttles({
                maxMessagesPerBundle: uint32(RLP.readUint256(t[0])),
                maxMessagePayloadBytes: uint64(RLP.readUint256(t[1])),
                maxGasPerMessage: uint64(RLP.readUint256(t[2])),
                maxQueueDepth: uint32(RLP.readUint256(t[3])),
                maxSyncBytes: uint64(RLP.readUint256(t[4])),
                maxLocalEndpoints: maxLocal,
                maxPeerEndpoints: maxPeer
            }),
            _rlpTrustAnchorToAbi(RLP.readBytes(proof[6]), epochLength, epochNumber),
            abi.encodePacked(epochNumber),
            endpointManifest
        );
    }

    /// @dev Verify the optional endpoint-manifest proof supplied to `verifyConfig`. When
    ///      `endpointManifestProofBytes` is empty, returns the UNINITIALIZED manifest at version 0
    ///      (bring-up — see {_uninitializedEndpointManifest}). Otherwise decodes `RLP([blockHeader, accountProof, manifestStorageProof,
    ///      manifestPreimage])`, verifies the header seal against `validator`, authenticates the service
    ///      account (pinning its codeHash — unpinned here, provided via the trust anchor at bundle time),
    ///      and binds the manifest commitment. `service_address` is bound to the config's service address.
    function _verifyConfigEndpointManifest(
        bytes calldata endpointManifestProofBytes,
        address validator,
        bytes memory serviceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        if (endpointManifestProofBytes.length == 0) {
            return _uninitializedEndpointManifest(serviceAddress);
        }

        Memory.Slice[] memory p = RLP.decodeList(endpointManifestProofBytes);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidProofPayloadShape();

        Memory.Slice[] memory hdr = RLP.readList(p[0]);
        if (hdr.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();
        ClprQbftSeal.verify(MIN_COMMITTED_SEALS, hdr, validator);

        bytes32 stateRoot = RLP.readBytes32(hdr[BLOCK_HEADER_STATE_ROOT_INDEX]);
        // codeHash pinning is disabled here (bytes32(0)); the config trust anchor establishes the
        // account, and bundle-time proofs pin the codeHash.
        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, _toAddress(serviceAddress), bytes32(0));
        return _verifyEndpointManifest(p[2], storageRoot, RLP.readBytes(p[3]), serviceAddress);
    }

    /// @dev Converts the RLP-encoded trust anchor from the config proof ([validator, service, codeHash])
    ///      into the 4-field ABI encoding used as Channel.trustAnchor, appending epochLength and
    ///      epochNumber.
    function _rlpTrustAnchorToAbi(bytes memory rlpBytes, uint64 epochLength, uint64 epochNumber)
        internal
        pure
        returns (bytes memory)
    {
        Memory.Slice[] memory fields = RLP.decodeList(rlpBytes);
        if (fields.length != 3) revert InvalidTrustAnchorFields();
        return abi.encode(RLP.readAddress(fields[0]), RLP.readBytes32(fields[2]), epochLength, epochNumber);
    }

    // FIXME: format should be shared for both modes, remove this temporary helper when header mode works correctly.
    function _isContractModeAnchor(bytes calldata trustAnchor) private pure returns (bool) {
        // 224 = QbftContractModeVerifier.CONTRACT_ANCHOR_LENGTH (7 words); the header-mode anchor is 192.
        return trustAnchor.length == 224 && uint256(bytes32(trustAnchor[:32])) == 1;
    }

    // FIXME: format should be shared for both modes, remove this temporary helper when header mode works correctly.
    function _isContractModeConfig(bytes calldata configProofBytes) private pure returns (bool) {
        return RLP.decodeList(configProofBytes).length == 8;
    }

    function _decodeTrustAnchor(bytes calldata trustAnchor)
        internal
        pure
        returns (address validator, bytes32 codeHash, uint64 epochLength, uint64 epochNumber)
    {
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (validator, codeHash, epochLength, epochNumber) = abi.decode(trustAnchor, (address, bytes32, uint64, uint64));
    }

    /// @dev Extracts the validator address from an epoch block header's extraData.
    ///      QBFT extraData layout: [vanity, validators[], vote, round, committedSeals[]]
    ///      The trust anchor tracks validators[0] as the representative for the new epoch.
    function _extractValidatorFromEpochHeader(Memory.Slice[] memory epochHeader) internal pure returns (address) {
        bytes memory extraDataInner = RLP.readBytes(epochHeader[BLOCK_HEADER_EXTRA_DATA_INDEX]);
        Memory.Slice[] memory extra = RLP.decodeList(extraDataInner);
        // extra[1] is the validators list
        Memory.Slice[] memory validators = RLP.readList(extra[1]);
        if (validators.length == 0) revert EmptyValidator();
        if (validators.length != 1) revert MultiValidatorNotSupported();
        return RLP.readAddress(validators[0]);
    }
}
