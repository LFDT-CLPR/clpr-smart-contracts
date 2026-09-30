// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// TODO: remove the legacy QBFTVerifier (incorrect implementation)
///      remove whole this file
contract QBFTVerifier is ClprEvmBundleVerifier {
    uint8 internal constant PAYLOAD_SHAPE_EXPECTED_FIELDS = 5;
    uint8 internal constant PAYLOAD_SHAPE_WITH_MANIFEST = 7;
    uint8 internal constant PAYLOAD_CURRENT_BLOCK_HEADER_INDEX = 0;
    uint8 internal constant PAYLOAD_EPOCH_HEADERS_INDEX = 1;
    uint8 internal constant PAYLOAD_ACCOUNT_PROOF_INDEX = 2;
    uint8 internal constant PAYLOAD_STORAGE_PROOF_INDEX = 3;
    uint8 internal constant PAYLOAD_BUNDLE_CONTENT_INDEX = 4;
    uint8 internal constant PAYLOAD_MANIFEST_STORAGE_PROOF_INDEX = 5;
    uint8 internal constant PAYLOAD_MANIFEST_PREIMAGE_INDEX = 6;
    uint8 internal constant MIN_BLOCK_HEADER_FIELDS = 15;
    uint8 internal constant MAX_BLOCK_HEADER_FIELDS = 22;
    uint8 internal constant BLOCK_HEADER_STATE_ROOT_INDEX = 3;
    uint8 internal constant BLOCK_HEADER_NUMBER_INDEX = 8;
    uint8 internal constant BLOCK_HEADER_EXTRA_DATA_INDEX = 12;
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 4;
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
    error WrongSealCount(uint256 got, uint256 expected);
    error ValidatorSealNotFound(address expected);
    uint8 public immutable MIN_COMMITTED_SEALS;

    constructor(uint8 _sealSignatures) {
        if (_sealSignatures == 0) revert InvalidNumberOfSealSignatures();
        MIN_COMMITTED_SEALS = _sealSignatures;
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
        (address validator, bytes32 expectedCodeHash, uint64 epochLength, uint64 trustAnchorEpoch) =
            _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 channelId = ctx.channelId;

        Memory.Slice[] memory payload = RLP.decodeList(proofBytes);
        if (payload.length != PAYLOAD_SHAPE_EXPECTED_FIELDS && payload.length != PAYLOAD_SHAPE_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }
        uint256 epochHeaderCount;
        {
            Memory.Slice[] memory epochHeaders = RLP.readList(payload[PAYLOAD_EPOCH_HEADERS_INDEX]);
            epochHeaderCount = epochHeaders.length;
            for (uint256 i = 0; i < epochHeaderCount;) {
                Memory.Slice[] memory epochHeader = RLP.readList(epochHeaders[i]);
                if (epochHeader.length < MIN_BLOCK_HEADER_FIELDS) {
                    revert InvalidHeader();
                }
                // casting to 'uint64' is safe: the loop counter is bounded by the epoch-header count.
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64 expectedBlockNumber = (trustAnchorEpoch + uint64(i) + 1) * epochLength;
                if (uint64(RLP.readUint256(epochHeader[BLOCK_HEADER_NUMBER_INDEX])) != expectedBlockNumber) {
                    revert InvalidHeader();
                }
                _verifySeal(epochHeader, validator);
                validator = _extractValidatorFromEpochHeader(epochHeader);
                unchecked {
                    i++;
                }
            }
        }
        uint64 currentEpoch;
        bytes32 storageRoot;
        {
            address clprService = _toAddress(ctx.remoteServiceAddress);
            Memory.Slice[] memory header = RLP.readList(payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX]);
            if (header.length < MIN_BLOCK_HEADER_FIELDS || header.length > MAX_BLOCK_HEADER_FIELDS) {
                revert InvalidHeader();
            }
            bytes32 stateRoot = RLP.readBytes32(header[BLOCK_HEADER_STATE_ROOT_INDEX]);
            _verifySeal(header, validator);
            currentEpoch = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX])) / epochLength;
            // forge-lint: disable-next-line(unsafe-typecast)
            if (currentEpoch != trustAnchorEpoch + uint64(epochHeaderCount)) revert EpochMismatch();
            storageRoot = _verifyServiceStorageRoot(
                payload[PAYLOAD_ACCOUNT_PROOF_INDEX], stateRoot, clprService, expectedCodeHash
            );
        }
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[PAYLOAD_BUNDLE_CONTENT_INDEX]));
        metadata =
            _verifyChannelStorage(payload[PAYLOAD_STORAGE_PROOF_INDEX], storageRoot, channelId, messagePayloads.length);
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
        if (epochHeaderCount > 0) {
            newTrustAnchor = abi.encode(validator, expectedCodeHash, epochLength, currentEpoch);
            newTrustAnchorId = abi.encodePacked(currentEpoch);
        }
    }

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
        if (proof.length != 10) revert InvalidProofPayloadShape();
        address validator = RLP.readAddress(proof[0]);
        Memory.Slice[] memory header = RLP.readList(proof[8]);
        if (header.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();
        _verifySeal(header, validator);
        uint64 epochLength = uint64(RLP.readUint256(proof[9]));
        uint64 epochNumber = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX])) / epochLength;
        Memory.Slice[] memory t = RLP.readList(proof[5]);
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
        _verifySeal(hdr, validator);

        bytes32 stateRoot = RLP.readBytes32(hdr[BLOCK_HEADER_STATE_ROOT_INDEX]);
        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, _toAddress(serviceAddress), bytes32(0));
        return _verifyEndpointManifest(p[2], storageRoot, RLP.readBytes(p[3]), serviceAddress);
    }

    function _rlpTrustAnchorToAbi(bytes memory rlpBytes, uint64 epochLength, uint64 epochNumber)
        internal
        pure
        returns (bytes memory)
    {
        Memory.Slice[] memory fields = RLP.decodeList(rlpBytes);
        if (fields.length != 3) revert InvalidTrustAnchorFields();
        return abi.encode(RLP.readAddress(fields[0]), RLP.readBytes32(fields[2]), epochLength, epochNumber);
    }

    function _decodeTrustAnchor(bytes calldata trustAnchor)
        internal
        pure
        returns (address validator, bytes32 codeHash, uint64 epochLength, uint64 epochNumber)
    {
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (validator, codeHash, epochLength, epochNumber) = abi.decode(trustAnchor, (address, bytes32, uint64, uint64));
    }

    function _verifySeal(Memory.Slice[] memory header, address expectedValidator) private view {
        (bytes32 sealHash, Memory.Slice[] memory seals) = ClprQbftSeal.decodeSealsContextFromHeader(header);
        if (seals.length < MIN_COMMITTED_SEALS) revert WrongSealCount(seals.length, MIN_COMMITTED_SEALS);

        for (uint256 i = 0; i < seals.length;) {
            if (ClprQbftSeal.recoverSeal(sealHash, seals[i]) == expectedValidator) return;
            unchecked {
                i++;
            }
        }
        revert ValidatorSealNotFound(expectedValidator);
    }

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
