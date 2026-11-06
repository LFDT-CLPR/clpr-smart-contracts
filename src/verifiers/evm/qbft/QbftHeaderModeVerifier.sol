// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftVerifierBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {
    QbftValidators,
    ValidatorSet,
    QbftValidatorMode
} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QbftHeaderModeVerifier
/// @notice Verifies Besu QBFT bundles for chains that list the validator set in every block
///         header.
contract QbftHeaderModeVerifier is QbftVerifierBase {
    uint8 internal constant HEADER_SOURCE_FIELDS = 2;

    /// @dev Config proof: RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor, blockHeader]).
    uint256 internal constant CONFIG_FIELDS_HEADER = 6;
    uint8 internal constant CONFIG_HEADER_INDEX_HEADER = 5;

    /// @dev Descriptor field count: [mode, codeHash].
    uint256 internal constant CONFIG_ANCHOR_FIELDS_HEADER = 2;

    /// @dev abi.encode(uint8 mode, bytes32 setCommitment, bytes32 codeHash, uint64 anchorBlockNumber).
    uint256 internal constant HEADER_ANCHOR_LENGTH = 128;

    struct HeaderAnchor {
        bytes32 setCommitment;
        bytes32 codeHash;
        uint64 anchorBlockNumber;
    }

    /// @inheritdoc IClprVerifier
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        pure
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        HeaderAnchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);

        Memory.Slice[] memory payload = _decodePayload(proofBytes);
        Memory.Slice[] memory header = _decodeCurrentHeader(payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX]);
        uint64 currentBlockNumber = _headerNumber(header);

        Memory.Slice[] memory source = RLP.readList(payload[PAYLOAD_VALIDATOR_SOURCE_INDEX]);
        if (source.length != HEADER_SOURCE_FIELDS) revert InvalidPayloadShape();
        ClprQbftSeal.HeaderExtra memory current = ClprQbftSeal.decodeHeader(header);
        ValidatorSet memory listedNow = _listedSet(current.validators);
        ValidatorSet memory trustedSet = _trustedSet(source[0], listedNow, anchor.setCommitment);

        (bool rotate, bool crossedHops) =
            _walkHeaders(source[1], current, listedNow, anchor.anchorBlockNumber, trustedSet, currentBlockNumber);

        (metadata, messagePayloads, newEndpointManifest) =
            _verifyStorageAndContent(payload, ctx, _headerStateRoot(header), anchor.codeHash);

        if (rotate || crossedHops) {
            bytes32 newCommitment = rotate ? QbftValidators.commit(listedNow) : anchor.setCommitment;
            newTrustAnchor = _encodeHeaderAnchor(newCommitment, anchor.codeHash, currentBlockNumber);
            newTrustAnchorId = abi.encodePacked(currentBlockNumber);
        }
    }

    /// @dev If an empty list is submitted as the trusted validator set, the validator set from the
    ///      header is used instead (no rotation assumed). It must still hash to the anchor.
    function _trustedSet(Memory.Slice listItem, ValidatorSet memory listedNow, bytes32 expected)
        internal
        pure
        returns (ValidatorSet memory)
    {
        if (_isEmptyList(listItem)) {
            _checkCommitment(listedNow, expected);
            return listedNow;
        }
        return _openCommitment(listItem, expected);
    }

    /// @param current The current header's `extraData`, already decoded by the caller (which read
    ///                `listedNow` from it). Each hop header is decoded once here, the same way.
    function _walkHeaders(
        Memory.Slice hopsItem,
        ClprQbftSeal.HeaderExtra memory current,
        ValidatorSet memory listedNow,
        uint64 anchorBlockNumber,
        ValidatorSet memory trustedSet,
        uint64 currentBlockNumber
    ) internal pure returns (bool rotate, bool crossedHops) {
        ValidatorSet memory currentSet = trustedSet;
        uint64 lastNumber = anchorBlockNumber;

        Memory.Slice[] memory hops = RLP.readList(hopsItem);
        uint256 count = hops.length;
        crossedHops = count > 0;
        for (uint256 i = 0; i < count;) {
            Memory.Slice[] memory hopHeader = _decodeHopHeader(hops[i]);
            uint64 number = _headerNumber(hopHeader);
            if (number <= lastNumber) revert HandoffHeaderNotAscending(number, lastNumber);
            ClprQbftSeal.HeaderExtra memory hop = ClprQbftSeal.decodeHeader(hopHeader);
            ValidatorSet memory listed = _listedSet(hop.validators);
            ClprQbftQuorum.verifyRotationStep(listed, currentSet, hop);
            currentSet = listed;
            lastNumber = number;
            unchecked {
                i++;
            }
        }

        if (currentBlockNumber <= lastNumber) revert CurrentHeaderBehindWalk(currentBlockNumber, lastNumber);
        ClprQbftQuorum.verifyRotationStep(listedNow, currentSet, current);
        rotate = !QbftValidators.equals(listedNow.members, trustedSet.members);
    }

    /// @dev The header's own validator list (`extraData.validators`), sorted and deduped.
    function _listedSet(Memory.Slice validators) internal pure returns (ValidatorSet memory set) {
        (address[] memory members, bool ok) = _readMemberList(validators);
        if (!ok) revert InvalidHeader();
        set.members = _sortedSet(members);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof is RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor,
    ///      blockHeader]). The descriptor must be [mode = 0, codeHash]. The initial set is the
    ///      header's own validator list, and the header must be sealed by a quorum of it.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        pure
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
        (Memory.Slice[] memory proof, Memory.Slice[] memory header) =
            _decodeConfigProof(configProofBytes, CONFIG_FIELDS_HEADER, CONFIG_HEADER_INDEX_HEADER);

        throttles = _decodeConfigThrottles(RLP.readList(proof[CONFIG_THROTTLES_INDEX]));
        serviceAddress = RLP.readBytes(proof[CONFIG_SERVICE_ADDRESS_INDEX]);

        ValidatorSet memory set;
        (initialTrustAnchor, initialTrustAnchorId, set) = _configAnchor(proof, header);

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, set, serviceAddress);
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

    /// @dev The initial set is the config header's own validator list; the header's seals are
    ///      checked against that same set (there is no earlier trusted set to link to).
    function _configAnchor(Memory.Slice[] memory proof, Memory.Slice[] memory header)
        internal
        pure
        returns (bytes memory anchor, bytes memory anchorId, ValidatorSet memory set)
    {
        Memory.Slice[] memory ta =
            _decodeDescriptor(proof, CONFIG_ANCHOR_FIELDS_HEADER, uint8(QbftValidatorMode.Header));

        ClprQbftSeal.HeaderExtra memory x = ClprQbftSeal.decodeHeader(header);
        set = _listedSet(x.validators);
        ClprQbftQuorum.verifyQuorum(set, x);
        uint64 blockNumber = _headerNumber(header);
        anchor = _encodeHeaderAnchor(QbftValidators.commit(set), RLP.readBytes32(ta[1]), blockNumber);
        anchorId = abi.encodePacked(blockNumber);
    }

    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (HeaderAnchor memory a) {
        if (trustAnchor.length != HEADER_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        uint8 mode = _anchorMode(trustAnchor);
        if (mode != uint8(QbftValidatorMode.Header)) revert UnknownValidatorMode(mode);
        (, bytes32 setCommitment, bytes32 codeHash, uint64 anchorBlockNumber) =
            abi.decode(trustAnchor, (uint8, bytes32, bytes32, uint64));
        a.setCommitment = setCommitment;
        a.codeHash = codeHash;
        a.anchorBlockNumber = anchorBlockNumber;
    }

    function _encodeHeaderAnchor(bytes32 setCommitment, bytes32 codeHash, uint64 anchorBlockNumber)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(uint8(QbftValidatorMode.Header), setCommitment, codeHash, anchorBlockNumber);
    }
}
