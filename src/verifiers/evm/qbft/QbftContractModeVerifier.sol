// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftVerifierBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {QbftContractValidatorSource} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftContractValidatorSource.sol";
import {
    QbftValidators,
    ValidatorSet,
    QbftValidatorMode
} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QbftContractModeVerifier
/// @notice Verifies Besu QBFT bundles for chains that keep the validator set in a contract.
///         Field 1 of the bundle proof is `[trustedSet, hops[], contractProof]`; each hop is
///         `[blockHeader, contractProof]`. See `qbft-contract-mode.md`.
contract QbftContractModeVerifier is QbftVerifierBase {
    uint8 internal constant CONTRACT_SOURCE_FIELDS = 3;

    /// @dev Config proof: RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor,
    ///      validatorContractProof, blockHeader]).
    uint256 internal constant CONFIG_FIELDS_CONTRACT = 7;
    uint8 internal constant CONFIG_CONTRACT_PROOF_INDEX = 5;
    uint8 internal constant CONFIG_HEADER_INDEX_CONTRACT = 6;

    /// @dev Descriptor field count: [mode, serviceAddr, codeHash, validatorContract, arraySlot].
    uint256 internal constant CONFIG_ANCHOR_FIELDS_CONTRACT = 5;

    /// @dev abi.encode(uint8 mode, bytes32 setCommitment, bytes32 codeHash, address validatorContract,
    ///      bytes32 arraySlot, uint64 anchorBlockNumber, bytes32 validatorCodeHash).
    uint256 internal constant CONTRACT_ANCHOR_LENGTH = 224;

    error WrongValidatorCodeHash(bytes32 got, bytes32 expected);

    struct QbftAnchor {
        bytes32 setCommitment;
        bytes32 codeHash;
        address validatorContract;
        bytes32 arraySlot;
        uint64 anchorBlockNumber;
        bytes32 validatorCodeHash;
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
        QbftAnchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);

        Memory.Slice[] memory payload = _decodePayload(proofBytes);
        Memory.Slice[] memory header = _decodeCurrentHeader(payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX]);
        bytes32 stateRoot = _headerStateRoot(header);
        uint64 currentBlockNumber = _headerNumber(header);

        Memory.Slice[] memory source = RLP.readList(payload[PAYLOAD_VALIDATOR_SOURCE_INDEX]);
        if (source.length != CONTRACT_SOURCE_FIELDS) revert InvalidPayloadShape();
        ValidatorSet memory trustedSet = _openCommitment(source[0], anchor.setCommitment);

        (address[] memory currentValidators, bool rotate, bool crossedHops) =
            _walkContractMode(source[1], source[2], header, anchor, trustedSet, stateRoot, currentBlockNumber);

        (metadata, messagePayloads, newEndpointManifest) =
            _verifyStorageAndContent(payload, ctx, stateRoot, anchor.codeHash);

        if (rotate || crossedHops) {
            bytes32 newCommitment =
                rotate ? QbftValidators.commit(ValidatorSet({members: currentValidators})) : anchor.setCommitment;
            newTrustAnchor = _encodeContractAnchor(
                newCommitment,
                anchor.codeHash,
                anchor.validatorContract,
                anchor.arraySlot,
                currentBlockNumber,
                anchor.validatorCodeHash
            );
            newTrustAnchorId = abi.encodePacked(currentBlockNumber);
        }
    }

    /// @dev A hop is the change block: sealed by the outgoing set (the set for block N comes from
    ///      the state of block N-1), with the next set already in its state. The harvest reads the
    ///      contract's set under the current state root.
    function _walkContractMode(
        Memory.Slice hopsItem,
        Memory.Slice proofItem,
        Memory.Slice[] memory header,
        QbftAnchor memory anchor,
        ValidatorSet memory trustedSet,
        bytes32 stateRoot,
        uint64 currentBlockNumber
    ) internal pure returns (address[] memory currentValidators, bool rotate, bool crossedHops) {
        ValidatorSet memory currentSet = trustedSet;
        uint64 lastNumber = anchor.anchorBlockNumber;

        Memory.Slice[] memory hops = RLP.readList(hopsItem);
        uint256 count = hops.length;
        crossedHops = count > 0;
        for (uint256 i = 0; i < count;) {
            Memory.Slice[] memory hop = RLP.readList(hops[i]);
            if (hop.length != 2) revert InvalidPayloadShape();
            Memory.Slice[] memory hopHeader = _decodeHopHeader(hop[0]);
            uint64 number = _headerNumber(hopHeader);
            if (number <= lastNumber) revert HandoffHeaderNotAscending(number, lastNumber);
            ClprQbftQuorum.verifyQuorum(currentSet, hopHeader);
            currentSet = _resolvePinnedSet(hop[1], _headerStateRoot(hopHeader), anchor);
            lastNumber = number;
            unchecked {
                i++;
            }
        }

        if (currentBlockNumber <= lastNumber) revert CurrentHeaderBehindWalk(currentBlockNumber, lastNumber);
        ClprQbftQuorum.verifyQuorum(currentSet, header);
        ValidatorSet memory next = _resolvePinnedSet(proofItem, stateRoot, anchor);
        currentValidators = next.members;
        rotate = !QbftValidators.equals(next.members, trustedSet.members);
    }

    function _resolvePinnedSet(Memory.Slice proofItem, bytes32 stateRoot, QbftAnchor memory anchor)
        private
        pure
        returns (ValidatorSet memory set)
    {
        bytes32 codeHash;
        (set, codeHash) = QbftContractValidatorSource.resolveSet(
            RlpCursor.payloadSlice(proofItem), stateRoot, anchor.validatorContract, anchor.arraySlot
        );
        if (codeHash != anchor.validatorCodeHash) revert WrongValidatorCodeHash(codeHash, anchor.validatorCodeHash);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof is RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor,
    ///      validatorContractProof, blockHeader]). The descriptor must be
    ///      [mode = 1, serviceAddr, codeHash, validatorContract, arraySlot]. The validator contract's
    ///      code hash is not declared: it is taken from its proven account and pinned in the anchor.
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
            _decodeConfigProof(configProofBytes, CONFIG_FIELDS_CONTRACT, CONFIG_HEADER_INDEX_CONTRACT);

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

    /// @dev The initial set comes from the contract proof under the config header's state root.
    ///      The header's seals are checked against that same set.
    function _configAnchor(Memory.Slice[] memory proof, Memory.Slice[] memory header)
        internal
        pure
        returns (bytes memory anchor, bytes memory anchorId, ValidatorSet memory set)
    {
        Memory.Slice[] memory ta =
            _decodeDescriptor(proof, CONFIG_ANCHOR_FIELDS_CONTRACT, uint8(QbftValidatorMode.Contract));

        uint64 blockNumber = _headerNumber(header);
        address validatorContract = RLP.readAddress(ta[3]);
        bytes32 arraySlot = RLP.readBytes32(ta[4]);
        bytes32 validatorCodeHash;
        (set, validatorCodeHash) = QbftContractValidatorSource.resolveSet(
            RlpCursor.payloadSlice(proof[CONFIG_CONTRACT_PROOF_INDEX]),
            _headerStateRoot(header),
            validatorContract,
            arraySlot
        );
        ClprQbftQuorum.verifyQuorum(set, header);
        anchor = _encodeContractAnchor(
            QbftValidators.commit(set),
            RLP.readBytes32(ta[2]),
            validatorContract,
            arraySlot,
            blockNumber,
            validatorCodeHash
        );
        anchorId = abi.encodePacked(blockNumber);
    }

    /// @dev Word 0 must be {QbftValidatorMode.Contract}.
    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (QbftAnchor memory a) {
        if (trustAnchor.length != CONTRACT_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        uint8 mode = _anchorMode(trustAnchor);
        if (mode != uint8(QbftValidatorMode.Contract)) revert UnknownValidatorMode(mode);
        (
            ,
            bytes32 setCommitment,
            bytes32 codeHash,
            address validatorContract,
            bytes32 arraySlot,
            uint64 anchorBlockNumber,
            bytes32 validatorCodeHash
        ) = abi.decode(trustAnchor, (uint8, bytes32, bytes32, address, bytes32, uint64, bytes32));
        a.setCommitment = setCommitment;
        a.codeHash = codeHash;
        a.validatorContract = validatorContract;
        a.arraySlot = arraySlot;
        a.anchorBlockNumber = anchorBlockNumber;
        a.validatorCodeHash = validatorCodeHash;
    }

    function _encodeContractAnchor(
        bytes32 setCommitment,
        bytes32 codeHash,
        address validatorContract,
        bytes32 arraySlot,
        uint64 anchorBlockNumber,
        bytes32 validatorCodeHash
    ) internal pure returns (bytes memory) {
        return abi.encode(
            uint8(QbftValidatorMode.Contract),
            setCommitment,
            codeHash,
            validatorContract,
            arraySlot,
            anchorBlockNumber,
            validatorCodeHash
        );
    }
}
