// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
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
contract QbftContractModeVerifier is ClprEvmBundleVerifier {
    /**
     * Aligned with QbftBundlePayload record field order:
     * [
     *  0: current block header,
     *  1: validator source - [trustedSet, hops[], contractProof],
     *  2: account proof for CLPR service address,
     *  3: storage proof (5 or 6 entries),
     *  4: bundle content protobuf (ClprBundleContent)
     * ]
     */
    uint8 internal constant PAYLOAD_SHAPE_EXPECTED_FIELDS = 5;
    uint8 internal constant PAYLOAD_SHAPE_WITH_MANIFEST = 7;
    uint8 internal constant PAYLOAD_CURRENT_BLOCK_HEADER_INDEX = 0;
    uint8 internal constant PAYLOAD_VALIDATOR_SOURCE_INDEX = 1;
    uint8 internal constant CONTRACT_SOURCE_FIELDS = 3;
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

    /// @dev Config-time endpoint-manifest proof shape:
    ///      RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage]).
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 4;

    /// @dev Descriptor field count: [mode, serviceAddr, codeHash, validatorContract, arraySlot].
    uint256 internal constant CONFIG_ANCHOR_FIELDS_CONTRACT = 5;

    /// @dev abi.encode(uint8 mode, bytes32 setCommitment, bytes32 codeHash, address validatorContract,
    ///      bytes32 arraySlot, uint64 anchorBlockNumber, bytes32 validatorCodeHash).
    uint256 internal constant CONTRACT_ANCHOR_LENGTH = 224;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidProofPayloadShape();
    error InvalidHeader();
    error InvalidConfigHeader();
    error InvalidConfigThrottleFieldCount();
    error InvalidTrustAnchorFields();
    error InvalidNumberOfSealSignatures();
    /// @notice A hop's block number is not strictly after the anchor block / previous hop.
    error HandoffHeaderNotAscending(uint64 got, uint64 lastSeen);
    error CurrentHeaderBehindWalk(uint64 got, uint64 lastSeen);
    error UnknownValidatorMode(uint8 mode);
    /// @notice The submitted member list does not hash to the anchor's set commitment.
    error WrongSetCommitment(bytes32 got, bytes32 expected);
    error WrongValidatorCodeHash(bytes32 got, bytes32 expected);
    error InvalidTrustedSet();

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

        Memory.Slice[] memory payload = RLP.decodeList(proofBytes);
        if (payload.length != PAYLOAD_SHAPE_EXPECTED_FIELDS && payload.length != PAYLOAD_SHAPE_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        Memory.Slice[] memory header = RLP.readList(payload[PAYLOAD_CURRENT_BLOCK_HEADER_INDEX]);
        if (header.length < MIN_BLOCK_HEADER_FIELDS || header.length > MAX_BLOCK_HEADER_FIELDS) {
            revert InvalidHeader();
        }
        bytes32 stateRoot = RLP.readBytes32(header[BLOCK_HEADER_STATE_ROOT_INDEX]);
        uint64 currentBlockNumber = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX]));

        Memory.Slice[] memory source = RLP.readList(payload[PAYLOAD_VALIDATOR_SOURCE_INDEX]);
        if (source.length != CONTRACT_SOURCE_FIELDS) revert InvalidPayloadShape();
        ValidatorSet memory trustedSet = _openCommitment(source[0], anchor.setCommitment);

        bytes32 storageRoot;
        address[] memory currentValidators;
        bool rotate;
        bool crossedHops;
        {
            (currentValidators, rotate, crossedHops) =
                _walkContractMode(source[1], source[2], header, anchor, trustedSet, stateRoot, currentBlockNumber);
            storageRoot = _verifyServiceStorageRoot(
                payload[PAYLOAD_ACCOUNT_PROOF_INDEX], stateRoot, _toAddress(ctx.remoteServiceAddress), anchor.codeHash
            );
        }

        metadata = _verifyChannelStorage(payload[PAYLOAD_STORAGE_PROOF_INDEX], storageRoot, ctx.channelId);

        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[PAYLOAD_BUNDLE_CONTENT_INDEX]));

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
            Memory.Slice[] memory hopHeader = RLP.readList(hop[0]);
            if (hopHeader.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidHeader();
            uint64 number = uint64(RLP.readUint256(hopHeader[BLOCK_HEADER_NUMBER_INDEX]));
            if (number <= lastNumber) revert HandoffHeaderNotAscending(number, lastNumber);
            ClprQbftQuorum.verifyQuorum(currentSet, hopHeader);
            currentSet = _resolvePinnedSet(hop[1], RLP.readBytes32(hopHeader[BLOCK_HEADER_STATE_ROOT_INDEX]), anchor);
            lastNumber = number;
            unchecked {
                i++;
            }
        }

        _verifyCurrentAgainstWalk(currentSet, header, currentBlockNumber, lastNumber);
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

    /// @dev The submitted member list, sorted and deduped, must hash to the anchor's commitment.
    ///      The list is parsed in place ({_readMemberList}) and sorted in place; a list carrying
    ///      duplicates is still accepted (compacted) so the wire format is unchanged. Anchors only
    ///      ever commit to resolveSet outputs, which are sorted, so a relay that submits the set as
    ///      it received it pays only the O(n) pass of an already-sorted insertion sort.
    function _openCommitment(Memory.Slice listItem, bytes32 expected) internal pure returns (ValidatorSet memory set) {
        address[] memory members = _readMemberList(listItem);
        if (QbftValidators.sortInPlace(members) != members.length) {
            members = QbftValidators.sortedDedup(members);
        }
        set.members = members;
        bytes32 got = QbftValidators.commit(set);
        if (got != expected) revert WrongSetCommitment(got, expected);
    }

    /// @dev The trusted-set list `[address, ...]` read with the cursor: no per-item slice
    ///      allocation. An oversized list can never match the commitment anyway
    ///      anchors only commit to resolveSet outputs, capped at ClprQbftQuorum.MAX_VALIDATORS.
    function _readMemberList(Memory.Slice listItem) private pure returns (address[] memory members) {
        (uint256 ptr, uint256 itemEnd) = RlpCursor.bounds(listItem);
        (uint256 cur, uint256 len, bool isList) = RlpCursor.head(ptr, itemEnd);
        uint256 end;
        unchecked {
            end = cur + len;
        }
        if (!isList || end != itemEnd) revert InvalidTrustedSet();

        uint256 n;
        for (uint256 p = cur; p < end;) {
            (uint256 payloadPtr, uint256 payloadLen,) = RlpCursor.head(p, end);
            unchecked {
                p = payloadPtr + payloadLen;
                n++;
            }
        }
        if (n > ClprQbftQuorum.MAX_VALIDATORS) revert ClprQbftQuorum.ValidatorSetTooLarge(n);

        members = new address[](n);
        for (uint256 i = 0; i < n;) {
            (uint256 payloadPtr, uint256 payloadLen, bool memberIsList) = RlpCursor.head(cur, end);
            uint256 itemLen;
            unchecked {
                itemLen = payloadPtr + payloadLen - cur;
            }
            if (memberIsList || (itemLen != 21 && itemLen != 1)) revert InvalidTrustedSet();
            // forge-lint: disable-next-line(unsafe-typecast)
            members[i] = address(uint160(RlpCursor.uintValue(payloadPtr, payloadLen)));
            unchecked {
                cur = payloadPtr + payloadLen;
                i++;
            }
        }
    }

    function _verifyCurrentAgainstWalk(
        ValidatorSet memory currentSet,
        Memory.Slice[] memory header,
        uint64 currentBlockNumber,
        uint64 lastNumber
    ) internal pure {
        if (currentBlockNumber <= lastNumber) {
            revert CurrentHeaderBehindWalk(currentBlockNumber, lastNumber);
        }
        ClprQbftQuorum.verifyQuorum(currentSet, header);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof is RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor,
    ///      validatorContractProof, blockHeader, epochLength]). The descriptor must be
    ///      [mode = 1, serviceAddr, codeHash, validatorContract, arraySlot].
    ///      Field 7 is kept for shape. This verifier does not use it.
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
        if (configProofBytes.length == 0) revert InvalidPayloadShape();

        Memory.Slice[] memory proof = RLP.decodeList(configProofBytes);
        if (proof.length != 8) revert InvalidProofPayloadShape();

        Memory.Slice[] memory header = RLP.readList(proof[6]);
        if (header.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();

        throttles = _decodeConfigThrottles(RLP.readList(proof[3]));
        serviceAddress = RLP.readBytes(proof[0]);

        ValidatorSet memory set;
        (initialTrustAnchor, initialTrustAnchorId, set) = _configAnchor(proof, header);

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, set, serviceAddress);
        return (
            channelContext,
            string(RLP.readBytes(proof[1])),
            serviceAddress,
            uint96(RLP.readUint256(proof[2])),
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
        Memory.Slice[] memory ta = RLP.decodeList(RLP.readBytes(proof[4]));
        if (ta.length != CONFIG_ANCHOR_FIELDS_CONTRACT) revert InvalidTrustAnchorFields();
        uint256 mode = RLP.readUint256(ta[0]);
        if (mode != uint256(uint8(QbftValidatorMode.Contract))) {
            // The truncation only shapes the error argument on the reverting path; the check itself
            // compares the full word, so a value like 0x101 cannot pass as Contract (1).
            // forge-lint: disable-next-line(unsafe-typecast)
            revert UnknownValidatorMode(uint8(mode));
        }

        uint64 blockNumber = uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX]));
        bytes32 stateRoot = RLP.readBytes32(header[BLOCK_HEADER_STATE_ROOT_INDEX]);
        address validatorContract = RLP.readAddress(ta[3]);
        bytes32 arraySlot = RLP.readBytes32(ta[4]);
        bytes32 validatorCodeHash;
        (set, validatorCodeHash) = QbftContractValidatorSource.resolveSet(
            RlpCursor.payloadSlice(proof[5]), stateRoot, validatorContract, arraySlot
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

    /// @dev A 5-entry list is the legacy shape: the two endpoint limits default to 0. A 7-entry
    ///      list appends (maxLocalEndpoints, maxPeerEndpoints).
    function _decodeConfigThrottles(Memory.Slice[] memory t)
        internal
        pure
        returns (ClprTypes.Throttles memory throttles)
    {
        if (t.length != 5 && t.length != 7) revert InvalidConfigThrottleFieldCount();
        uint32 maxLocal;
        uint32 maxPeer;
        if (t.length == 7) {
            // The endpoint limits are small caps. Oversized values truncate.
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

    /// @dev Empty bytes return the UNINITIALIZED manifest at version 0. Otherwise the shape is
    ///      RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage]). The codeHash
    ///      is not pinned here. The trust anchor pins it at bundle time.
    function _verifyConfigEndpointManifest(
        bytes calldata endpointManifestProofBytes,
        ValidatorSet memory set,
        bytes memory serviceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory) {
        if (endpointManifestProofBytes.length == 0) {
            return _uninitializedEndpointManifest(serviceAddress);
        }

        Memory.Slice[] memory p = RLP.decodeList(endpointManifestProofBytes);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidProofPayloadShape();

        Memory.Slice[] memory hdr = RLP.readList(p[0]);
        if (hdr.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();
        ClprQbftQuorum.verifyQuorum(set, hdr);

        bytes32 stateRoot = RLP.readBytes32(hdr[BLOCK_HEADER_STATE_ROOT_INDEX]);
        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, _toAddress(serviceAddress), bytes32(0));
        return _verifyEndpointManifest(p[2], storageRoot, RLP.readBytes(p[3]), serviceAddress);
    }

    /// @dev Word 0 must be {QbftValidatorMode.Contract}.
    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (QbftAnchor memory a) {
        if (trustAnchor.length != CONTRACT_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        uint8 mode = uint8(uint256(bytes32(trustAnchor[:32])));
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
