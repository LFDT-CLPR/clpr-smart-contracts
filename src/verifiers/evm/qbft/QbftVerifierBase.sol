// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QbftVerifierBase
/// @notice What the two Besu QBFT verifiers share is here: proof shapes, the trusted-set
///         commitment, the storage-proof tail and the config proof pieces.
///         Modes differ only in where the validator set comes from.
abstract contract QbftVerifierBase is ClprEvmBundleVerifier {
    /**
     * Bundle proof: RLP list of 5 fields, or 7 with an endpoint-manifest update.
     * [
     *  0: current block header,
     *  1: validator source (mode-specific),
     *  2: account proof for the CLPR service address,
     *  3: channel storage proof (5 or 6 entries),
     *  4: bundle content protobuf (ClprBundleContent),
     *  5: manifest storage proof   (7-field shape only),
     *  6: manifest preimage        (7-field shape only)
     * ]
     */
    uint8 internal constant PAYLOAD_SHAPE_EXPECTED_FIELDS = 5;
    uint8 internal constant PAYLOAD_SHAPE_WITH_MANIFEST = 7;
    uint8 internal constant PAYLOAD_CURRENT_BLOCK_HEADER_INDEX = 0;
    uint8 internal constant PAYLOAD_VALIDATOR_SOURCE_INDEX = 1;
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

    /// @dev Config proof: RLP([serviceAddr, chainId, peerConfigNanos, throttles, descriptor, ...]).
    ///      The first five fields are shared; each mode fixes the fields after them and the total
    ///      count (header mode: the block header at 5; contract mode: the validator contract proof
    ///      at 5 and the block header at 6).
    uint8 internal constant CONFIG_SERVICE_ADDRESS_INDEX = 0;
    uint8 internal constant CONFIG_CHAIN_ID_INDEX = 1;
    uint8 internal constant CONFIG_PEER_NANOS_INDEX = 2;
    uint8 internal constant CONFIG_THROTTLES_INDEX = 3;
    uint8 internal constant CONFIG_DESCRIPTOR_INDEX = 4;

    /// @dev Config-time endpoint-manifest proof shape:
    ///      RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage]).
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 4;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidProofPayloadShape();
    error InvalidHeader();
    error InvalidConfigHeader();
    error InvalidConfigThrottleFieldCount();
    error InvalidTrustAnchorFields();
    error HandoffHeaderNotAscending(uint64 got, uint64 lastSeen);
    error CurrentHeaderBehindWalk(uint64 got, uint64 lastSeen);
    error UnknownValidatorMode(uint8 mode);
    error WrongSetCommitment(bytes32 got, bytes32 expected);
    error InvalidTrustedSet();

    function _decodePayload(bytes calldata proofBytes) internal pure returns (Memory.Slice[] memory payload) {
        if (proofBytes.length < 2) revert InvalidPayloadShape();
        payload = RLP.decodeList(proofBytes);
        if (payload.length != PAYLOAD_SHAPE_EXPECTED_FIELDS && payload.length != PAYLOAD_SHAPE_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }
    }

    function _decodeCurrentHeader(Memory.Slice item) internal pure returns (Memory.Slice[] memory header) {
        header = RLP.readList(item);
        if (header.length < MIN_BLOCK_HEADER_FIELDS || header.length > MAX_BLOCK_HEADER_FIELDS) {
            revert InvalidHeader();
        }
    }

    function _decodeHopHeader(Memory.Slice item) internal pure returns (Memory.Slice[] memory header) {
        header = RLP.readList(item);
        if (header.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidHeader();
    }

    function _headerNumber(Memory.Slice[] memory header) internal pure returns (uint64) {
        // Block numbers fit in 64 bits on every EVM chain; the cast only shapes the value.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(RLP.readUint256(header[BLOCK_HEADER_NUMBER_INDEX]));
    }

    function _headerStateRoot(Memory.Slice[] memory header) internal pure returns (bytes32) {
        return RLP.readBytes32(header[BLOCK_HEADER_STATE_ROOT_INDEX]);
    }

    function _decodeConfigProof(bytes calldata configProofBytes, uint256 expectedFields, uint8 headerIndex)
        internal
        pure
        returns (Memory.Slice[] memory proof, Memory.Slice[] memory header)
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        proof = RLP.decodeList(configProofBytes);
        if (proof.length != expectedFields) revert InvalidProofPayloadShape();
        header = RLP.readList(proof[headerIndex]);
        if (header.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidConfigHeader();
    }

    /// @dev The submitted member list, sorted and deduped, must hash to the anchor's commitment.
    ///      This method reads the list and verifies it.
    function _openCommitment(Memory.Slice listItem, bytes32 expected) internal pure returns (ValidatorSet memory set) {
        (address[] memory members, bool ok) = _readMemberList(listItem);
        if (!ok) revert InvalidTrustedSet();
        set.members = _sortedSet(members);
        _checkCommitment(set, expected);
    }

    /// @dev The (sorted, deduped) set must hash to the anchor's commitment.
    function _checkCommitment(ValidatorSet memory set, bytes32 expected) internal pure {
        bytes32 got = QbftValidators.commit(set);
        if (got != expected) revert WrongSetCommitment(got, expected);
    }

    function _isEmptyList(Memory.Slice item) internal pure returns (bool) {
        (uint256 ptr, uint256 itemEnd) = RlpCursor.bounds(item);
        (, uint256 len, bool isList) = RlpCursor.head(ptr, itemEnd);
        return isList && len == 0;
    }

    function _sortedSet(address[] memory members) internal pure returns (address[] memory) {
        if (QbftValidators.sortInPlace(members) != members.length) {
            return QbftValidators.sortedDedup(members);
        }
        return members;
    }

    /// @dev An RLP list `[address, ...]` read with the cursor: no per-item slice allocation.
    function _readMemberList(Memory.Slice listItem) internal pure returns (address[] memory members, bool ok) {
        (uint256 ptr, uint256 itemEnd) = RlpCursor.bounds(listItem);
        (uint256 cur, uint256 len, bool isList) = RlpCursor.head(ptr, itemEnd);
        uint256 end;
        unchecked {
            end = cur + len;
        }
        if (!isList || end != itemEnd) return (members, false);

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
            if (memberIsList || itemLen != 21) return (members, false);
            // We already made sure the item length is 21 in the line above.
            // forge-lint: disable-next-line(unsafe-typecast)
            address member = address(uint160(RlpCursor.uintValue(payloadPtr, payloadLen)));
            if (member == address(0)) return (members, false);
            members[i] = member;
            unchecked {
                cur = payloadPtr + payloadLen;
                i++;
            }
        }
        ok = true;
    }

    /// @dev Everything after the validator set is settled: the service account under `stateRoot`
    ///      (pinning `codeHash`), the channel slots, the bundle content, and the optional
    ///      endpoint-manifest update.
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
    ///      RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage]); the header
    ///      must be sealed by a quorum of `set`. The codeHash is not pinned here. The trust anchor
    ///      pins it at bundle time.
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

        bytes32 storageRoot =
            _verifyServiceStorageRoot(p[1], _headerStateRoot(hdr), _toAddress(serviceAddress), bytes32(0));
        return _verifyEndpointManifest(p[2], storageRoot, RLP.readBytes(p[3]), serviceAddress);
    }

    /// @dev The descriptor (config field 4) as its RLP items; word 0 must be the mode the caller
    ///      serves.
    function _decodeDescriptor(Memory.Slice[] memory proof, uint256 expectedFields, uint8 expectedMode)
        internal
        pure
        returns (Memory.Slice[] memory ta)
    {
        ta = RLP.decodeList(RLP.readBytes(proof[CONFIG_DESCRIPTOR_INDEX]));
        if (ta.length != expectedFields) revert InvalidTrustAnchorFields();
        uint256 mode = RLP.readUint256(ta[0]);
        if (mode != uint256(expectedMode)) {
            // The truncation only shapes the error argument on the reverting path; the check itself
            // compares the full word, so a value like 0x101 cannot pass as mode 1.
            // forge-lint: disable-next-line(unsafe-typecast)
            revert UnknownValidatorMode(uint8(mode));
        }
    }

    /// @dev Word 0 of an ABI-encoded trust anchor: the mode byte.
    function _anchorMode(bytes calldata trustAnchor) internal pure returns (uint8) {
        // The mode word holds a uint8; anything above is rejected by the caller's mode check.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(uint256(bytes32(trustAnchor[:32])));
    }
}
