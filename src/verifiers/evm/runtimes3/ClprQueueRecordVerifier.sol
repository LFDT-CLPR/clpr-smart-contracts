// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @title ClprQueueRecordVerifier
/// @notice Shared base for the verifiers of chains whose CLPR Service is not an EVM contract
///         (Initia MoveVM, Fuel Sway, Waves Ride). Each chain authenticates the record its own way,
///         but the record itself is one fixed byte layout, so the decode, the manifest binding and
///         the bundle-content decode live here.
///
/// ## The queue record (`ChannelQueue`, BCS)
/// ```move
/// struct ChannelQueue has store {
///     status: u8,                                 // ClprTypes.ChannelStatus
///     next_message_id: u64,                       // little-endian
///     received_message_id: u64,
///     sent_running_hash: vector<u8>,              // ULEB128 length 32, then 32 bytes
///     received_running_hash: vector<u8>,          // ULEB128 length 32, then 32 bytes
///     peer_endpoint_manifest_version: u64,        // QueueMetadata field 7
///     endpoint_manifest_commitment: vector<u8>,   // keccak256(ClprProtobuf manifest), or empty
/// }
/// ```
/// This is the Move family's record (Aptos, Sui) byte for byte, so one relay encoder serves all of
/// them. A Move service stores it with BCS; the Sway and Ride services write the same bytes.
/// The record is 92 bytes without a manifest commitment and 124 bytes with one.
///
/// @dev Reuses the bundle-content and manifest-sentinel helpers of {ClprEvmBundleVerifier}; none of
///      its Merkle-Patricia code is used.
abstract contract ClprQueueRecordVerifier is ClprEvmBundleVerifier {
    uint256 internal constant RECORD_LENGTH = 92;
    uint256 internal constant RECORD_LENGTH_WITH_COMMITMENT = 124;
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);

    error InvalidQueueRecord();
    error ManifestCommitmentAbsent();
    error WrongChainNamespace();

    /// @dev Decode a BCS `ChannelQueue` into queue metadata plus the committed manifest hash
    ///      (bytes32(0) when the record carries no commitment). Rejects any other length, a status
    ///      above the enum's maximum, a hash vector whose length is not 32 and a zero commitment.
    function _decodeQueueRecord(bytes memory record)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata, bytes32 manifestCommitment)
    {
        uint256 n = record.length;
        if (n != RECORD_LENGTH && n != RECORD_LENGTH_WITH_COMMITMENT) revert InvalidQueueRecord();
        uint8 status = uint8(record[0]);
        if (status > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        metadata.state = ClprTypes.ChannelStatus(status);
        metadata.nextMessageId = _le64(record, 1);
        metadata.receivedMessageId = _le64(record, 9);
        if (uint8(record[17]) != 32 || uint8(record[50]) != 32) revert InvalidQueueRecord();
        metadata.sentRunningHash = _word(record, 18);
        metadata.receivedRunningHash = _word(record, 51);
        metadata.endpointManifestVersion = _le64(record, 83);
        uint8 commitLen = uint8(record[91]);
        if (n == RECORD_LENGTH) {
            if (commitLen != 0) revert InvalidQueueRecord();
        } else {
            if (commitLen != 32) revert InvalidQueueRecord();
            manifestCommitment = _word(record, 92);
            if (manifestCommitment == bytes32(0)) revert InvalidQueueRecord();
        }
    }

    /// @dev Bind a manifest preimage to the commitment proven inside the queue record and decode it.
    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (commitment == bytes32(0)) revert ManifestCommitmentAbsent();
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev The configuration must name a chain of this verifier's CAIP-2 namespace, so a
    ///      configuration produced for another chain cannot seed this verifier's anchor.
    function _requireNamespace(string memory chainId, bytes memory prefix) internal pure {
        bytes memory c = bytes(chainId);
        if (c.length <= prefix.length) revert WrongChainNamespace();
        for (uint256 i = 0; i < prefix.length; i++) {
            if (c[i] != prefix[i]) revert WrongChainNamespace();
        }
    }

    /// @dev A 32-byte service address or object id from the opaque service-address bytes.
    function _bytes32Address(bytes memory b) internal pure returns (bytes32 a) {
        if (b.length != 32) revert InvalidServiceAddressLength();
        assembly ("memory-safe") {
            a := mload(add(b, 0x20))
        }
    }

    function _le64(bytes memory b, uint256 off) internal pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            v |= uint64(uint8(b[off + i])) << uint64(8 * i);
        }
    }

    function _word(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }
}
