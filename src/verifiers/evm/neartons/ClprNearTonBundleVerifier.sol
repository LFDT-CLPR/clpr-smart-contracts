// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @title ClprNearTonBundleVerifier
/// @notice Shared CLPR plumbing for the NEAR and TON verifiers. Both chains run a non-EVM CLPR
///         Service that keeps the same three facts the EVM service keeps in storage slots:
///
///         | fact | EVM ClprService | NEAR / TON service |
///         |---|---|---|
///         | per-channel queue state | `Channel` slots +1, +2, +4, +5, +16 | one `ChannelQueue` record per channel |
///         | endpoint-manifest commitment | slot 18 | one 32-byte service-wide value |
///         | configuration commitment | proven `_config.serviceAddress` | one 32-byte service-wide value: keccak256 of the ControlMessage bytes |
///
///         The `ChannelQueue` record has the fields of `ClprTypes.QueueMetadata`:
///         `status u8, next_message_id u64, received_message_id u64, sent_running_hash [32],
///         received_running_hash [32], endpoint_manifest_version u64` (89 bytes of payload; NEAR stores
///         it as Borsh, TON as one 712-bit cell). Message payloads travel in `ClprBundleContent` and
///         ClprService authenticates them against the proven `sent_running_hash`, as for every peer.
abstract contract ClprNearTonBundleVerifier is ClprEvmBundleVerifier {
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);

    error InvalidQueueRecord();
    error WrongChainId();
    error ConfigCommitmentMismatch();
    error InvalidServiceAddress();

    /// @dev Bind a manifest preimage to the proven service-wide commitment and decode it.
    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev Decode the ControlMessage bytes whose keccak256 the peer service stores as its
    ///      configuration commitment, after checking that commitment.
    function _bindConfig(bytes memory controlMessage, bytes32 commitment, bytes32 expectedChainIdHash)
        internal
        pure
        returns (ClprTypes.LedgerConfiguration memory lc)
    {
        if (keccak256(controlMessage) != commitment) revert ConfigCommitmentMismatch();
        lc = ClprProtobuf.decodeControlMessage(controlMessage).config;
        if (keccak256(bytes(lc.chainId)) != expectedChainIdHash) revert WrongChainId();
    }

    function _queueMetadata(
        uint8 status,
        uint64 nextMessageId,
        uint64 receivedMessageId,
        bytes32 sentRunningHash,
        bytes32 receivedRunningHash,
        uint64 endpointManifestVersion
    ) internal pure returns (ClprTypes.QueueMetadata memory metadata) {
        if (status > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        metadata = ClprTypes.QueueMetadata({
            nextMessageId: nextMessageId,
            sentRunningHash: sentRunningHash,
            receivedMessageId: receivedMessageId,
            receivedRunningHash: receivedRunningHash,
            state: ClprTypes.ChannelStatus(status),
            endpointManifestVersion: endpointManifestVersion
        });
    }

    function _bytes32At(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }
}
