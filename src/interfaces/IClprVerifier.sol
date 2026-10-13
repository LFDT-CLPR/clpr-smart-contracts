// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title IClprVerifier
/// @notice Interface for pluggable proof verification. Each channel specifies its own verifier.
interface IClprVerifier {
    /// @notice Verifies a bundle proof and extracts contents.
    /// @param proofBytes Opaque proof bytes from the peer ledger
    /// @param trustAnchor Current trust anchor bytes stored in the channel. Opaque to the
    ///        caller; the verifier defines its own encoding.
    /// @param channelContext Opaque bytes encoding the ChannelContext{channelId,
    ///         remoteServiceAddress} — static context created at channel setup time. Used by
    ///         verifiers to validate bundles originate from the expected peer channel.
    /// @return metadata ABI-decoded queue metadata from the proof
    /// @return messagePayloads Array of raw protobuf-encoded ClprMessagePayload bytes
    /// @return newTrustAnchor Updated trust anchor bytes if the finality proof contained a key
    ///         rotation or committee update; empty bytes if the anchor was not advanced.
    /// @return newTrustAnchorId Opaque identifier for `newTrustAnchor`
    /// @return newEndpointManifest Verified updated endpoint manifest if the bundle payload carried a
    ///         manifest proof; otherwise absent, signalled by `newEndpointManifest.version == 0`
    ///         (a present manifest always has version >= 1). The CLPR Service applies it only when
    ///         `version > Channel.endpointManifestVersion` (BundleLib Step 1b).
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        );

    /// @notice Verifies a config proof and an endpoint-manifest proof, and extracts peer configuration.
    /// @param configProofBytes Opaque config proof bytes from the peer ledger
    /// @param channelId The channelId of the channel being established.
    /// @param endpointManifestProofBytes Proof of the remote `ClprEndpointManifest`. MUST be verifiable
    ///        against the same initial trust anchor this call establishes.
    /// @return channelContext Opaque bytes encoding ChannelContext{channelId, serviceAddress}
    ///         — static data captured at channel setup time that does not evolve with the trust anchor.
    /// @return chainId Peer chain's CAIP-2 identifier
    /// @return serviceAddress Peer's CLPR service address (opaque bytes)
    /// @return peerConfigNanos Peer's config version timestamp (nanoseconds since epoch, uint96)
    /// @return throttles Peer's throttle configuration (used to populate Channel.peerThrottles)
    /// @return initialTrustAnchor Initial trust anchor bytes for this channel; opaque to the
    ///         protocol. Stateless verifiers return empty bytes.
    /// @return initialTrustAnchorId Opaque identifier for `initialTrustAnchor`
    ///         (LedgerConfiguration spec field 8). Non-empty iff `initialTrustAnchor` is
    ///         non-empty. Stored as Channel.trustAnchorId at completeChannel.
    /// @return endpointManifest The peer's verified initial `ClprEndpointManifest` (version >= 1).
    ///         Stored as the Channel's initial peer manifest. MUST NOT revert solely because the
    ///         endpoint list is empty. The verifier MUST revert if the manifest's serviceAddress does
    ///         not match ctx.remoteServiceAddress, or if the manifest version is 0.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        );
}
