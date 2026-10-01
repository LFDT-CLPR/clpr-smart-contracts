// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";

/// @title ClprRecordVerifierBase
/// @notice Shared half of the verifiers for ledgers whose CLPR endpoint publishes a
///         {ClprQueueRecord} instead of exposing EVM storage (XRPL, HyperEVM, Mixin). Each concrete
///         verifier authenticates the record its own way (validations + SHAMap, attested block +
///         receipt, kernel CoSi + transaction); this base turns an authenticated record into queue
///         metadata, a verified LedgerConfiguration and a verified endpoint manifest.
/// @dev Reuses the bundle-content decode and manifest sentinels of {ClprEvmBundleVerifier}.
abstract contract ClprRecordVerifierBase is ClprEvmBundleVerifier {
    /// @dev keccak256 of the CAIP-2 chain id this verifier serves.
    bytes32 internal immutable CHAIN_ID_HASH;

    error RecordChannelMismatch(bytes32 expected, bytes32 actual);
    error ConfigHashMismatch();
    error WrongChain(string chainId);
    error ManifestNotCommitted();

    constructor(string memory caip2) {
        CHAIN_ID_HASH = keccak256(bytes(caip2));
    }

    /// @dev A bundle record must name this channel (a zero channel id is only valid at config).
    function _requireChannel(ClprQueueRecord.Record memory r, bytes32 channelId) internal pure {
        if (r.channelId != channelId || channelId == bytes32(0)) revert RecordChannelMismatch(channelId, r.channelId);
    }

    /// @dev Config: the record must be a service-level record (channel 0) or this channel's, and its
    ///      configHash must commit to the supplied LedgerConfiguration control message.
    function _verifiedConfig(ClprQueueRecord.Record memory r, bytes32 channelId, bytes memory controlMessage)
        internal
        view
        returns (ClprTypes.LedgerConfiguration memory lc)
    {
        if (r.channelId != bytes32(0) && r.channelId != channelId) {
            revert RecordChannelMismatch(channelId, r.channelId);
        }
        if (keccak256(controlMessage) != r.configHash) revert ConfigHashMismatch();
        lc = ClprProtobuf.decodeControlMessage(controlMessage).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChain(lc.chainId);
    }

    /// @dev Bind a manifest preimage to the record's manifest commitment (the same rules as the
    ///      storage-slot path: version >= 1 and the service address must match).
    function _recordManifest(ClprQueueRecord.Record memory r, bytes memory preimage, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        if (r.manifestCommitment == bytes32(0)) revert ManifestNotCommitted();
        if (keccak256(preimage) != r.manifestCommitment) revert ManifestCommitmentMismatch();
        m = ClprProtobuf.decodeEndpointManifest(preimage);
        if (m.version == 0) revert ManifestVersionZero();
        if (keccak256(m.serviceAddress) != keccak256(serviceAddress)) revert ManifestServiceAddressMismatch();
    }

    /// @dev Config-time manifest: empty proof is bring-up (version 0), else the proof IS the preimage.
    function _configManifest(ClprQueueRecord.Record memory r, bytes calldata proof, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        if (proof.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        return _recordManifest(r, proof, serviceAddress);
    }
}
