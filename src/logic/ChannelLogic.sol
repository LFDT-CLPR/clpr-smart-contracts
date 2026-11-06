// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {ConnectorLib} from "@hiero-ledger/clpr/libraries/service/ConnectorLib.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {LogicModuleBase} from "@hiero-ledger/clpr/logic/base/LogicModuleBase.sol";
import {ECDSA} from "@hiero-ledger/clpr/libraries/crypto/ECDSA.sol";

/// @title ChannelLogic
/// @notice Channel lifecycle: register, complete, close, and inspect channels.
/// @dev Executed via delegatecall from ClprService. All state reads and writes
///      operate on ClprServiceStorage slots in the router's storage.
contract ChannelLogic is LogicModuleBase {
    uint8 private immutable PUB_KEY_LENGTH = 64;

    constructor() {}

    // ── Public views ───────────────────────────────────────────────────────

    /// @notice Returns true if `commitment` has been registered but not yet revealed.
    /// @param commitment The commitment hash to check.
    function pendingCommitments(bytes32 commitment) external view returns (bool) {
        return _pendingCommitments[commitment];
    }

    /// @notice Number of channels that have been completed (any status).
    function channelCount() external view returns (uint256) {
        return _channelCount;
    }

    /// @notice Returns the full channel record for `_channelId`.
    /// @dev Reverts with `ClprChannelNotFound` if the channel does not exist.
    /// @param _channelId The channel identifier.
    function getChannel(bytes32 _channelId) external view returns (ClprTypes.Channel memory) {
        if (!_channelExists[_channelId]) revert ClprTypes.ClprChannelNotFound();
        return _channels[_channelId];
    }

    /// @notice Return the Channel's cached peer `ClprEndpointManifest`.
    /// @dev The manifest is stored out-of-line from the Channel struct (see
    ///      `ClprServiceStorage._peerEndpointManifests`). Returns a zero manifest (version 0)
    ///      for an unknown channel or one completed without a manifest proof (bring-up).
    /// @param _channelId The channel whose cached peer manifest to return.
    function getPeerEndpointManifest(bytes32 _channelId) external view returns (ClprTypes.ClprEndpointManifest memory) {
        return _peerEndpointManifests[_channelId];
    }

    /// @notice Return the per-Channel peer endpoint roster (legacy view shape).
    /// @dev Derived on the fly from the cached peer manifest — nothing is stored in roster
    ///      shape any more, so the roster can never go stale relative to the manifest.
    ///      Returns an empty array for an unknown channel or an empty manifest.
    /// @param _channelId The channel whose roster to return.
    function getPeerEndpointRoster(bytes32 _channelId) external view returns (ClprTypes.PeerEndpoint[] memory) {
        ClprTypes.Endpoint[] storage eps = _peerEndpointManifests[_channelId].endpoints;
        uint256 len = eps.length;
        ClprTypes.PeerEndpoint[] memory roster = new ClprTypes.PeerEndpoint[](len);
        for (uint256 i = 0; i < len; i++) {
            ClprTypes.Endpoint storage ep = eps[i];
            roster[i] = ClprTypes.PeerEndpoint({
                ipAddress: bytes(ep.ipAddress),
                port: ep.port,
                tlsCertificate: ep.tlsCertificate,
                accountId: ep.accountId,
                registered: true
            });
        }
        return roster;
    }

    // ── Channel lifecycle ───────────────────────────────────────────────

    /// @notice Register a channel commitment (commit phase of commit-reveal).
    /// @dev The `channelId` is stored in a reverse index so that `closeChannel`
    ///      can find and delete the pending commitment for not-yet-revealed channels.
    ///      The service does NOT verify channelId at this phase — verification happens
    ///      at completeChannel. Callers must supply the correct channelId (from
    ///      deriveChannelId) or closeChannel will not be able to clean up the entry.
    ///      Emits {ChannelRegistered}.
    /// @param channelId Deterministic id derived via deriveChannelId.
    /// @param commitment keccak256(channelId || pubKey) binding the reveal.
    function registerChannel(bytes32 channelId, bytes32 commitment) external onlyService whenEnabled {
        _pendingCommitments[commitment] = true;
        // Build reverse index: channelId => commitment for closeChannel lookups.
        // Only write if not already set — a re-register of the same channelId keeps
        // the original commitment mapping so a duplicate commitment doesn't overwrite.
        if (_channelIdToCommitment[channelId] == bytes32(0)) {
            _channelIdToCommitment[channelId] = commitment;
        }
        emit ChannelRegistered(commitment);
    }

    /// @notice Reveal and complete a previously registered channel commitment.
    /// @dev Verifies the commitment, checks the ECDSA signature over
    ///      keccak256(channelId || address(this)) — binding the reveal to this
    ///      specific ClprService deployment — then calls verifier.verifyConfig to
    ///      validate the peer chain's configuration and creates the channel record.
    ///      Emits {ChannelCompleted} and {ChannelStatusChanged}.
    /// @param _channelId The channel identifier (must match a pending commitment).
    /// @param pubKey Raw 64-byte uncompressed ECDSA public key of the peer operator.
    /// @param sig ECDSA signature over keccak256(channelId || address(this)).
    /// @param salt Entropy used when the channelId was derived.
    /// @param verifier Address of the IClprVerifier contract for this peer chain.
    /// @param configProof Opaque proof bytes passed to verifier.verifyConfig.
    /// @param endpointManifestProof Proof of the peer's `ClprEndpointManifest`, passed to
    ///        verifier.verifyConfig as its third argument. Must be verifiable against the same
    ///        initial trust anchor the config proof establishes. Empty for bring-up: the
    ///        Channel then starts with an uninitialized (version 0) peer manifest and the
    ///        first manifest-carrying bundle populates it via Step 1b.
    function completeChannel(
        bytes32 _channelId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        address verifier,
        bytes calldata configProof,
        bytes calldata endpointManifestProof
    ) external onlyService whenEnabled {
        if (pubKey.length != PUB_KEY_LENGTH) {
            revert ClprTypes.ClprInvalidSignature();
        }
        if (economicConfig.maxChannels > 0 && _channelCount >= economicConfig.maxChannels) {
            revert ClprTypes.ClprTooManyChannels();
        }
        if (_channelExists[_channelId]) revert ClprTypes.ClprChannelAlreadyExists();

        bytes32 commitment = keccak256(abi.encodePacked(_channelId, pubKey));
        if (!_pendingCommitments[commitment]) revert ClprTypes.ClprCommitmentMismatch();

        ECDSA._verifySignature(_channelId, pubKey, sig);
        if (verifier.code.length == 0) revert ClprTypes.ClprInvalidVerifierContract();

        _createChannel(_channelId, commitment, pubKey, salt, verifier, configProof, endpointManifestProof);
    }

    /// @notice Close a channel or abandon an unfinished pending commitment.
    /// @dev Owner-only. Handles three cases:
    ///
    ///      1. **Active/Paused channel** — transitions the channel to CLOSING, advancing
    ///         straight to DRAINED in the same call if no Data Messages remain
    ///         in the outbound queue. Also deletes any pending commitment that
    ///         shares this channelId (e.g. if the same operator registered a
    ///         commitment but the channel was completed via a separate reveal flow).
    ///
    ///      2. **Drained channel** — closes directly to CLOSED, but only once
    ///         every outbound message has been acknowledged; reverts with
    ///         `ClprInvalidChannelStatus` otherwise.
    ///
    ///      3. **Pending-only** (registered commitment, no completeChannel yet) —
    ///         the channel does not exist in `_channels`, so we look up the
    ///         pending commitment via the reverse index (`_channelIdToCommitment`)
    ///         and delete it. This allows an admin to close an
    ///         abandoned commitment without it accruing forever.
    ///
    ///      Reverts with `ClprInvalidChannelStatus` if the channel exists but is
    ///      in some status other than ACTIVE, PAUSED, or DRAINED (e.g. already
    ///      CLOSING or CLOSED), and with `ClprChannelNotFound` if neither a
    ///      channel record nor a pending commitment exists for the given
    ///      channelId.
    /// @param _channelId The channel or pending commitment to close.
    function closeChannel(bytes32 _channelId) external onlyService whenEnabled {
        if (_channelExists[_channelId]) {
            ClprTypes.Channel storage channel = _channels[_channelId];

            // DRAINED: admin recovery path — when the endpoint cannot deliver the
            // close-notification bundle, the admin may force-close directly to CLOSED,
            // but only once every outbound message (including in-flight Responses
            // generated during CLOSING) has been acknowledged; otherwise this would
            // abandon a message the peer never received.
            if (channel.status == ClprTypes.ChannelStatus.DRAINED) {
                if (!BundleLib._allOutboundAcked(channel.nextMessageId, channel.ackedMessageId)) {
                    revert ClprTypes.ClprInvalidChannelStatus();
                }
                channel.status = ClprTypes.ChannelStatus.CLOSED;
                emit ChannelStatusChanged(_channelId, ClprTypes.ChannelStatus.CLOSED);
                return;
            }

            if (channel.status != ClprTypes.ChannelStatus.ACTIVE && channel.status != ClprTypes.ChannelStatus.PAUSED) {
                revert ClprTypes.ClprInvalidChannelStatus();
            }
            channel.status = ClprTypes.ChannelStatus.CLOSING;
            emit ChannelStatusChanged(_channelId, ClprTypes.ChannelStatus.CLOSING);

            // Same drain condition the bundle path uses for CLOSING -> DRAINED: skip
            // straight to DRAINED when the outbound queue is already empty.
            if (BundleLib._allDataAcked(channel.lastDataMessageId, channel.ackedMessageId, channel.nextExpectedReplyId))
            {
                channel.status = ClprTypes.ChannelStatus.DRAINED;
                emit ChannelStatusChanged(_channelId, ClprTypes.ChannelStatus.DRAINED);
            }

            // Also delete any pending commitment for this channelId (belt-and-suspenders:
            // normally completeChannel already deleted it, but clean up if not).
            bytes32 pendingForCleanup = _channelIdToCommitment[_channelId];
            if (pendingForCleanup != bytes32(0) && _pendingCommitments[pendingForCleanup]) {
                delete _pendingCommitments[pendingForCleanup];
                delete _channelIdToCommitment[_channelId];
            } else if (_pendingCommitments[channel.ownershipCommitment]) {
                // Fallback: use the commitment stored on the Channel record itself.
                delete _pendingCommitments[channel.ownershipCommitment];
            }
            return;
        }
        // pending-only path
        bytes32 pending = _channelIdToCommitment[_channelId];
        if (pending == bytes32(0) || !_pendingCommitments[pending]) revert ClprTypes.ClprChannelNotFound();

        delete _pendingCommitments[pending];
        delete _channelIdToCommitment[_channelId];
    }

    /// @notice Compute the deterministic channel identifier for a peer.
    /// @dev Chain IDs are lexicographically sorted before hashing so the id is
    ///      symmetric: both ends of the channel derive the same value.
    ///      Formula: keccak256(sort(localChainId, peerChainId) || pubKey || salt).
    /// @param peerChainId Human-readable chain identifier of the peer (e.g. "hedera-mainnet").
    /// @param pubKey Raw 64-byte uncompressed ECDSA public key of the peer operator.
    /// @param salt Caller-chosen entropy to allow multiple channels to the same peer.
    /// @return Deterministic channel identifier.
    function deriveChannelId(string calldata peerChainId, bytes calldata pubKey, bytes32 salt)
        external
        view
        returns (bytes32)
    {
        return _deriveChannelId(peerChainId, pubKey, salt);
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /// @dev Allocates and initialises the Channel storage record after commitment
    ///      and signature verification. Calls verifier.verifyConfig to extract peer
    ///      chain parameters and the initial peer endpoint manifest, validates the
    ///      derived channelId, deletes the pending commitment, and emits
    ///      ChannelCompleted and ChannelStatusChanged(ACTIVE).
    function _createChannel(
        bytes32 _channelId,
        bytes32 commitment,
        bytes calldata pubKey,
        bytes32 salt,
        address verifier,
        bytes calldata configProof,
        bytes calldata endpointManifestProof
    ) internal {
        (
            bytes memory ctxBytes,
            string memory peerChainId,
            bytes memory peerServiceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory peerThrottles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        ) = IClprVerifier(verifier).verifyConfig(configProof, _channelId, endpointManifestProof);

        ClprTypes.validateThrottles(peerThrottles);
        bytes32 expected = _deriveChannelId(peerChainId, pubKey, salt);
        if (_channelId != expected) revert ClprTypes.ClprInvalidChannelId();

        ClprTypes.Channel storage channel = _channels[_channelId];
        channel.channelId = _channelId;
        channel.chainId = peerChainId;
        channel.peerServiceAddress = peerServiceAddress;
        channel.verifier = verifier;
        channel.status = ClprTypes.ChannelStatus.ACTIVE;
        channel.nextMessageId = 1;
        channel.nextExpectedReplyId = 1;
        channel.peerConfigTimestamp = peerConfigNanos;
        channel.peerThrottles = peerThrottles;
        channel.lastConfigTimestamp = uint96(block.timestamp) * 1_000_000_000;
        channel.ownershipCommitment = commitment;
        channel.salt = salt;
        channel.trustAnchor = initialTrustAnchor;
        channel.trustAnchorId = initialTrustAnchorId;
        channel.channelContext = ctxBytes;
        // Store the verified initial peer endpoint manifest out-of-line (an empty endpoint list is
        // allowed). A proof-backed manifest is version >= 1; version 0 means no manifest proof was
        // supplied (bring-up) — the Channel starts uninitialized and the first proven manifest
        // (version >= 1 > 0) populates it via BundleLib Step 1b. The endpoint list is truncated to
        // the local maxPeerEndpoints throttle (0 = no limit) before storing.
        ClprTypes.truncateEndpoints(endpointManifest, _config.throttles.maxPeerEndpoints);
        _peerEndpointManifests[_channelId] = endpointManifest;
        channel.endpointManifestVersion = endpointManifest.version;
        _channelExists[_channelId] = true;
        unchecked {
            _channelCount++;
        }

        delete _pendingCommitments[commitment];
        // Clean up reverse index now that the channel is fully revealed.
        delete _channelIdToCommitment[_channelId];

        emit ChannelCompleted(_channelId, peerChainId, peerServiceAddress, verifier, keccak256(verifier.code));
        emit ChannelStatusChanged(_channelId, ClprTypes.ChannelStatus.ACTIVE);
    }

    /// @dev Lexicographically orders two chain IDs by keccak256 so that channelId
    ///      derivation is symmetric. Returns (lo, hi) where keccak256(lo) <= keccak256(hi).
    function _sortChains(string memory x, string memory y) internal pure returns (bytes memory lo, bytes memory hi) {
        bytes memory bx = bytes(x);
        bytes memory by = bytes(y);
        if (bx.length == 0 || by.length == 0) revert ClprTypes.ClprInvalidChainId();
        if (keccak256(bx) <= keccak256(by)) {
            return (bx, by);
        }
        return (by, bx);
    }

    /// @dev Core channelId derivation: keccak256(sort(localChainId, peerChainId) || pubKey || salt).
    ///      Sorting ensures the id is identical on both ends of the channel.
    function _deriveChannelId(string memory peerChainId, bytes calldata pubKey, bytes32 salt)
        internal
        view
        returns (bytes32)
    {
        (bytes memory a, bytes memory b) = _sortChains(_config.chainId, peerChainId);

        // Can be slither disabled because:
        // - chain IDs are canonical protocol identifiers
        // - pubKey has fixed protocol-defined length
        // - ordering is canonicalized via _sortChains
        // - hash format is compatibility critical
        // slither-disable-next-line encode-packed-collision
        return keccak256(abi.encodePacked(a, b, pubKey, salt));
    }
}
