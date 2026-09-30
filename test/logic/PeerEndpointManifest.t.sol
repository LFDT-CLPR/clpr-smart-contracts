// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "../../src/libraries/ClprTypes.sol";
import {ClprProtobuf} from "../../src/libraries/codec/ClprProtobuf.sol";
import {ClprTestBase} from "../helpers/ClprTestBase.sol";
import {BundleLib} from "../../src/libraries/service/BundleLib.sol";

/// @notice Peer endpoint manifest lifecycle: initial population at completeChannel,
///         out-of-line storage, Step 1b bundle updates, maxPeerEndpoints truncation,
///         version-0 bring-up, and local-manifest commitment coherence.
contract PeerEndpointManifestTest is ClprTestBase {
    /// @dev Absolute storage slot of `EndpointManifestState.commitment` (base 17 + member 1),
    ///      mirrored by ClprEvmBundleVerifier.ENDPOINT_MANIFEST_COMMITMENT_SLOT.
    uint256 internal constant COMMITMENT_SLOT = 18;

    function _endpoint(bytes memory accountId) internal pure returns (ClprTypes.Endpoint memory) {
        return ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: hex"", accountId: accountId});
    }

    function _manifest(uint64 version, uint256 endpointCount)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.version = version;
        m.serviceAddress = hex"AABB"; // matches MockClprVerifier's configured service address
        m.endpoints = new ClprTypes.Endpoint[](endpointCount);
        for (uint256 i = 0; i < endpointCount; i++) {
            // casting to 'uint8' is safe because tests build manifests of at most a handful of
            // endpoints (endpointCount <= 5), so i + 1 never exceeds 255.
            // forge-lint: disable-next-line(unsafe-typecast)
            m.endpoints[i] = _endpoint(abi.encodePacked(uint8(i + 1)));
        }
    }

    /// @dev A no-op queue metadata so a bundle's only progress is the manifest (Criterion 5).
    function _noOpMetadata() internal pure returns (ClprTypes.QueueMetadata memory) {
        return ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
    }

    // ── Initial population at completeChannel ───────────────────────────

    function test_completeChannel_storesManifestOutOfLine() public {
        // setUp seeded a version-1 manifest with one endpoint (accountId 0x01).
        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 1, "stored manifest version");
        assertEq(stored.endpoints.length, 1, "stored manifest endpoint count");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.endpointManifestVersion, 1, "Channel.endpointManifestVersion");
    }

    /// @dev Bring-up: no manifest proof — verifier returns the UNINITIALIZED (version 0)
    ///      manifest and the Channel starts with endpointManifestVersion = 0.
    function test_completeChannel_bringUp_storesUninitializedVersion0() public {
        verifier.setEndpointManifest(_manifest(0, 0));
        bytes32 connId = _openExtraChannel(bytes32(uint256(1)));

        assertEq(service.getChannel(connId).endpointManifestVersion, 0, "version-0 bring-up accepted");
        assertEq(service.getPeerEndpointManifest(connId).version, 0);
        assertEq(service.getPeerEndpointRoster(connId).length, 0);
    }

    function test_completeChannel_truncatesToMaxPeerEndpoints() public {
        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxPeerEndpoints = 1;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");

        verifier.setEndpointManifest(_manifest(1, 3));
        bytes32 connId = _openExtraChannel(bytes32(uint256(2)));

        assertEq(service.getPeerEndpointManifest(connId).endpoints.length, 1, "manifest truncated to cap");
        assertEq(service.getPeerEndpointRoster(connId).length, 1, "derived roster matches truncated manifest");
    }

    // ── Step 1b: manifest updates through bundles ──────────────────────────

    /// @dev Regression for the version-1 collision: a Channel bootstrapped without a
    ///      manifest proof (version 0) must accept a peer's genuine version-1 manifest —
    ///      the very first version a fresh remote CLPR Service advertises.
    function test_step1b_bringUpChannel_acceptsPeerVersion1Manifest() public {
        verifier.setEndpointManifest(_manifest(0, 0));
        bytes32 connId = _openExtraChannel(bytes32(uint256(3)));
        assertEq(service.getChannel(connId).endpointManifestVersion, 0);

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(1, 2));
        service.submitBundle(connId, hex"00FF");

        assertEq(service.getChannel(connId).endpointManifestVersion, 1, "v1 > 0 must apply");
        assertEq(service.getPeerEndpointManifest(connId).endpoints.length, 2, "manifest replaced");
    }

    /// @dev A manifest-only bundle (no messages, no ack, no anchor) satisfies Progress
    ///      Criterion 5 and atomically replaces the cached manifest.
    function test_step1b_manifestOnlyBundle_appliesAndSatisfiesCriterion5() public {
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(7, 2));
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 7, "manifest version advanced");
        assertEq(stored.endpoints.length, 2, "manifest fully replaced");
        assertEq(service.getChannel(channelId).endpointManifestVersion, 7);

        // The derived roster can never go stale relative to the manifest.
        assertEq(service.getPeerEndpointRoster(channelId).length, 2, "derived roster follows update");
    }

    /// @dev A stale manifest (version <= stored) is silently skipped; with no other
    ///      progress criterion satisfied, the NoProgress rejection applies.
    function test_step1b_staleManifest_skippedAndNoProgressReverts() public {
        // setUp stored version 1; an equal-version manifest does not satisfy Criterion 5.
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(1, 2));

        vm.expectRevert(BundleLib.NoProgress.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 1, "stale manifest not applied");
    }

    function test_step1b_truncatesToMaxPeerEndpoints() public {
        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxPeerEndpoints = 2;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 5));
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2, "Step 1b truncated to cap");
        assertEq(service.getChannel(channelId).endpointManifestVersion, 2);
    }

    // ── Local manifest commitment coherence ────────────────────────────────

    function _storedCommitment() internal view returns (bytes32) {
        return vm.load(address(service), bytes32(COMMITMENT_SLOT));
    }

    function _expectedCommitment() internal returns (bytes32) {
        return keccak256(ClprProtobuf.encodeEndpointManifest(service.getEndpointManifest()));
    }

    /// @dev The commitment slot must always bind the manifest getEndpointManifest() returns —
    ///      from genesis (empty version-1 manifest), through serviceAddress changes (the
    ///      address is part of the committed encoding), and endpoint admission.
    function test_manifestCommitment_coherentAcrossLifecycle() public {
        // (a) Genesis: seeded in the constructor, so the empty v1 manifest is provable.
        assertEq(_storedCommitment(), _expectedCommitment(), "genesis commitment");

        // (b) serviceAddress change re-syncs the commitment without a version bump.
        uint64 versionBefore = service.getEndpointManifest().version;
        service.updateLedgerConfiguration(hex"9999", defaultThrottles, "", "");
        assertEq(_storedCommitment(), _expectedCommitment(), "commitment after serviceAddress change");
        assertEq(service.getEndpointManifest().version, versionBefore, "no version bump on address change");

        // (c) Endpoint admission bumps the version and refreshes the commitment.
        service.addEndpoint(address(0xE1), _endpoint(hex"E1"));
        assertEq(service.getEndpointManifest().version, versionBefore + 1, "version bump on admission");
        assertEq(_storedCommitment(), _expectedCommitment(), "commitment after admission");
    }

    /// @dev A manifest-update bundle against a PENDING Channel is rejected.
    function test_manifestBundle_pendingChannel_rejected() public {
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(channelId, uint256(15)))) + 1);
        bytes32 packed = vm.load(address(service), slot1);

        packed &= ~bytes32(uint256(0xFF) << 160);
        vm.store(address(service), slot1, packed);

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "manifest untouched");
    }

    /// @dev CLOSING Channels continue to accept manifest-update bundles (a manifest-only
    ///      bundle satisfying Criterion 5 alone is accepted), and — with nothing to drain —
    ///      the state machine walks CLOSING → DRAINED, which also continues to accept them.
    function test_manifestBundle_acceptedOnClosingAndDrained() public {
        service.closeChannel(channelId);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING));

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).endpointManifestVersion, 2, "applied on CLOSING");
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED));

        // Manifest-only bundle against DRAINED, but still accepted and applied
        verifier.setNewEndpointManifest(_manifest(3, 2));
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).endpointManifestVersion, 3, "applied on DRAINED");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    /// @dev For a bundle carrying BOTH a manifest update and a trust-anchor rotation
    ///      the manifest is applied at before the anchor advances at Step 1c (two
    ///      updates land in the same transaction).
    function test_step1b1c_manifestAndRotation_bothCommitted() public {
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(4, 2));
        verifier.setNewTrustAnchor(hex"A11C");
        verifier.setNewTrustAnchorId(hex"1D");

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.endpointManifestVersion, 4, "manifest committed");
        assertEq(keccak256(channel.trustAnchor), keccak256(hex"A11C"), "anchor advanced");
        assertEq(keccak256(channel.trustAnchorId), keccak256(hex"1D"), "anchor id advanced");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2);
    }

    /// @dev When a bundle carrying a manifest update reverts in a LATER step,
    ///      the manifest update MUST NOT survive.
    function test_step1b_revertAfterManifestUpdate_leavesNoPartialCommit() public {
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = hex"0A00";
        ClprTypes.QueueMetadata memory meta = _noOpMetadata();
        meta.nextMessageId = 2; // one new message...
        meta.sentRunningHash = bytes32(uint256(0xBAD)); // ...with a wrong running hash
        meta.lastMessageId = 1;
        meta.lastMessageRunningHash = meta.sentRunningHash;

        verifier.setVerifyBundleResult(meta, msgs);
        verifier.setNewEndpointManifest(_manifest(9, 3));
        verifier.setNewTrustAnchor(hex"A11C");
        verifier.setNewTrustAnchorId(hex"1D");

        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.endpointManifestVersion, 1, "manifest rolled back");
        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "stored manifest rolled back");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 1, "endpoints rolled back");
        assertEq(channel.trustAnchor.length, 0, "anchor rolled back");
    }

    function _syncByteThrottles(uint64 maxSyncBytes) internal view returns (ClprTypes.Throttles memory t) {
        t = defaultThrottles;
        t.maxSyncBytes = maxSyncBytes;
    }

    /// @dev A bundle whose manifest proof pushes the payload over the local max_sync_bytes is
    ///      rejected.
    function test_manifestBundle_overMaxSyncBytes_rejected() public {
        service.updateLedgerConfiguration(hex"1234", _syncByteThrottles(100), "", "");

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));

        bytes memory oversized = new bytes(101);
        vm.expectRevert(BundleLib.BundleTooLarge.selector);
        service.submitBundle(channelId, oversized);

        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "manifest not applied");
    }

    /// @dev A manifest-only bundle whose proof fits within max_sync_bytes passes
    ///      the size check and is applied.
    function test_manifestOnlyBundle_withinMaxSyncBytes_accepted() public {
        service.updateLedgerConfiguration(hex"1234", _syncByteThrottles(100), "", "");

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));

        service.submitBundle(channelId, new bytes(100)); // exactly at the limit

        assertEq(service.getPeerEndpointManifest(channelId).version, 2, "manifest applied");
    }

    /// @dev A manifest bundle too large for max_sync_bytes fails, but after admin
    ///      updates limits the SAME bundle succeeds.
    function test_manifestBundle_recoverableAfterMaxSyncBytesRaise() public {
        service.updateLedgerConfiguration(hex"1234", _syncByteThrottles(100), "", "");

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));
        bytes memory proof = new bytes(150);

        vm.expectRevert(BundleLib.BundleTooLarge.selector);
        service.submitBundle(channelId, proof);
        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "not applied while too large");

        // Now it works.
        service.updateLedgerConfiguration(hex"1234", _syncByteThrottles(200), "", "");
        service.submitBundle(channelId, proof);

        assertEq(service.getPeerEndpointManifest(channelId).version, 2, "applied after the raise");
    }

    receive() external payable {}
}
