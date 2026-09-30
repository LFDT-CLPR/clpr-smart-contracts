// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @title ClprManifestServiceComplianceTest
/// @notice Spec-compliance cases for the CLPR **Service's** endpoint-manifest obligations: when a
///         manifest returned by `verifyBundle` advances the Channel's cached manifest, how it is
///         stored, which Channel states accept a manifest-bearing bundle, and how a manifest
///         update composes with the trust-anchor update in the same bundle.
///
/// @dev These are deliberately NOT in `ClprVerifierComplianceTest`. They are obligations of the
///      Service, not of any verifier: the Service only ever sees the manifest a verifier returned,
///      so the behaviour is identical for QBFT, Sei, Ethereum and Hiero, and asserting it needs
///      direct control over Channel state and over successive manifest versions — which real
///      cryptographic fixtures cannot express. The verifier-side obligations (proving a manifest,
///      binding it to the on-ledger commitment, rejecting version 0 / a foreign service address)
///      live in test/verifiers/compliance/ and run against every real verifier.
///
///      `ClprTestBase.setUp` opens an ACTIVE channel whose cached peer manifest is version 1 with
///      a single endpoint; every case below starts from that state.
contract ClprManifestServiceComplianceTest is ClprTestBase {
    // ── helpers ───────────────────────────────────────────────────────────────

    /// @dev A manifest at `version` carrying `endpointCount` endpoints whose accountIds are
    ///      1..endpointCount, so a replacement can be told apart from a merge by inspecting them.
    ///      `serviceAddress` matches MockClprVerifier's configured peer service address.
    function _manifest(uint64 version, uint256 endpointCount)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.version = version;
        m.serviceAddress = hex"AABB";
        m.endpoints = new ClprTypes.Endpoint[](endpointCount);
        for (uint256 i = 0; i < endpointCount; i++) {
            m.endpoints[i] = ClprTypes.Endpoint({
                ipAddress: "10.0.0.1",
                port: 50211,
                tlsCertificate: hex"",
                // casting to 'uint8' is safe because these fixtures build at most a handful of
                // endpoints, so i + 1 never exceeds 255.
                // forge-lint: disable-next-line(unsafe-typecast)
                accountId: abi.encodePacked(uint8(i + 1))
            });
        }
    }

    /// @dev Queue metadata describing no queue movement at all, so a bundle's only possible
    ///      progress is a manifest advance (Progress Criterion 5) or a trust-anchor update.
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

    /// @dev The absent-manifest sentinel every verifier returns when a bundle carries no manifest
    ///      proof: version 0 and no endpoints.
    function _absentManifest() internal pure returns (ClprTypes.ClprEndpointManifest memory) {
        return _manifest(0, 0);
    }

    /// @dev Submit a bundle whose single inbound message is `payload`, with the running hash the
    ///      Service recomputes over it, so the bundle progresses through hash verification and
    ///      message dispatch rather than stopping at the manifest step.
    function _submitBundleWithMessage(bytes memory payload) internal {
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload;
        ClprTypes.QueueMetadata memory meta = _noOpMetadata();
        meta.nextMessageId = 2;
        meta.sentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        meta.lastMessageId = 1;
        meta.lastMessageRunningHash = meta.sentRunningHash;
        verifier.setVerifyBundleResult(meta, msgs);
        service.submitBundle(channelId, hex"00FF");
    }

    /// @dev A CONTROL message the Service can dispatch without a connector or application: it
    ///      carries a well-formed peer LedgerConfiguration and lands as a peerConfigTimestamp update.
    function _controlPayload(uint96 nanos) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory cfg;
        cfg.protocolVersion = 1; // must match the deployed service's protocolVersion
        cfg.nanosSinceEpoch = nanos;
        cfg.throttles = defaultThrottles;
        return ClprProtobuf.encodeControlMessage(cfg);
    }

    // ── Endpoint manifest advancement ─────────────────────────────────────────

    /// @dev Spec: a bundle containing only a manifest proof with an advancing version (no
    ///      application messages, no trust anchor update, no ack progress, no channel-state
    ///      transition) is accepted by the CLPR Service.
    function test_compliance_manifestOnlyBundle_advancesManifest() public {
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(7, 2));

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 7, "manifest version advanced");
        assertEq(stored.endpoints.length, 2, "manifest endpoints stored");
        assertEq(service.getChannel(channelId).endpointManifestVersion, 7, "Channel version advanced");
        // The roster is derived from the manifest, so it can never lag behind an accepted update.
        assertEq(service.getPeerEndpointRoster(channelId).length, 2, "derived roster follows the manifest");
    }

    /// @dev Spec: a bundle where verifyBundle returns empty bytes for the manifest does NOT advance.
    ///      If no other progress criterion is satisfied, the NoProgress rejection applies.
    function test_compliance_absentManifest_doesNotAdvance_andNoProgressReverts() public {
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_absentManifest());

        vm.expectRevert(BundleLib.NoProgress.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "cached manifest untouched");
    }

    /// @dev Spec: a bundle where verifyBundle returns a manifest with
    ///      new_endpoint_manifest.version <= Channel.endpoint_manifest_version does NOT advance;
    ///      the manifest content is silently skipped.
    /// @dev "Silently" is the operative word: the bundle carries independent progress (a trust-anchor
    ///      rotation) so it MUST succeed, proving the non-advancing manifest is ignored rather than
    ///      treated as an error. Both an equal and a lower version are checked.
    function test_compliance_nonAdvancingManifestVersion_silentlySkipped() public {
        // Equal version (cached is 1).
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(1, 3));
        verifier.setNewTrustAnchor(hex"A11CE0");
        verifier.setNewTrustAnchorId(hex"01");

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 1, "equal version must not advance");
        assertEq(stored.endpoints.length, 1, "equal-version content must not be applied");
        assertEq(keccak256(service.getChannel(channelId).trustAnchor), keccak256(hex"A11CE0"), "anchor advanced");

        // Advance the cached manifest, then replay a strictly lower version.
        verifier.setNewTrustAnchor("");
        verifier.setNewTrustAnchorId("");
        verifier.setNewEndpointManifest(_manifest(5, 2));
        service.submitBundle(channelId, hex"00FF");
        assertEq(service.getChannel(channelId).endpointManifestVersion, 5, "cached advanced to 5");

        verifier.setNewEndpointManifest(_manifest(4, 3));
        verifier.setNewTrustAnchor(hex"A11CE1");
        verifier.setNewTrustAnchorId(hex"02");
        service.submitBundle(channelId, hex"00FF");

        stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 5, "lower version must not overwrite a newer cached manifest");
        assertEq(stored.endpoints.length, 2, "lower-version content must not be applied");
    }

    /// @dev Spec: manifest advancement applies when the Channel is CLOSING or DRAINED as well as
    ///      ACTIVE — it is not limited to ACTIVE Channels.
    function test_compliance_manifestAdvancement_appliesToClosingAndDrained() public {
        service.closeChannel(channelId);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING));

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).endpointManifestVersion, 2, "applied while CLOSING");
        // With nothing left to drain the state machine walks CLOSING → DRAINED.
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED));

        verifier.setNewEndpointManifest(_manifest(3, 2));
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).endpointManifestVersion, 3, "applied while DRAINED");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2, "content applied while DRAINED");
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    /// @dev Spec: a manifest-update bundle submitted against a PENDING Channel is rejected —
    ///      PENDING Channels reject all bundles.
    function test_compliance_manifestUpdate_pendingChannelRejected() public {
        // Force the Channel back to PENDING (status byte 0) in its packed slot: base
        // keccak256(channelId, 15) + 1 holds verifier | status | nextMessageId.
        bytes32 statusSlot = bytes32(uint256(keccak256(abi.encode(channelId, uint256(15)))) + 1);
        bytes32 packed = vm.load(address(service), statusSlot);
        packed &= ~bytes32(uint256(0xFF) << 160);
        vm.store(address(service), statusSlot, packed);

        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 1));

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getPeerEndpointManifest(channelId).version, 1, "manifest untouched on rejection");
    }

    // ── Bundle manifest update: storage semantics and ordering ────────────────

    /// @dev Spec: when verifyBundle returns empty bytes for the manifest, no manifest update is
    ///      applied and the bundle proceeds normally through the remaining steps (hash verification,
    ///      message dispatch, etc.).
    function test_compliance_absentManifest_bundleProceedsNormally() public {
        verifier.setNewEndpointManifest(_absentManifest());

        _submitBundleWithMessage(_controlPayload(1_000_000_000));

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 1, "inbound cursor advanced: the bundle was processed");
        assertEq(channel.peerConfigTimestamp, 1_000_000_000, "the CONTROL message was dispatched");
        assertEq(channel.endpointManifestVersion, 1, "absent manifest left the version alone");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 1, "cached manifest untouched");
    }

    /// @dev Spec: when new_endpoint_manifest.version > Channel.endpoint_manifest_version,
    ///      Channel.endpoint_manifest is replaced in full with the returned manifest. If the new
    ///      manifest is smaller than the current cached manifest, the cached manifest is replaced
    ///      with the smaller one; no prior entries are retained.
    function test_compliance_manifestUpdate_isFullReplacement() public {
        // Grow the cached manifest to three endpoints (accountIds 0x01, 0x02, 0x03).
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(2, 3));
        service.submitBundle(channelId, hex"00FF");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 3, "cached grew to 3");

        // A newer but SMALLER manifest must replace it outright, not merge into it.
        ClprTypes.ClprEndpointManifest memory shrunk = _manifest(3, 1);
        shrunk.endpoints[0].accountId = hex"7F"; // distinguishable from any prior entry
        verifier.setNewEndpointManifest(shrunk);
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(channelId);
        assertEq(stored.version, 3, "version advanced");
        assertEq(stored.endpoints.length, 1, "shrinking manifest replaces rather than merges");
        assertEq(stored.endpoints[0].accountId, hex"7F", "the surviving entry is the new one");
        // A stale tail left behind in the derived roster would keep dialing withdrawn endpoints.
        assertEq(service.getPeerEndpointRoster(channelId).length, 1, "derived roster shrank with it");
    }

    /// @dev Spec: when a bundle carries both a trust anchor update and a manifest update, the
    ///      manifest update is applied atomically before the trust anchor update — all steps in a
    ///      single bundle submission happen in that order, with no intermediate state observable
    ///      outside the transaction.
    /// @dev The ordering itself is unobservable by construction (both writes land in one
    ///      transaction); what is observable, and what the ordering guarantees, is that the pair is
    ///      all-or-nothing. Both halves are asserted: committed together on success, and neither
    ///      surviving when a later step reverts.
    function test_compliance_manifestUpdate_appliedAtomicallyWithTrustAnchorUpdate() public {
        verifier.setVerifyBundleResult(_noOpMetadata(), new bytes[](0));
        verifier.setNewEndpointManifest(_manifest(4, 2));
        verifier.setNewTrustAnchor(hex"A11C");
        verifier.setNewTrustAnchorId(hex"1D");

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.endpointManifestVersion, 4, "manifest committed");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2, "manifest content committed");
        assertEq(keccak256(channel.trustAnchor), keccak256(hex"A11C"), "trust anchor committed");
        assertEq(keccak256(channel.trustAnchorId), keccak256(hex"1D"), "trust anchor id committed");

        // Now make a LATER step fail (running-hash mismatch): the manifest write happens before that
        // step, so only transaction atomicity can prevent a partial commit.
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = hex"0A00";
        ClprTypes.QueueMetadata memory meta = _noOpMetadata();
        meta.nextMessageId = 2;
        meta.sentRunningHash = bytes32(uint256(0xBAD));
        meta.lastMessageId = 1;
        meta.lastMessageRunningHash = meta.sentRunningHash;
        verifier.setVerifyBundleResult(meta, msgs);
        verifier.setNewEndpointManifest(_manifest(9, 3));
        verifier.setNewTrustAnchor(hex"BEEF");
        verifier.setNewTrustAnchorId(hex"02");

        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, hex"00FF");

        channel = service.getChannel(channelId);
        assertEq(channel.endpointManifestVersion, 4, "manifest rolled back to the last committed version");
        assertEq(service.getPeerEndpointManifest(channelId).endpoints.length, 2, "manifest content rolled back");
        assertEq(keccak256(channel.trustAnchor), keccak256(hex"A11C"), "trust anchor rolled back");
    }

    /// @dev Spec: completeChannel succeeds when the remote CLPR Service has an empty manifest
    ///      (version >= 1, no endpoints). Channel.endpoint_manifest stores the empty manifest with
    ///      the correct service_address and version; endpoint_manifest_version is set to the
    ///      manifest's version value (>= 1); the Channel transitions to ACTIVE normally with no
    ///      error for the empty endpoint list.
    function test_compliance_emptyManifest_storedCorrectlyAtCompleteChannel() public {
        ClprTypes.ClprEndpointManifest memory empty = _manifest(4, 0);
        verifier.setEndpointManifest(empty);

        bytes32 connId = _openExtraChannel(bytes32(uint256(0xE1)));

        ClprTypes.Channel memory channel = service.getChannel(connId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "an empty manifest is not an error");
        assertEq(channel.endpointManifestVersion, 4, "Channel.endpointManifestVersion takes the manifest's version");

        ClprTypes.ClprEndpointManifest memory stored = service.getPeerEndpointManifest(connId);
        assertEq(stored.version, 4, "stored manifest keeps its version");
        assertEq(stored.serviceAddress, empty.serviceAddress, "stored manifest keeps the peer service address");
        assertEq(stored.endpoints.length, 0, "stored manifest carries no endpoints");
        assertEq(service.getPeerEndpointRoster(connId).length, 0, "derived roster is empty");
    }
}
