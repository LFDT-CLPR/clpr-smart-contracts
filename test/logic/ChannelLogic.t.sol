// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";

contract ClprService_Channel is ClprServiceTestBase {
    function test_registerChannel() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);
        assertTrue(service.pendingCommitments(commitment));
    }

    function test_registerChannel_idempotent() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);
        service.registerChannel(channelId, commitment);
        assertTrue(service.pendingCommitments(commitment));
    }

    function test_completeChannel() public {
        // Channel already registered and completed in setUp().
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(channel.nextMessageId, 1);
        assertEq(channel.ackedMessageId, 0);
        assertEq(channel.receivedMessageId, 0);
        assertEq(channel.verifier, address(verifier));
        assertEq(keccak256(bytes(channel.chainId)), keccak256(bytes("eip155:1")));
    }

    function test_completeChannel_storesSalt() public {
        // Verifies that salt is stored on the channel.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertNotEq(channel.salt, bytes32(0));
    }

    function test_completeChannel_revert_commitmentMismatch() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 freshId = _deriveTestChannelId(pubKey, bytes32(uint256(5)));
        bytes32 msgHash = keccak256(abi.encodePacked(freshId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprCommitmentMismatch.selector);
        service.completeChannel(freshId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_alreadyExists() public {
        // Channel already created in setUp(), now try to create it again
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprChannelAlreadyExists.selector);
        service.completeChannel(channelId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_invalidSignature() public {
        bytes32 testChannelId = _deriveTestChannelId(_signerPubKey(), bytes32(uint256(2)));
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(testChannelId, pubKey));
        service.registerChannel(testChannelId, commitment);
        bytes memory badSig = new bytes(65);

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeChannel(testChannelId, pubKey, badSig, bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_wrongSigner() public {
        bytes32 testChannelId = _deriveTestChannelId(_signerPubKey(), bytes32(uint256(3)));
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(testChannelId, pubKey));
        service.registerChannel(testChannelId, commitment);

        uint256 wrongPk = 0xDEAD;
        bytes32 msgHash = keccak256(abi.encodePacked(testChannelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeChannel(testChannelId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_invalidVerifier() public {
        bytes32 testChannelId = _deriveTestChannelId(_signerPubKey(), bytes32(uint256(4)));
        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(testChannelId, pubKey));
        service.registerChannel(testChannelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(testChannelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        address eoa = address(0xDEAD);
        vm.expectRevert(ClprTypes.ClprInvalidVerifierContract.selector);
        service.completeChannel(testChannelId, pubKey, sig, bytes32(0), eoa, hex"0001", "");
    }

    function test_closeChannel_revert_notOwner() public {
        vm.prank(address(0x99));
        vm.expectRevert();
        service.closeChannel(channelId);
    }

    function test_closeChannel_pendingCommitment_preventsCompleteChannel() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 freshId = _deriveTestChannelId(pubKey, bytes32(uint256(6)));
        bytes32 commitment = keccak256(abi.encodePacked(freshId, pubKey));
        service.registerChannel(freshId, commitment);
        service.closeChannel(freshId);

        bytes32 msgHash = keccak256(abi.encodePacked(freshId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert(ClprTypes.ClprCommitmentMismatch.selector);
        service.completeChannel(freshId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");
    }

    /// @dev closeChannel fallback: the ownershipCommitment was re-registered elsewhere,
    ///      but hasPending=false (reverse-index entry is gone).
    function test_closeChannel_ownershipCommitmentFallback_whenReverseIndexMissing() public {
        // Channel already registered and completed in setUp().
        // After: channel.ownershipCommitment=commit1, _pendingCommitments[commit1]=false, reverse-index cleared

        // Re-register the SAME commitment for a DIFFERENT channelId (makes commit1 pending again).
        bytes32 differentConnId = keccak256("different-channel-id");
        bytes memory pubKey = _signerPubKey();
        bytes32 commit1 = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(differentConnId, commit1); // _pendingCommitments[commit1] = true again

        // Now close the original channel:
        //   hasPending = (_channelIdToCommitment[channelId] != 0 && ...) = false (reverse index was deleted)
        //   BUT _pendingCommitments[channel.ownershipCommitment=commit1] = true (re-registered above)
        //   → else-if at line 137 fires → deletes commit1 from _pendingCommitments
        service.closeChannel(channelId);

        // The ownershipCommitment should be cleaned up even though it's now linked to a different connId
        assertFalse(
            service.pendingCommitments(commit1), "ownershipCommitment commit1 should be deleted by fallback cleanup"
        );
    }

    /// @dev closeChannel with an active channel that ALSO has a pending commitment
    ///      Achieved by re-registering a new commitment for the same channelId
    ///      after completeChannel (which deleted the original commitment's reverse index).
    function test_closeChannel_withSubsequentPendingCommitment_cleansUpBoth() public {
        // Channel already registered and completed in setUp().
        // After completeChannel: _channelIdToCommitment[channelId] = 0

        // Register a NEW commitment for the same channelId.
        // Since the reverse index is now 0, it gets written with commit2.
        bytes32 commit2 = keccak256("second-commitment");
        service.registerChannel(channelId, commit2);
        assertTrue(service.pendingCommitments(commit2), "commit2 should exist");

        // closeChannel now has hasPending=true → line 134 fires
        service.closeChannel(channelId);

        // Both the channel and the new pending commitment should be cleaned up
        assertFalse(service.pendingCommitments(commit2), "commit2 should be deleted");
        // No Data Messages were ever sent, so CLOSING advances immediately to DRAINED.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    /// @dev peerThrottles is populated at completeChannel from the verifier's verifyConfig return value.
    function test_completeChannel_populatesPeerThrottles() public {
        uint64 expectedPeerPayload = 512;
        defaultThrottles.maxMessagesPerBundle = 50;
        defaultThrottles.maxMessagePayloadBytes = expectedPeerPayload;
        verifier.setPeerThrottles(defaultThrottles);

        bytes32 freshId = _openExtraChannel(bytes32(uint256(300)));

        ClprTypes.Channel memory channel = service.getChannel(freshId);
        assertEq(
            channel.peerThrottles.maxMessagePayloadBytes,
            expectedPeerPayload,
            "peerThrottles.maxMessagePayloadBytes must equal verifier-supplied value"
        );
        assertEq(
            channel.peerThrottles.maxMessagesPerBundle,
            50,
            "peerThrottles.maxMessagesPerBundle must equal verifier-supplied value"
        );
    }

    /// @dev Domain-separated reveal sig cannot be replayed on a different router.
    function test_completeChannel_revealSignature_isDomainSeparated() public {
        // Deploy a second router with the same chain config.
        ClprService service2 = _deployClprService(1, "eip155:1337");
        service2.initialize(hex"1234", defaultThrottles, "", "", _defaultEconomicConfig());
        service2.setClprEnabled(true);

        // Set up verifier for service2 (same verifier contract works for both).
        MockClprVerifier verifier2 = MockClprVerifier(deployCode("MockClprVerifier.sol:MockClprVerifier"));
        verifier2.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
        verifier2.setPeerThrottles(defaultThrottles);

        bytes memory pubKey = _signerPubKey();
        bytes32 cid = _deriveTestChannelId(pubKey, bytes32(uint256(200)));

        // Register on service2.
        bytes32 commitment = keccak256(abi.encodePacked(cid, pubKey));
        service2.registerChannel(cid, commitment);

        // Sign for service (address(service)), not service2.
        bytes32 msgHash = keccak256(abi.encodePacked(cid, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        // Replaying the service-1 signature on service2 must fail.
        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service2.completeChannel(cid, pubKey, sig, bytes32(0), address(verifier2), hex"0001", "");
    }

    /// @dev Trust anchor is sourced from the verifier, not the caller.
    function test_completeChannel_initialTrustAnchorFromVerifier() public {
        bytes memory verifierAnchor = hex"DEADBEEF1234";
        verifier.setInitialTrustAnchor(verifierAnchor);

        bytes32 freshId = _openExtraChannel(bytes32(uint256(201)));

        ClprTypes.Channel memory channel = service.getChannel(freshId);
        assertEq(channel.trustAnchor, verifierAnchor, "trustAnchor must equal the value returned by the verifier");
    }

    function test_completeChannel_revert_invalidSignature_pubKeyLength() public {
        bytes memory badPubKey = new bytes(63);

        channelId = _deriveTestChannelId(badPubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(channelId, badPubKey));
        service.registerChannel(channelId, commitment);

        // Expect revert due to bad pubKey length before any signature math
        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeChannel(channelId, badPubKey, hex"", bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_tooManyChannels() public {
        service.updateEconomicConfiguration(_econWithMaxChannels(1));

        // Attempt a second channel (different pubkey ensures a new channelId)
        uint256 otherPk = signerPk + 1;
        Vm.Wallet memory w = vm.createWallet(otherPk);
        bytes memory pubKey2 = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        bytes32 connId2 = _deriveTestChannelId(pubKey2, bytes32(0));
        bytes32 com2 = keccak256(abi.encodePacked(connId2, pubKey2));
        service.registerChannel(connId2, com2);
        bytes32 msgHash2 = keccak256(abi.encodePacked(connId2, address(service)));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(otherPk, _ethSignedHash(msgHash2));
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);

        vm.expectRevert(ClprTypes.ClprTooManyChannels.selector);
        service.completeChannel(connId2, pubKey2, sig2, bytes32(0), address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_invalidChannelId_dueToSaltMismatch() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 goodConnId = _deriveTestChannelId(pubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(goodConnId, pubKey));
        service.registerChannel(goodConnId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(goodConnId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        // Use a different salt at reveal time ,derived expected id won't equal goodConnId
        bytes32 wrongSalt = bytes32(uint256(1));
        vm.expectRevert(ClprTypes.ClprInvalidChannelId.selector);
        service.completeChannel(goodConnId, pubKey, sig, wrongSalt, address(verifier), hex"0001", "");
    }

    function test_sortChains_equalBranch_takenWhenHashesEqual() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 salt = bytes32(uint256(123));

        bytes32 derived = service.deriveChannelId("eip155:1337", pubKey, salt);
        bytes32 expected = keccak256(abi.encodePacked(bytes("eip155:1337"), bytes("eip155:1337"), pubKey, salt));

        assertEq(derived, expected, "sort_chains should take <= branch when hashes equal (identical chains)");
    }

    // ── closeChannel ────────────────────────────────────────────────

    function test_closeChannel_revert_invalidStatus() public {
        bytes memory pubKey = _signerPubKey();
        channelId = _deriveTestChannelId(pubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        service.completeChannel(channelId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");
        service.closeChannel(channelId); // ACTIVE -> DRAINED (no Data Messages were ever sent)
        service.closeChannel(channelId); // DRAINED -> CLOSED (vacuously fully acked)

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.closeChannel(channelId); // CLOSED: neither ACTIVE/PAUSED nor DRAINED
    }

    // Admin recovery path: closeChannel on a DRAINED channel transitions directly to
    // CLOSED once every outbound message has been acknowledged.
    function test_closeChannel_fromDrained_transitionsToClosed() public {
        // No Data Messages were ever sent, so the first admin close advances straight
        // through CLOSING to DRAINED in the same call.
        service.closeChannel(channelId);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED));

        // Admin recovery: closeChannel from DRAINED → CLOSED directly.
        vm.expectEmit(true, false, false, true);
        emit ChannelStatusChanged(channelId, ClprTypes.ChannelStatus.CLOSED);
        service.closeChannel(channelId);

        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSED));
    }

    function test_closeChannel_pendingOnly_deletesCommitment() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(connId, pubKey));
        service.registerChannel(connId, commitment);

        service.closeChannel(connId);

        assertFalse(service.pendingCommitments(commitment), "commitment should be deleted");
    }

    function test_closeChannel_revert_noPendingNoActive() public {
        bytes32 unknownId = keccak256("cl.unknown-conn");
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.closeChannel(unknownId);
    }

    function test_deriveChannelId_returnsCorrectId() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 salt = bytes32(uint256(42));
        bytes32 derived = service.deriveChannelId("eip155:1", pubKey, salt);
        bytes32 expected = _deriveTestChannelId(pubKey, salt);
        assertEq(derived, expected, "deriveChannelId should match");
    }

    function test_sortChains_swapBranch_nonZeroResult() public {
        bytes memory pubKey = _signerPubKey();
        bytes32 id = service.deriveChannelId("aaa", pubKey, bytes32(0));
        assertNotEq(id, bytes32(0), "derived id must be non-zero");
    }

    function test_channelCount_incrementsOnComplete() public {
        assertEq(service.channelCount(), 1);

        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(connId, pubKey));
        service.registerChannel(connId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);
        service.completeChannel(connId, pubKey, sig, bytes32(0), address(verifier), hex"0001", "");

        assertEq(service.channelCount(), 2);
    }

    // ─── _sortChains: edge cases ──────────────────────────────────────────────

    function test_sortChains_emptyPeerChain_reverts() public {
        bytes memory pubKey = _signerPubKey();
        vm.expectRevert(ClprTypes.ClprInvalidChainId.selector);
        service.deriveChannelId("", pubKey, bytes32(0));
    }

    function test_sortChains_emptyLocalChain_reverts() public {
        ClprService svc = _deployClprService(1, "");
        bytes memory pubKey = _signerPubKey();
        vm.expectRevert(ClprTypes.ClprInvalidChainId.selector);
        svc.deriveChannelId("eip155:1", pubKey, bytes32(0));
    }

    function test_sortChains_bothEmpty_reverts() public {
        ClprService svc = _deployClprService(1, "");
        bytes memory pubKey = _signerPubKey();
        vm.expectRevert(ClprTypes.ClprInvalidChainId.selector);
        svc.deriveChannelId("", pubKey, bytes32(0));
    }

    function _econWithMaxChannels(uint256 maxConn) internal pure returns (ClprTypes.EconomicConfig memory) {
        return ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            // forge-lint: disable-next-line(unsafe-typecast)
            maxChannels: uint32(maxConn),
            maxConnectors: 0
        });
    }

    // ── Edge case: closeChannel status transitions ───────────────────────

    /// @notice closeChannel on an ACTIVE channel with no Data Messages outstanding
    ///         advances straight to DRAINED in the same call.
    function test_closeChannel_transitionsActiveDirectlyToDrained_whenQueueEmpty() public {
        // Verify initial state is ACTIVE
        ClprTypes.Channel memory beforeClose = service.getChannel(channelId);
        assertEq(uint8(beforeClose.status), uint8(ClprTypes.ChannelStatus.ACTIVE));

        // Close the channel
        service.closeChannel(channelId);

        // Verify state advanced past CLOSING to DRAINED
        ClprTypes.Channel memory afterClose = service.getChannel(channelId);
        assertEq(uint8(afterClose.status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    /// @notice closeChannel on an ACTIVE channel stays at CLOSING while an unacked
    ///         Data Message remains in the outbound queue.
    function test_closeChannel_stopsAtClosing_whenDataMessageOutstanding() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, hex"11223344", hex"01");

        service.closeChannel(channelId);

        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSING),
            "must stay at CLOSING while an unacked Data Message remains outstanding"
        );
    }

    // ── Peer endpoint roster (relocated from test/logic/PeerEndpointRoster.t.sol) ──────

    uint256 internal altPeerEpPk = uint256(keccak256("clpr.test.altPeerEndpoint"));

    /// @notice After completeChannel the peer roster contains the verifier's seed endpoint.
    ///         Verified indirectly: the derived signer address is non-zero and deterministic.
    function test_rosterPopulatedAtCompleteChannel() public {
        address peerSigner = _peerEndpointSignerAddr();
        assertFalse(peerSigner == address(0), "peerSigner must be non-zero");
        Vm.Wallet memory w = vm.createWallet(PEER_EP_PK);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        address expected = address(uint160(uint256(keccak256(pubKey))));
        assertEq(peerSigner, expected, "signer address mismatch");
    }

    /// @notice After completeChannel the getter returns exactly the verifier's seed endpoint:
    ///         ipAddress, port, signing key, and registered=true.
    function test_getPeerEndpointRoster_populatedAtCompleteChannel() public {
        ClprTypes.PeerEndpoint[] memory roster = service.getPeerEndpointRoster(channelId);
        assertEq(roster.length, 1, "roster must contain exactly the one seed endpoint");
        assertEq(roster[0].ipAddress, bytes("127.0.0.1"), "ipAddress mismatch");
        assertEq(uint256(roster[0].port), uint256(50211), "port mismatch");
        assertTrue(roster[0].registered, "endpoint must be registered");
    }

    /// @notice An unknown channel id yields an empty roster (no revert).
    function test_getPeerEndpointRoster_emptyForUnknownChannel() public {
        bytes32 unknown = keccak256("clpr.test.no.such.channel");
        ClprTypes.PeerEndpoint[] memory roster = service.getPeerEndpointRoster(unknown);
        assertEq(roster.length, 0, "unknown channel must have an empty roster");
    }

    // NOTE: test_getPeerEndpointRoster_replacedOnControlRefresh removed — endpoint changes no longer
    // propagate via ConfigUpdate CONTROL messages. Peer endpoints now travel
    // through manifest-update bundle payloads (BundleLib Step 1b); covered by the manifest test suite.

    function test_roster_silentlySkipsDuplicateSigners_inBatch() public {
        bytes memory pubKey = _peerEndpointPubKey();
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](2);
        seeds[0] = ClprTypes.Endpoint({ipAddress: "192.168.1.10", port: 50211, tlsCertificate: hex"", accountId: hex""});
        seeds[1] = ClprTypes.Endpoint({ipAddress: "192.168.1.10", port: 50211, tlsCertificate: hex"", accountId: hex""});
        verifier.setSeedEndpoints(seeds);

        channelId = _deriveTestChannelId(pubKey, bytes32(0));
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PEER_EP_PK, _ethSignedHash(msgHash));
        service.completeChannel(
            channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), address(verifier), hex"0001", ""
        );

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel should be active");
    }

    /// @dev Derive the Ethereum address corresponding to PEER_EP_PK's uncompressed pubkey.
    function _peerEndpointSignerAddr() internal returns (address) {
        bytes memory pubKey = _peerEndpointPubKey();
        return address(uint160(uint256(keccak256(pubKey))));
    }

    function _dummyLocalKey() internal pure returns (bytes memory) {
        bytes memory k = new bytes(64);
        k[0] = 0xAA;
        return k;
    }

    // ── Peer throttle validation at completeChannel ───────────────────────

    function test_completeChannel_revert_peerThrottles_zeroGasPerMessage() public {
        defaultThrottles.maxGasPerMessage = 0;
        verifier.setPeerThrottles(defaultThrottles);
        bytes32 salt = bytes32(uint256(300));
        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, salt);
        service.registerChannel(connId, keccak256(abi.encodePacked(connId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.completeChannel(connId, pubKey, abi.encodePacked(r, s, v), salt, address(verifier), hex"0001", "");
    }

    function test_completeChannel_revert_peerThrottles_zeroSyncBytes() public {
        defaultThrottles.maxSyncBytes = 0;
        verifier.setPeerThrottles(defaultThrottles);
        bytes32 salt = bytes32(uint256(301));
        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, salt);
        service.registerChannel(connId, keccak256(abi.encodePacked(connId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.completeChannel(connId, pubKey, abi.encodePacked(r, s, v), salt, address(verifier), hex"0001", "");
    }
}
