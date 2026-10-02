// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Attacks on a channel's binding to its verifier.
/// @dev Proof forgery, trust-anchor rotation, slot substitution and panic-freedom are asserted by
///      the per-family verifier suites and the cross-family compliance harness, which own the
///      proof fixtures. What no proof fixture can express is the property here: that a channel's
///      verifier, once chosen, is the verifier for the rest of that channel's life.
contract VerifierAttacksTest is BundleLogicTestBase, SecurityAssertions {
    function setUp() public override {
        super.setUp();
        _registerTestConnector();
    }

    /// A channel's verifier cannot be changed after the channel is open.
    ///
    /// The verifier is the channel's entire trust boundary: swapping it would retroactively
    /// change what every future proof is judged against, and an attacker who could substitute one
    /// would not need to forge anything. `channel.verifier` is assigned only in
    /// `ChannelLogic._createChannel`, the whole-struct write-backs in `BundleLib.processBundle` and
    /// `BundleLib._validateAndPrepare` store it unchanged, and no setter exists — so this asserts the
    /// property from the outside: run the operations that rewrite channel state and show the verifier
    /// survives all of them, then show the one route that looks like a swap is refused.
    /// @custom:matrix-row V6
    function test_verifierIsPinnedForTheLifeOfTheChannel() public {
        address original = service.getChannel(channelId).verifier;
        assertEq(original, address(verifier), "precondition: the channel uses the deployed verifier");

        // A second, differently-configured verifier the attacker would like the channel to use.
        MockClprVerifier rogue = MockClprVerifier(deployCode("MockClprVerifier.sol:MockClprVerifier"));
        rogue.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
        rogue.setPeerThrottles(defaultThrottles);
        assertTrue(address(rogue) != original, "precondition: a distinct verifier exists");

        // Re-registering a commitment for an open channel and revealing it with the rogue
        // verifier is the only shape that resembles a swap. It is refused: the channel exists.
        bytes memory pubKey = _signerPubKey();
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        vm.expectRevert(ClprTypes.ClprChannelAlreadyExists.selector);
        service.completeChannel(
            channelId, pubKey, abi.encodePacked(r, s, v), testingSalt, address(rogue), hex"0001", ""
        );

        // Now exercise every path that writes channel state, and confirm none of them touch it.
        bytes[] memory inbound = _payloads(2);
        _submitBundleWithAnchor(channelId, _slice(inbound, 0, 1), 1, _runningHashThrough(inbound, 1));
        assertEq(service.getChannel(channelId).verifier, original, "bundle processing must not rebind the verifier");

        // Note the inbound DATA above already queued a REPLY at id 1, so the DATA message this
        // sends is not id 1 — and only DATA is redactable.
        uint64 outboundId =
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(connector)), "outbound");
        assertEq(service.getChannel(channelId).verifier, original, "sendMessage must not rebind the verifier");

        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxQueueDepth = 9;
        service.updateLedgerConfiguration(hex"BEEF", throttles, hex"AA", hex"BB");
        assertEq(service.getChannel(channelId).verifier, original, "config updates must not rebind the verifier");

        service.updateEconomicConfiguration(defaultEcon);
        assertEq(service.getChannel(channelId).verifier, original, "economic config must not rebind the verifier");

        service.redactMessage(channelId, outboundId);
        assertEq(service.getChannel(channelId).verifier, original, "redaction must not rebind the verifier");

        service.closeChannel(channelId);
        assertEq(service.getChannel(channelId).verifier, original, "closing must not rebind the verifier");
    }
}
