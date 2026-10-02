// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";
import {ReentrantConnector} from "@test/security/ReentrantConnector.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Messaging attack rows from `docs/security-test-matrix.md` (M domain).
/// @dev This file holds multi-step attacks, plus M7, whose guard no
///      existing test asserts by selector. The single messaging guards — connector
///      authorization, queue depth, per-connector quota, the payload and wedge limits,
///      redaction's own window checks, config validation — are each asserted at this level by
///      `MessagingLogic.t.sol` and `AdminLogic.t.sol`, so those rows are `E*` and the matrix
///      points at them.
contract MessagingAttacksTest is BundleLogicTestBase, SecurityAssertions {
    ReentrantConnector internal attackerConnector;
    bytes32 internal attackerConnectorId;

    function setUp() public override {
        super.setUp();
        _registerTestConnector();
    }

    /// @dev Registers `attackerConnector` as a second connector on the channel.
    function _registerAttackerConnector() internal {
        attackerConnector = new ReentrantConnector();
        attackerConnectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256("security.reentrant-connector"),
            address(attackerConnector),
            owner,
            0.5 ether
        );
        vm.deal(address(attackerConnector), 1 ether);
    }

    /// M7 — a connector cannot reenter the service from its authorization callback.
    ///
    /// `authorizeOutboundMessage` is an outward call made while `sendMessage` is mid-flight. A
    /// reentrant second send would run against half-applied queue accounting. This attacker
    /// bubbles the inner revert verbatim, so the assertion is the guard's own selector rather
    /// than a wrapper string.
    function test_M7_connectorCannotReenterSendMessage() public {
        _registerAttackerConnector();

        bytes memory target = abi.encodePacked(address(connector));
        bytes memory reentrantCall =
            abi.encodeCall(service.sendMessage, (channelId, attackerConnectorId, target, "reentrant"));
        attackerConnector.arm(address(service), reentrantCall, false);

        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        service.sendMessage(channelId, attackerConnectorId, target, "outer");
    }

    /// M7 — the guard leaves no partial state behind when it fires.
    ///
    /// The attacker swallows the inner revert so the outer send completes. Exactly one message
    /// must be enqueued: if the reentrant call had partially applied, the queue or the
    /// connector's in-flight count would be ahead of the message count.
    function test_M7_swallowedReentry_enqueuesExactlyOneMessage() public {
        _registerAttackerConnector();

        bytes memory target = abi.encodePacked(address(connector));
        bytes memory reentrantCall =
            abi.encodeCall(service.sendMessage, (channelId, attackerConnectorId, target, "reentrant"));
        attackerConnector.arm(address(service), reentrantCall, true);

        uint64 nextBefore = service.getChannel(channelId).nextMessageId;
        service.sendMessage(channelId, attackerConnectorId, target, "outer");

        assertEq(service.getChannel(channelId).nextMessageId, nextBefore + 1, "exactly one message may be enqueued");
        assertEq(
            _selectorOf(attackerConnector.lastInnerRevert()),
            ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector,
            "the reentrant call must have been rejected by the guard"
        );
    }

    /// M13 — redaction cannot be used to break the running-hash chain the peer verifies against.
    ///
    /// Redaction rewrites a live outbound payload to `sha256(original)`. The peer has already
    /// hashed the original into its chain, so the local `sentRunningHash` must not move — if it
    /// did, every later bundle would mismatch and the channel would wedge permanently. This
    /// chains redaction with the reply path: after redacting, the peer's reply for that very
    /// message must still be accepted.
    function test_M13_redactionPreservesTheHashChainAndStillAcceptsTheReply() public {
        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "secret");
        service.sendMessage(channelId, connectorId, target, "public");

        bytes32 sentHashBefore = service.getChannel(channelId).sentRunningHash;
        bytes memory originalPayload = service.getMessage(channelId, 1).payload;
        bytes32 msg1HashBefore = service.getMessage(channelId, 1).runningHashAfterProcessing;

        service.redactMessage(channelId, 1);

        // The chain is untouched: only the payload was replaced.
        assertEq(service.getChannel(channelId).sentRunningHash, sentHashBefore, "sentRunningHash must not move");
        assertEq(
            service.getMessage(channelId, 1).runningHashAfterProcessing,
            msg1HashBefore,
            "the message's own chain entry must not move"
        );
        assertEq(
            service.getMessage(channelId, 1).payload,
            ClprProtobuf.encodeRedactedMessage(sha256(originalPayload)),
            "payload must be replaced by the hash marker"
        );

        // Redaction is one-way.
        vm.expectRevert(ClprTypes.ClprMessageAlreadyRedacted.selector);
        service.redactMessage(channelId, 1);

        // And the peer's reply for the redacted message is still accepted, in order.
        bytes[] memory replies = new bytes[](2);
        replies[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        replies[1] = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleAnchor(replies, 2, _runningHashThrough(replies, 2), 2);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");

        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.ACTIVE),
            "the channel must stay ACTIVE: redaction must not look like an ordering violation"
        );
        assertEq(service.getChannel(channelId).ackedMessageId, 2, "both messages must be acked");
    }

    /// M14 — the in-flight guard on connector eviction cannot be bypassed, and the stake is
    /// returned exactly once.
    ///
    /// A connector with messages in flight must not be evictable: its stake is what backs the
    /// slashing of those messages. Redaction decrements the in-flight counter, so it is the
    /// obvious route to unlocking an eviction early. This chains the two and then attacks the
    /// refund path, where a double-release would live.
    function test_M14_inflightGuardCannotBeBypassed_andStakeIsReturnedOnce() public {
        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "in flight");

        // Eviction is blocked while the message is in flight.
        vm.expectRevert(ClprTypes.ClprConnectorHasInflightMessages.selector);
        service.removeConnector(channelId, connectorId, owner);

        // A non-admin still cannot evict it, in-flight or not.
        _assertRevertsWith(
            attacker,
            address(service),
            abi.encodeCall(service.removeConnector, (channelId, connectorId, attacker)),
            abi.encodeWithSelector(ClprTypes.ClprConnectorUnauthorized.selector)
        );

        uint256 stake = service.getConnector(channelId, connectorId).lockedStake;
        assertGt(stake, 0, "precondition: connector has stake at risk");

        // Redaction clears the in-flight count, which is what makes eviction legal.
        service.redactMessage(channelId, 1);

        uint256 balanceBefore = owner.balance;
        service.removeConnector(channelId, connectorId, owner);
        assertEq(owner.balance, balanceBefore + stake, "stake must be refunded exactly once");
        assertEq(service.connectorCount(), 0, "connector must be gone");

        // A second eviction cannot release the stake again.
        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        service.removeConnector(channelId, connectorId, owner);
        assertEq(owner.balance, balanceBefore + stake, "no second refund");
    }
}
