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

/// @notice Attacks on the outbound messaging path: reentrancy through a connector callback, and
///         early eviction of a connector that still has messages in flight.
/// @dev The individual send-path guards — connector authorization, queue depth, per-connector
///      quota, the payload and wedge limits — are asserted on their own by `MessagingLogic.t.sol`.
///      These tests chain them.
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

    /// A connector cannot reenter the service from its authorization callback.
    ///
    /// `authorizeOutboundMessage` is an outward call made while `sendMessage` is mid-flight. A
    /// reentrant second send would run against half-applied queue accounting. This attacker
    /// bubbles the inner revert verbatim, so the assertion is the guard's own selector rather
    /// than a wrapper string.
    /// @custom:matrix-row M5
    function test_connectorCannotReenterSendMessage() public {
        _registerAttackerConnector();

        bytes memory target = abi.encodePacked(address(connector));
        bytes memory reentrantCall =
            abi.encodeCall(service.sendMessage, (channelId, attackerConnectorId, target, "reentrant"));
        attackerConnector.arm(address(service), reentrantCall, false);

        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        service.sendMessage(channelId, attackerConnectorId, target, "outer");
    }

    /// The guard leaves no partial state behind when it fires.
    ///
    /// The attacker swallows the inner revert so the outer send completes. Exactly one message
    /// must be enqueued: if the reentrant call had partially applied, the queue or the
    /// connector's in-flight count would be ahead of the message count.
    /// @custom:matrix-row M5
    function test_swallowedReentry_enqueuesExactlyOneMessage() public {
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

    /// The in-flight guard on connector eviction cannot be bypassed, and the stake is
    /// returned exactly once.
    ///
    /// A connector with messages in flight must not be evictable: its stake is what backs the
    /// slashing of those messages. Only the peer's reply decrements the in-flight counter, so this
    /// chains the guard with the reply path and then attacks the refund path, where a
    /// double-release would live.
    /// @custom:matrix-row M9
    function test_inflightGuardCannotBeBypassed_andStakeIsReturnedOnce() public {
        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "in flight");

        // Eviction is blocked while the message is in flight.
        vm.expectRevert(ClprTypes.ClprConnectorHasInflightMessages.selector);
        service.removeConnector(channelId, connectorId, owner);

        // A non-admin still cannot evict it, in-flight or not.
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprConnectorUnauthorized.selector);
        service.removeConnector(channelId, connectorId, attacker);

        uint256 stake = service.getConnector(channelId, connectorId).lockedStake;
        assertGt(stake, 0, "precondition: connector has stake at risk");

        // The peer's reply clears the in-flight count, which is what makes eviction legal.
        bytes[] memory replies = new bytes[](1);
        replies[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleAnchor(replies, 1, _runningHashThrough(replies, 1), 1);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");

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
