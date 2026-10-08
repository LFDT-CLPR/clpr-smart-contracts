// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ExactGasCall} from "@hiero-ledger/clpr/libraries/service/ExactGasCall.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";
import {GasProbeApplication, GasProbeConnector} from "@test/security/GasProbes.sol";

/// @notice Multi-step attacks on inbound bundle processing.
/// @dev Each scenario chains several of BundleLib's guards and then asserts the channel's
///      integrity *after* the attack fails — that no partial state was written, no accounting was
///      freed, and no message was skipped. The individual guards are asserted on their own by the
///      `BundleLib_*` and `BundleLogic_*` suites; what those cannot show is the state a failed
///      attempt leaves behind, because each stops at its own revert.
///
///      `submitBundle` is permissionless by design, so the attacker needs no privilege. The mock
///      verifier stands in for a proof, which is what lets these tests choose the `QueueMetadata`
///      and payload list a proof would attest while BundleLib's own checks stay live.
contract BundleAttacksTest is BundleLogicTestBase, SecurityAssertions {
    function setUp() public override {
        super.setUp();
        _registerTestConnector();
    }

    /// A rewound bundle cannot re-deliver messages the channel already accepted.
    ///
    /// A relay replaying an older proof claims a `nextMessageId` behind what the channel has
    /// received; accepting it would dispatch those messages a second time. The attacker pairs the
    /// rewind with an ack advance so the bundle clears the progress gate and reaches the
    /// message-position check, which rejects it. The channel is left where it was and still
    /// accepts the honest continuation.
    /// @custom:matrix-row B4
    function test_rewoundBundle_cannotRedeliverAcceptedMessages() public {
        bytes[] memory all = _payloads(3);

        // Legitimately receive messages 1..2. Each inbound DATA queues a reply, so there is an ack to advance.
        _submitBundleWithAnchor(channelId, _slice(all, 0, 2), 2, _runningHashThrough(all, 2));
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "precondition: 1..2 received");
        bytes32 receivedHashBefore = service.getChannel(channelId).receivedRunningHash;

        // Replay the bundle that delivered message 1, acking our first reply so it clears the progress gate.
        _armBundleAnchor(_slice(all, 0, 1), 1, _runningHashThrough(all, 1), 1);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(_localSyncData(channelId).receivedMessageId, 2, "a rewind must not move progress");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            receivedHashBefore,
            "a rewind must not touch the hash chain"
        );
        assertEq(service.getChannel(channelId).ackedMessageId, 0, "the rewound bundle's ack must not apply");

        // The honest continuation still applies.
        _submitBundleWithAnchor(channelId, _slice(all, 2, 3), 3, _runningHashThrough(all, 3));
        assertEq(_localSyncData(channelId).receivedMessageId, 3, "the honest continuation must still apply");
    }

    /// A message cannot be skipped, by any route, and failed attempts leave no trace.
    ///
    /// Chains the message-position and hash-chain guards across two attempts. An attacker that
    /// wants message 3 never delivered must either claim a `lastMessageId` beyond the payloads it
    /// carries, or carry a forged payload in message 3's slot. Both fail; the interesting part
    /// is that after both failures the channel is byte-for-byte where it started, so the
    /// legitimate bundle still applies and message 3 is delivered exactly once.
    /// @custom:matrix-row B10
    function test_messageCannotBeSkipped_andFailedAttemptsLeaveNoState() public {
        bytes[] memory all = _payloads(4);

        // Legitimately receive messages 1..2.
        _submitBundleWithAnchor(channelId, _slice(all, 0, 2), 2, _runningHashThrough(all, 2));
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "precondition: 1..2 received");
        bytes32 receivedHashBefore = service.getChannel(channelId).receivedRunningHash;

        // Attempt 1: claim the run ends at message 4 (`lastMessageId` 4) while carrying only
        // message 4 — skipping 3 outright.
        bytes[] memory onlyFourth = _slice(all, 3, 4);
        _armBundleAnchor(onlyFourth, 4, _runningHashThrough(all, 4), 2);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");

        // Attempt 2: carry two payloads so the count checks out, but substitute message 3.
        bytes[] memory forged = _slice(all, 2, 4);
        forged[0] = ClprProtobuf.encodeDataMessage(
            connectorId, abi.encodePacked(address(connector)), abi.encodePacked(uint32(3)), "FORGED"
        );
        _armBundleAnchor(forged, 4, _runningHashThrough(all, 4), 2);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, hex"00FF");

        // Neither failure moved the channel.
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "failed attempts must not advance progress");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            receivedHashBefore,
            "failed attempts must not touch the hash chain"
        );

        // And the honest continuation still applies, delivering 3 and 4 exactly once.
        _submitBundleWithAnchor(channelId, _slice(all, 2, 4), 4, _runningHashThrough(all, 4));
        assertEq(_localSyncData(channelId).receivedMessageId, 4, "honest bundle must still apply after the attack");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            _runningHashThrough(all, 4),
            "hash chain must cover all four messages"
        );
    }

    /// A forged ack cannot launder per-connector queue quota.
    ///
    /// A connector's quota is held until the peer's reply to each of its messages is processed.
    /// If an unbacked ack released it, the connector could exceed its share of the shared queue
    /// indefinitely. This drives the queue to its quota, has the attacker try to free it with an
    /// unbacked ack, and asserts the quota is still exhausted afterwards; only a legitimate reply
    /// releases exactly one slot.
    /// @custom:matrix-row B11
    function test_forgedAck_cannotLaunderConnectorQuota() public {
        // maxQueueDepth 4 with the default 50% connector quota gives this connector 2 slots.
        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxQueueDepth = 4;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");

        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "one");
        service.sendMessage(channelId, connectorId, target, "two");

        // Quota is now exhausted.
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "three");

        uint64 nextMessageId = service.getChannel(channelId).nextMessageId;

        // Attack: claim an ack beyond anything we ever sent, to free both slots at once.
        bytes[] memory none = new bytes[](0);
        _armBundleAnchor(none, 0, bytes32(0), nextMessageId + 10);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprAckVerificationFailed.selector);
        service.submitBundle(channelId, hex"00FF");

        // The quota is still exhausted: nothing was laundered.
        assertEq(service.getChannel(channelId).ackedMessageId, 0, "forged ack must not apply");
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "three");

        // A legitimate reply releases exactly one slot, and no more. The quota is released by the
        // reply, not the ack: an ack covering a live DATA message without its reply is committed,
        // but pauses the channel and leaves the quota held.
        bytes[] memory reply = new bytes[](1);
        reply[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleAnchor(reply, 1, _runningHashThrough(reply, 1), 1);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        assertEq(service.getChannel(channelId).ackedMessageId, 1, "honest ack should apply");
        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.ACTIVE),
            "an in-order reply must leave the channel ACTIVE"
        );

        service.sendMessage(channelId, connectorId, target, "three");
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "four");
    }

    /// A closing channel drains forward and can never be revived.
    ///
    /// Once the operator closes a channel, a peer that keeps claiming ACTIVE must not be able to
    /// hold it open or walk it back — that would defeat the close and keep accepting traffic the
    /// operator decided to stop. Status transitions are monotonic, so each of the peer's claims
    /// either advances the drain or does nothing. `BundleLib_StateMachine` asserts the same rule
    /// against `BundleLibHarness`; this is the end-to-end path through `submitBundle`, and it
    /// also checks the channel cannot be sent to after the close. The local side has one DATA
    /// message the peer never acks: with an empty queue `closeChannel` goes straight to DRAINED.
    /// @custom:matrix-row B9
    function test_closingChannel_cannotBeRevivedByPeerClaims() public {
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(connector)), "unacked");
        service.closeChannel(channelId);
        assertEq(
            uint8(_localSyncData(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING), "precondition: CLOSING"
        );

        bytes[] memory all = _payloads(2);

        // The peer insists the channel is ACTIVE while delivering traffic, twice.
        _armBundleAnchor(_slice(all, 0, 1), 1, _runningHashThrough(all, 1), 0);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        uint8 afterFirst = uint8(_localSyncData(channelId).status);
        assertGe(afterFirst, uint8(ClprTypes.ChannelStatus.CLOSING), "status must not move backwards");

        _armBundleAnchor(_slice(all, 1, 2), 2, _runningHashThrough(all, 2), 0);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        uint8 afterSecond = uint8(_localSyncData(channelId).status);
        assertGe(afterSecond, afterFirst, "status must only ever step forward");
        assertTrue(
            afterSecond != uint8(ClprTypes.ChannelStatus.ACTIVE)
                && afterSecond != uint8(ClprTypes.ChannelStatus.PAUSED),
            "a peer's ACTIVE claim must not revive a closing channel"
        );

        // And the local side cannot be talked into sending on it again.
        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(connector)), "after close");
    }

    // ── Forwarded gas ────────────────────────────────────────────────────

    /// @dev Gas a probe can find missing from its budget, rounded up: the CALL's own cost, which the
    ///      callee pays from its budget, plus the probe's dispatch before its first `gasleft()`. The
    ///      unoptimized `forge coverage --ir-minimum` build is the worst case: `onInboundMessage`
    ///      decodes its five arguments in about 1,200 gas there.
    uint256 private constant ENTRY_GAS = 2_000;

    GasProbeApplication private probeApp;
    GasProbeConnector private probeConnector;
    bytes32 private probeConnectorId;

    function _deployProbes() private {
        probeApp = new GasProbeApplication();
        probeConnector = new GasProbeConnector();
        probeConnectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256("gas-probe-connector"),
            address(probeConnector),
            owner,
            0.5 ether
        );
        vm.deal(address(probeConnector), 100 ether);
    }

    /// @dev Arms one inbound DATA message for the probe application through the probe connector.
    function _armProbeData() private {
        _armProbeDataTo(address(probeApp));
    }

    function _armProbeDataTo(address target) private {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = ClprProtobuf.encodeDataMessage(
            probeConnectorId, abi.encodePacked(target), abi.encodePacked(address(this)), "PING"
        );
        _armBundleAnchor(payloads, 1, _runningHashThrough(payloads, 1));
    }

    function _submitCall() private view returns (bytes memory) {
        return abi.encodeCall(service.submitBundle, (channelId, hex"00FF"));
    }

    function _submitSucceeds(uint256 gasAmount) private returns (bool ok) {
        uint256 snapshot = vm.snapshotState();
        (ok,) = address(service).call{gas: gasAmount}(_submitCall());
        vm.revertToState(snapshot);
    }

    /// @dev Smallest transaction gas for which the armed bundle applies, by bisection. The submitter
    ///      picks exactly this kind of value to starve a callee while the bundle still goes through.
    function _minimalSubmitGas() private returns (uint256 hi) {
        uint256 lo = 50_000;
        hi = 30_000_000;
        assertFalse(_submitSucceeds(lo), "lower bound must fail");
        assertTrue(_submitSucceeds(hi), "upper bound must succeed");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_submitSucceeds(mid)) hi = mid;
            else lo = mid;
        }
    }

    /// @dev Submits at the smallest gas that applies the bundle, and returns what one unit less
    ///      reverted with, for `_assertRefusedByTheGasCheck`.
    function _submitAtMinimalGas() private returns (bytes memory belowMinimum) {
        uint256 gMin = _minimalSubmitGas();
        uint256 snapshot = vm.snapshotState();
        bool ok;
        (ok, belowMinimum) = address(service).call{gas: gMin - 1}(_submitCall());
        vm.revertToState(snapshot);
        assertFalse(ok, "one gas less must fail");

        (ok,) = address(service).call{gas: gMin}(_submitCall());
        assertTrue(ok, "minimal gas must apply the bundle");
    }

    /// @dev One unit below the minimal gas, the bundle must be refused by the forwarded-gas check of
    ///      the callback whose gas is `budget`, rather than by another callback's check or a later
    ///      out-of-gas.
    function _assertRefusedByTheGasCheck(bytes memory belowMinimum, uint256 budget) private pure {
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes4(belowMinimum), ExactGasCall.InsufficientGasForCall.selector, "refused by the gas check");
        uint256 required;
        assembly ("memory-safe") {
            required := mload(add(belowMinimum, 36))
        }
        assertEq(required, budget + budget / 63, "refused by this callback's check");
    }

    /// @dev The newest REPLY in the channel's outbound queue.
    function _lastReply() private returns (ClprTypes.DecodedReply memory) {
        for (uint64 id = service.getChannel(channelId).nextMessageId - 1; id > 0; id--) {
            bytes memory payload = service.getMessage(channelId, id).payload;
            (bool known, ClprTypes.MessageType mt) = ClprProtobuf.tryGetMessageType(payload);
            if (known && mt == ClprTypes.MessageType.REPLY) return ClprProtobuf.decodeReplyMessage(payload);
        }
        revert("no reply queued");
    }

    /// The destination application receives its `maxGasPerMessage`, less the CALL's own cost,
    /// whatever gas the submitter sends.
    ///
    /// The submitter picks the transaction's gas. Under the EIP-150 63/64 rule a call gets at most
    /// 63/64 of what is left, so a bundle sent with just enough gas starves the application. An
    /// application that fails cheaply hands the rest back, the bundle applies, and the message is
    /// recorded as an application failure for good.
    /// @custom:matrix-row B12
    function test_applicationCannotBeStarvedOfItsGas() public {
        _deployProbes();
        probeApp.setFloor(defaultThrottles.maxGasPerMessage - ENTRY_GAS);
        _armProbeData();

        bytes memory belowMinimum = _submitAtMinimalGas();

        assertGe(
            probeApp.messageGas(),
            defaultThrottles.maxGasPerMessage - ENTRY_GAS,
            "maxGasPerMessage, less the CALL's cost"
        );
        assertLe(probeApp.messageGas(), defaultThrottles.maxGasPerMessage, "and no more");
        assertEq(uint8(_lastReply().status), uint8(ClprTypes.ReplyStatus.SUCCESS), "the message must succeed");
        _assertRefusedByTheGasCheck(belowMinimum, defaultThrottles.maxGasPerMessage);
    }

    /// The source application receives its `maxGasPerMessage`, less the CALL's own cost, for
    /// `onClprResponse`.
    ///
    /// A starved response callback fails silently: the reply is consumed and `ReplyDelivered` is
    /// emitted, but the application never learns the outcome of the message it sent.
    /// @custom:matrix-row B12
    function test_responseCallbackCannotBeStarvedOfItsGas() public {
        _deployProbes();
        probeApp.send(IClprService(address(service)), channelId, probeConnectorId, hex"BEEF", "PING");
        probeApp.setFloor(defaultThrottles.maxGasPerMessage - ENTRY_GAS);

        bytes[] memory reply = new bytes[](1);
        reply[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleAnchor(reply, 1, _runningHashThrough(reply, 1), 1);

        bytes memory belowMinimum = _submitAtMinimalGas();

        assertGe(
            probeApp.responseGas(),
            defaultThrottles.maxGasPerMessage - ENTRY_GAS,
            "maxGasPerMessage, less the CALL's cost"
        );
        assertLe(probeApp.responseGas(), defaultThrottles.maxGasPerMessage, "and no more");
        _assertRefusedByTheGasCheck(belowMinimum, defaultThrottles.maxGasPerMessage);
    }

    /// The connector receives its `connectorInboundGasStipend`, less the CALL's own cost, for
    /// `onInboundMessage`.
    ///
    /// The message targets an address without code and nothing is charged, so the notification is
    /// the only callback and its own check sets the bundle's minimal gas.
    /// @custom:matrix-row B12
    function test_connectorNotificationCannotBeStarvedOfItsGas() public {
        _deployProbes();
        probeConnector.setFloor(defaultEcon.connectorInboundGasStipend - ENTRY_GAS);
        _armProbeDataTo(makeAddr("no-code-target"));

        bytes memory belowMinimum = _submitAtMinimalGas();

        assertGe(
            probeConnector.inboundGas(),
            defaultEcon.connectorInboundGasStipend - ENTRY_GAS,
            "the stipend, less the CALL's cost"
        );
        assertLe(probeConnector.inboundGas(), defaultEcon.connectorInboundGasStipend, "and no more");
        _assertRefusedByTheGasCheck(belowMinimum, defaultEcon.connectorInboundGasStipend);
    }

    /// A funded connector cannot be slashed by starving its `payForExecution`, which gets
    /// `connectorPaymentGasLimit`, less the CALL's own cost.
    ///
    /// A failed charge slashes the connector. If the submitter can make `payForExecution` fail by
    /// sending too little gas, it slashes a connector that could pay, and collects the proceeds.
    /// The payment's own check never sets the minimal gas here: the application's larger budget
    /// comes first. `ConnectorLib_SlashAndCharge` asserts the payment's check on its own.
    /// @custom:matrix-row B12
    function test_connectorPaymentCannotBeStarvedIntoASlash() public {
        _deployProbes();
        probeConnector.setFloor(defaultEcon.connectorPaymentGasLimit - ENTRY_GAS);
        vm.txGasPrice(1 gwei);
        _armProbeData();

        _submitAtMinimalGas();

        ClprTypes.Connector memory c = service.getConnector(channelId, probeConnectorId);
        assertEq(c.slashCount, 0, "a funded connector must not be slashed");
        assertEq(c.lockedStake, 0.5 ether, "its stake must be intact");
        assertGe(
            probeConnector.payGas(),
            defaultEcon.connectorPaymentGasLimit - ENTRY_GAS,
            "connectorPaymentGasLimit, less the CALL's cost"
        );
        assertLe(probeConnector.payGas(), defaultEcon.connectorPaymentGasLimit, "and no more");
    }

    /// A connector whose `payForExecution` spends all the gas it gets cannot stall the channel.
    ///
    /// Without a cap, the payment would take 63/64 of what is left, and no gas limit would leave
    /// enough for the rest of the bundle. With the cap, the charge fails, the connector is slashed,
    /// and the bundle applies.
    /// @custom:matrix-row B12
    function test_connectorThatBurnsItsPaymentGasCannotStallTheChannel() public {
        _deployProbes();
        probeConnector.setBurnOnPay(true);
        vm.txGasPrice(1 gwei);
        _armProbeData();

        (bool ok,) = address(service).call{gas: 10_000_000}(_submitCall());

        assertTrue(ok, "the bundle must apply");
        assertEq(service.getConnector(channelId, probeConnectorId).slashCount, 1, "the connector is slashed");
        assertLe(probeConnector.payGas(), defaultEcon.connectorPaymentGasLimit, "it burned only its budget");
    }

    /// An application that spends its whole budget does not make a charged message need a second
    /// `maxGasPerMessage` for the payment.
    ///
    /// Every callback needs its budget available, used or not. If the payment's budget were
    /// `maxGasPerMessage`, a sender could target an application that burns its budget and make one
    /// message need two of them, which can exceed the chain's per-transaction gas cap and stall the
    /// channel.
    /// @custom:matrix-row B12
    function test_aBurningApplicationDoesNotDoubleTheGasAMessageNeeds() public {
        _deployProbes();
        probeApp.setBurn(true);
        vm.txGasPrice(1 gwei);
        _armProbeData();

        uint256 gMin = _minimalSubmitGas();

        assertLt(gMin, 2 * defaultThrottles.maxGasPerMessage, "one message must not need two application budgets");
    }

    /// A connector cannot spend the application's budget in its payment and still pay.
    ///
    /// The gas a payment spends is never charged to anyone but the submitter, so its budget bounds
    /// what a connector can make the submitter spend without being slashed.
    /// @custom:matrix-row B12
    function test_aPaymentCannotSpendTheApplicationsBudget() public {
        _deployProbes();
        probeConnector.setBurnBeforePay(900_000);
        vm.txGasPrice(1 gwei);
        _armProbeData();

        (bool ok,) = address(service).call{gas: 10_000_000}(_submitCall());

        assertTrue(ok, "the bundle must apply");
        assertEq(service.getConnector(channelId, probeConnectorId).slashCount, 1, "a payment over its budget fails");
    }

    /// @dev Delivers one DATA message whose application returns `raw` byte for byte, and returns
    ///      the reply it produced. State is rolled back afterwards, so cases can run in sequence.
    function _replyToRawReturn(bytes memory raw) private returns (ClprTypes.DecodedReply memory r) {
        uint256 snapshot = vm.snapshotState();
        _deployProbes();
        probeApp.setRawReturn(raw);
        _armProbeData();
        service.submitBundle(channelId, hex"00FF");
        r = _lastReply();
        vm.revertToState(snapshot);
    }

    /// An application whose return data is not an ABI-encoded `bytes` fails its own message, not
    /// the bundle.
    ///
    /// Decoding the return data of a successful call is not covered by `try`/`catch`, so a malformed
    /// return would revert the whole bundle and stop every later message on the channel.
    /// @custom:matrix-row B15
    function test_malformedApplicationReturnFailsTheMessageNotTheBundle() public {
        bytes[5] memory malformed = [
            bytes(hex"01"),
            // The offset leaves no room for the length word.
            abi.encodePacked(uint256(0x21), uint256(0)),
            abi.encodePacked(uint256(0x40), uint256(0)),
            // The length runs past the end.
            abi.encodePacked(uint256(0x20), uint256(1)),
            abi.encodePacked(uint256(0x20), uint256(33), keccak256("thirty-two bytes of data"))
        ];
        for (uint256 i = 0; i < malformed.length; i++) {
            ClprTypes.DecodedReply memory r = _replyToRawReturn(malformed[i]);
            assertEq(uint8(r.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR), "recorded as the app's failure");
            assertEq(r.messageReplyData, malformed[i], "with the raw return data as the reason");
        }
    }

    /// Every return `abi.decode(ret, (bytes))` accepts is decoded, including the shapes at the
    /// decoder's bounds.
    /// @custom:matrix-row B15
    function test_wellFormedApplicationReturnIsDecoded() public {
        bytes32 full = keccak256("thirty-two bytes of data");
        bytes[4] memory encoded = [
            abi.encode(bytes("")),
            abi.encode(bytes("ok")),
            abi.encodePacked(uint256(0x20), uint256(32), full),
            // One zero word: offset 0 points at itself, which reads as length 0.
            abi.encode(uint256(0))
        ];
        bytes[4] memory decoded = [bytes(""), bytes("ok"), abi.encodePacked(full), bytes("")];
        for (uint256 i = 0; i < encoded.length; i++) {
            ClprTypes.DecodedReply memory r = _replyToRawReturn(encoded[i]);
            assertEq(uint8(r.status), uint8(ClprTypes.ReplyStatus.SUCCESS), "the message succeeds");
            assertEq(r.messageReplyData, decoded[i], "with the decoded response");
        }
    }
}
