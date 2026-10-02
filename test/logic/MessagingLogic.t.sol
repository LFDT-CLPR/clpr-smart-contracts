// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";

contract MessagingLogicTest is ClprTestBase {
    event MessageQueued(bytes32 indexed channelId, uint64 messageId, ClprTypes.MessageType messageType);
    event MessageRedacted(bytes32 indexed channelId, uint64 messageId);

    function test_maybeEnqueueConfigUpdate_enqueuesControlOnSendMessage() public {
        // Update local ledger configuration so _config.nanosSinceEpoch > channel.lastConfigTimestamp
        // completeChannel set lastConfigTimestamp = block.timestamp * 1e9. Advance time so the
        // new config has a strictly greater nanosSinceEpoch than the channel's timestamp.
        vm.warp(block.timestamp + 1);
        service.updateLedgerConfiguration(hex"ABCD", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());

        // Prepare connector
        bytes32 connectorId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("ml.cov.connector")), address(connector), owner, 0.5 ether
        );
        (bool okFund,) = address(connector).call{value: 0.5 ether}("");
        require(okFund, "fund connector failed");

        ClprTypes.Channel memory beforeConn = service.getChannel(channelId);
        uint64 expectedControlId = beforeConn.nextMessageId;

        vm.expectEmit(true, true, true, true, address(service));
        emit MessageQueued(channelId, expectedControlId, ClprTypes.MessageType.CONTROL);

        uint64 dataMsgId = service.sendMessage(channelId, connectorId, hex"11223344", hex"01");

        assertEq(dataMsgId, expectedControlId + 1, "DATA should follow CONTROL in the queue");

        //Verify queue contents and state updates
        {
            ClprTypes.MessageValue memory controlMsg = service.getMessage(channelId, expectedControlId);
            assertGt(controlMsg.payload.length, 0, "control payload stored");
            assertEq(
                uint8(ClprProtobuf.getMessageType(controlMsg.payload)),
                uint8(ClprTypes.MessageType.CONTROL),
                "first enqueued must be CONTROL"
            );
        }
        {
            ClprTypes.MessageValue memory dataMsg = service.getMessage(channelId, dataMsgId);
            assertGt(dataMsg.payload.length, 0, "data payload stored");
            assertEq(
                uint8(ClprProtobuf.getMessageType(dataMsg.payload)),
                uint8(ClprTypes.MessageType.DATA),
                "second enqueued must be DATA"
            );
        }

        // Channel bookkeeping updated: nextMessageId advanced by 2 and
        //    lastConfigTimestamp set to current config's nanosSinceEpoch
        ClprTypes.Channel memory afterConn = service.getChannel(channelId);
        assertEq(afterConn.nextMessageId, expectedControlId + 2, "nextMessageId should advance by 2");

        ClprTypes.LedgerConfiguration memory cfg = service.getLedgerConfiguration();
        assertEq(afterConn.lastConfigTimestamp, cfg.nanosSinceEpoch, "lastConfigTimestamp updated to config nanos");

        // Running hash advanced non-zero
        assertTrue(afterConn.sentRunningHash != beforeConn.sentRunningHash, "running hash should update");
    }

    function test_sendMessage_revert_channelNotFound() public {
        bytes32 unknownId = keccak256("unknown-conn");
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.sendMessage(unknownId, hex"AA", hex"BB", hex"CC");
    }

    function test_sendMessage_revert_nonActiveChannel() public {
        service.closeChannel(channelId);

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.sendMessage(channelId, hex"AA", hex"BB", hex"CC");
    }

    function test_sendMessage_payloadTooLarge_when_channelMaxPayloadBytesIsZero() public {
        defaultThrottles.maxMessagePayloadBytes = 0;
        verifier.setPeerThrottles(defaultThrottles);
        bytes32 salt = bytes32(uint256(1));
        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, salt);
        service.registerChannel(connId, keccak256(abi.encodePacked(connId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.completeChannel(connId, pubKey, abi.encodePacked(r, s, v), salt, address(verifier), hex"0001", "");
    }

    function test_sendMessage_payloadTooLarge_when_messageDataIsBiggerThanMaxPayloadBytes() public {
        verifier.setPeerThrottles(defaultThrottles);
        bytes32 connId = _openExtraChannel(bytes32(uint256(2)));
        bytes memory bigPayload = new bytes(2048);

        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(connId, hex"AA", hex"11223344", bigPayload);
    }

    /// @dev Peer throttles with a chosen maxSyncBytes and a payload ceiling high enough that
    ///      only the wedge guard (never ClprPayloadTooLarge) can fire in these tests.
    function _wedgeThrottles(uint64 maxSyncBytes) internal pure returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: uint64(uint256(maxSyncBytes) - ClprTypes.WORST_CASE_BUNDLE_OVERHEAD - 1),
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: maxSyncBytes,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }

    function test_sendMessage_wedgeGuard_rejectsUndeliverableMessage() public {
        // 2_000B message + 1B connId + 4B target + 20B sender + 32_768B overhead = 34_793.
        verifier.setPeerThrottles(_wedgeThrottles(34_792));
        bytes32 connId = _openExtraChannel(bytes32(uint256(0xE1)));

        bytes memory messageData = new bytes(2_000);

        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(connId, hex"AA", hex"11223344", messageData);
    }

    function test_sendMessage_wedgeGuard_boundary() public {
        uint64 maxSyncBytes = 65_536;
        verifier.setPeerThrottles(_wedgeThrottles(maxSyncBytes));
        bytes32 connId = _openExtraChannel(bytes32(uint256(0xE2)));

        bytes32 wedgeConnectorId = ConnectorRegistrar.register(
            service, connId, keccak256("wedge.boundary.connector"), address(connector), owner, 0.5 ether
        );
        bytes memory targetApp = hex"11223344";

        uint256 maxData = uint256(maxSyncBytes) - ClprTypes.WORST_CASE_BUNDLE_OVERHEAD - 20 - wedgeConnectorId.length
            - targetApp.length;

        uint64 msgId = service.sendMessage(connId, wedgeConnectorId, targetApp, new bytes(maxData));
        assertGt(service.getMessage(connId, msgId).payload.length, 0, "boundary message must be enqueued");
        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(connId, wedgeConnectorId, targetApp, new bytes(maxData + 1));
    }

    function test_sendMessage_wedgeGuard_countsAllEncodedFields() public {
        // 1B message + 1B connId + 6_000B target + 20B sender + 32_768B overhead = 38_790.
        verifier.setPeerThrottles(_wedgeThrottles(38_789));
        bytes32 connId = _openExtraChannel(bytes32(uint256(0xE3)));

        bytes memory hugeTargetApp = new bytes(6_000);

        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(connId, hex"AA", hugeTargetApp, hex"01");
    }

    function test_sendMessage_wedgeGuard_usesPeerThrottlesNotLocal() public {
        ClprTypes.Throttles memory local = _defaultThrottles();
        local.maxSyncBytes = uint64(uint256(local.maxMessagePayloadBytes) + ClprTypes.WORST_CASE_BUNDLE_OVERHEAD + 1);
        service.updateLedgerConfiguration(hex"1234", local, "", "");

        bytes32 wedgeConnectorId = ConnectorRegistrar.register(
            service, channelId, keccak256("wedge.local.connector"), address(connector), owner, 0.5 ether
        );

        bytes memory maxPayload = new bytes(local.maxMessagePayloadBytes);
        uint64 msgId = service.sendMessage(channelId, wedgeConnectorId, hex"01", maxPayload);
        assertGt(uint256(msgId), 0, "send must succeed against the peer limit");
    }

    function test_sendMessage_revert_connectorQuotaExceeded() public {
        defaultThrottles.maxQueueDepth = 10;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");

        ClprTypes.EconomicConfig memory econ = ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 10,
            connectorInboundGasStipend: 500_000,
            maxChannels: 0,
            maxConnectors: 0
        });
        service.updateEconomicConfiguration(econ);

        bytes32 connectorId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("quota.connector")), address(connector), owner, 0.5 ether
        );
        (bool okFund,) = address(connector).call{value: 0.5 ether}("");
        require(okFund, "fund connector failed");

        // First message should pass (count becomes 1 which equals quota)
        service.sendMessage(channelId, connectorId, hex"11223344", hex"01");

        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, hex"11223344", hex"02");
    }

    // ── redactMessage ──────────────────────────────────────────────────

    function test_redactMessage_revert_channelNotFound() public {
        bytes32 unknownId = keccak256("unknown-conn-redact");
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.redactMessage(unknownId, 1);
    }

    function test_redactMessage_revert_invalidMessageId_belowWindow() public {
        // messageId=0 is always <= ackedMessageId=0; no message queued needed.
        vm.expectRevert(ClprTypes.ClprInvalidMessageId.selector);
        service.redactMessage(channelId, 0);
    }

    function test_redactMessage_replacesPayloadWithRedactedMarkerPreservesHashEmitsEvent() public {
        service.updateLedgerConfiguration(hex"1234", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());
        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.basic.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);
        uint64 msgId = service.sendMessage(channelId, connId, hex"11223344", hex"48454C4C4F");
        bytes32 hashBefore = service.getMessage(channelId, msgId).runningHashAfterProcessing;

        vm.expectEmit(true, true, false, false, address(service));
        emit MessageRedacted(channelId, msgId);
        service.redactMessage(channelId, msgId);

        ClprTypes.MessageValue memory mv = service.getMessage(channelId, msgId);
        assertEq(
            uint8(ClprProtobuf.getMessageType(mv.payload)),
            uint8(ClprTypes.MessageType.REDACTED),
            "payload must be a REDACTED marker"
        );
        assertEq(mv.runningHashAfterProcessing, hashBefore, "running hash must be preserved");
    }

    // Redacting a DATA message decrements _connectorQueueCounts. Observable via quota:
    // fill to quota (count=1=quota), redact, then another send succeeds (count back to 0).
    function test_redactMessage_decrementsQueueCount_freesQuota() public {
        defaultThrottles.maxQueueDepth = 10;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 10; // quota = floor(10*10/100) = 1
        service.updateEconomicConfiguration(econ);

        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.quota.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);

        uint64 msgId = service.sendMessage(channelId, connId, hex"11223344", hex"01"); // count=1=quota

        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connId, hex"11223344", hex"02"); // blocked

        service.redactMessage(channelId, msgId); // count→0

        service.sendMessage(channelId, connId, hex"11223344", hex"03"); // count=0 < quota=1, passes
    }

    // Redacting a DATA message decrements _connectorInflightCount. Observable via removeConnector:
    // blocked while inflight > 0, succeeds once the message is redacted.
    function test_redactMessage_decrementsInflightCount_unblocksRemoveConnector() public {
        service.updateLedgerConfiguration(hex"1234", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());
        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.inflight.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);

        uint64 msgId = service.sendMessage(channelId, connId, hex"11223344", hex"01"); // inflight=1

        vm.expectRevert(ClprTypes.ClprConnectorHasInflightMessages.selector);
        service.removeConnector(channelId, connId, owner); // blocked

        service.redactMessage(channelId, msgId); // inflight→0

        service.removeConnector(channelId, connId, owner); // succeeds
    }

    // Only DATA messages may be redacted; attempting to redact a CONTROL message must revert.
    function test_redactMessage_controlMessage_reverts() public {
        // completeChannel stamps lastConfigTimestamp = block.timestamp * 1e9.
        // Warp one second before updateLedgerConfiguration so nanosSinceEpoch > lastConfigTimestamp → CONTROL fires.
        vm.warp(block.timestamp + 1);
        defaultThrottles.maxQueueDepth = 10;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 10;
        service.updateEconomicConfiguration(econ);

        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.ctrl.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);

        // First send: CONTROL injected at nextMessageId, DATA follows.
        ClprTypes.Channel memory before = service.getChannel(channelId);
        uint64 controlId = before.nextMessageId;
        service.sendMessage(channelId, connId, hex"11223344", hex"01");

        // Attempting to redact a CONTROL message must revert.
        vm.expectRevert(ClprTypes.ClprMessageNotRedactable.selector);
        service.redactMessage(channelId, controlId);
    }

    // The redacted payload must be a REDACTED-type message whose embedded hash equals SHA-256(original_payload).
    function test_redactMessage_storesHashOfOriginalPayload() public {
        service.updateLedgerConfiguration(hex"1234", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());
        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.hash.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);

        uint64 msgId = service.sendMessage(channelId, connId, hex"11223344", hex"48454C4C4F");
        bytes memory originalPayload = service.getMessage(channelId, msgId).payload;
        bytes32 expectedHash = sha256(originalPayload);

        service.redactMessage(channelId, msgId);

        bytes memory redactedPayload = service.getMessage(channelId, msgId).payload;
        assertEq(
            uint8(ClprProtobuf.getMessageType(redactedPayload)),
            uint8(ClprTypes.MessageType.REDACTED),
            "redacted slot must carry REDACTED type"
        );
        // Decode ClprRedactedMessage { message_hash = 1 } to verify the embedded hash.
        // Wire: outer field 4 LEN | inner field 1 LEN | 32-byte hash.
        // Offset 0: field key (1 byte), offset 1: outer len (1 byte),
        // offset 2: inner field key (1 byte), offset 3: inner len (1 byte), offset 4..35: hash.
        bytes32 storedHash;
        assembly {
            // redactedPayload is a bytes; skip 32-byte length prefix then read from offset 4.
            storedHash := mload(add(add(redactedPayload, 32), 4))
        }
        assertEq(storedHash, expectedHash, "embedded hash must equal SHA-256(original_payload)");
    }

    // Redacting a message that was already redacted must revert with ClprMessageAlreadyRedacted.
    function test_redactMessage_revert_alreadyRedacted_detectedViaType() public {
        service.updateLedgerConfiguration(hex"1234", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());
        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("redact.dup.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok);

        uint64 msgId = service.sendMessage(channelId, connId, hex"11223344", hex"01");
        service.redactMessage(channelId, msgId); // first redaction: succeeds

        vm.expectRevert(ClprTypes.ClprMessageAlreadyRedacted.selector);
        service.redactMessage(channelId, msgId); // second redaction: must revert
    }

    // Config before _createActiveChannel so channel.lastConfigTimestamp == _config.nanosSinceEpoch;
    // _maybeEnqueueConfigUpdate does not fire during fills. Two connectors distribute messages
    // so no single connector hits quota (floor(2*50/100)=1) before the queue fills.
    function test_getQueueDepth_tracksSendMessage() public {
        ClprTypes.Throttles memory throttles = _defaultThrottles();
        throttles.maxQueueDepth = 2;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 50;
        service.updateEconomicConfiguration(econ);

        ClprTypes.QueueDepth memory qd = service.getQueueDepth(channelId);
        assertEq(qd.queueDepth, 0, "fresh channel has zero depth");
        assertEq(qd.maxQueueDepth, 2, "max reflects configured throttle");

        // Two distinct connectors, one message each, so the per-connector queue quota
        // (50% of maxQueueDepth = 1) isn't the thing under test — see
        // test_sendMessage_queueFull_earlyCheck_connectorNotCalled for the same pattern.
        bytes32 connId1 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qd.c1")), address(connector), owner, 0.5 ether
        );
        bytes32 connId2 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qd.c2")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 1 ether}("");
        require(ok, "fund connector failed");

        service.sendMessage(channelId, connId1, hex"11223344", hex"01");
        qd = service.getQueueDepth(channelId);
        assertEq(qd.queueDepth, 1, "queueDepth advances with each unacked outbound message");

        service.sendMessage(channelId, connId2, hex"11223344", hex"02");
        qd = service.getQueueDepth(channelId);
        assertEq(qd.queueDepth, 2, "queueDepth reaches maxQueueDepth");
        assertEq(qd.maxQueueDepth, 2);
    }

    function test_sendMessage_queueFull_earlyCheck_connectorNotCalled() public {
        defaultThrottles.maxQueueDepth = 2;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 50;
        service.updateEconomicConfiguration(econ);

        bytes32 connId1 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qf.early.c1")), address(connector), owner, 0.5 ether
        );
        bytes32 connId2 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qf.early.c2")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 1 ether}("");
        require(ok, "fund connector failed");

        service.sendMessage(channelId, connId1, hex"11223344", hex"01"); // depth 1
        service.sendMessage(channelId, connId2, hex"11223344", hex"02"); // depth 2 = maxQueueDepth

        vm.expectCall(address(connector), abi.encodeWithSelector(IClprConnector.authorizeOutboundMessage.selector), 0);
        vm.expectRevert(ClprTypes.ClprQueueFull.selector);
        service.sendMessage(channelId, connId1, hex"11223344", hex"03");
    }

    // Queue has one free slot so the early check and quota both pass; the connector is called.
    // Config updated after the fill so _maybeEnqueueConfigUpdate injects a CONTROL on the attempt,
    // consuming the last slot. The second queueFull check then fires.
    // A fresh connId2 (count=0) is used for the attempt so quota (floor(2*50/100)=1) does not
    // fire before the second check — with connId1 exhausted at count=1, quota would fire first.
    function test_sendMessage_queueFull_secondCheck_connectorCalled() public {
        defaultThrottles.maxQueueDepth = 2;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig()); // pct=50 → quota=1

        bytes32 connId1 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qf.second.c1")), address(connector), owner, 0.5 ether
        );
        bytes32 connId2 = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("qf.second.c2")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 1 ether}("");
        require(ok, "fund connector failed");

        service.sendMessage(channelId, connId1, hex"11223344", hex"01"); // depth 1, connId1 count=1=quota

        // Advancing time produces a higher nanosSinceEpoch on the next config update,
        // so _maybeEnqueueConfigUpdate fires on the attempt and injects a CONTROL message.
        vm.warp(block.timestamp + 1);
        service.updateLedgerConfiguration(hex"ABCD", defaultThrottles, "", "");

        // connId2 count=0 < quota=1 → passes. Early check passes (1 free slot) → connector called
        // → CONTROL fills the slot → second queueFull check fires.
        vm.expectCall(address(connector), abi.encodeWithSelector(IClprConnector.authorizeOutboundMessage.selector), 1);
        vm.expectRevert(ClprTypes.ClprQueueFull.selector);
        service.sendMessage(channelId, connId2, hex"11223344", hex"02");
    }

    // When quota is exhausted the connector must not be called at all.
    function test_sendMessage_quotaExceeded_connectorNotCalled() public {
        defaultThrottles.maxQueueDepth = 10;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 10; // quota = floor(10*10/100) = 1
        service.updateEconomicConfiguration(econ);

        bytes32 connId = ConnectorRegistrar.register(
            service, channelId, keccak256(abi.encodePacked("quota.nc.c")), address(connector), owner, 0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok, "fund connector failed");

        service.sendMessage(channelId, connId, hex"11223344", hex"01"); // count=1=quota

        vm.expectCall(address(connector), abi.encodeWithSelector(IClprConnector.authorizeOutboundMessage.selector), 0);
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connId, hex"11223344", hex"02");
    }

    receive() external payable {}
}

contract ClprService_Messaging is ClprServiceTestBase {
    function test_sendMessage_basic() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");

        assertEq(msgId, 1);
        assertEq(connector.authorizeCallCount(), 1);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.nextMessageId, 2);
        assertTrue(channel.sentRunningHash != bytes32(0));
    }

    function test_sendMessage_revert_connectorRejects() public {
        _registerTestConnector();
        connector.setAuthorize(false);
        vm.expectRevert(ClprTypes.ClprConnectorUnauthorized.selector);
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");
    }

    function test_sendMessage_revert_connectorReverts() public {
        _registerTestConnector();
        connector.setAuthorizeReverts(true);
        vm.expectRevert(bytes("authorize revert"));
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");
    }

    function test_sendMessage_reentrancy_blocked() public {
        _registerTestConnector();

        // Configure the connector to reentrantly call sendMessage from inside authorizeOutboundMessage.
        bytes memory reentrantCall =
            abi.encodeWithSelector(service.sendMessage.selector, channelId, connectorId, hex"1122334455", hex"02");
        connector.setReentrancy(address(service), reentrantCall);

        // MockClprConnector re-reverts with its own require string, so the guard's
        // ReentrancyGuardReentrantCall selector is not observable from here. Assert the
        // wrapper the mock actually produces rather than accepting any revert.
        vm.expectRevert(bytes("reentrant call failed"));
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");
    }

    function test_sendMessage_revert_channelNotActive() public {
        // Use a non-existent channel ID
        bytes32 nonExistentChannelId = _deriveTestChannelId(_signerPubKey(), bytes32(uint256(100)));
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.sendMessage(nonExistentChannelId, hex"AA", hex"BB", hex"DD");
    }

    function test_sendMessage_revert_connectorNotFound() public {
        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        service.sendMessage(channelId, hex"FF00FF00", hex"BB", hex"DD");
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        _registerTestConnector();
        bytes memory bigPayload = new bytes(2048);
        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(channelId, connectorId, hex"1122334455", bigPayload);
    }

    /// @dev peerThrottles is populated by verifyConfig during completeChannel. If the verifier
    ///      returns maxMessagePayloadBytes=0 (the proto3 default when unpopulated), any sendMessage
    ///      call is rejected at this guard before the payload-length comparison.
    function test_sendMessage_revert_zeroPeerThrottlePayloadLimit() public {
        defaultThrottles.maxMessagePayloadBytes = 0;
        verifier.setPeerThrottles(defaultThrottles);
        bytes32 salt = bytes32(uint256(42));
        bytes memory pubKey = _signerPubKey();
        bytes32 connId = _deriveTestChannelId(pubKey, salt);
        service.registerChannel(connId, keccak256(abi.encodePacked(connId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.completeChannel(connId, pubKey, abi.encodePacked(r, s, v), salt, address(verifier), hex"0001", "");
    }

    function test_sendMessage_revert_queueFull() public {
        // maxQueueDepth=2, pct=50 → quota=1 per connector.  Use two connectors so
        // neither hits its quota before the shared queue fills.
        defaultThrottles.maxQueueDepth = 2;
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        _setupDefaultEconomicConfig(); // connectorQueueQuotaPct = 50

        bytes32 connId1 = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("svc-conn-qf-1")),
            address(connector),
            owner,
            0.5 ether
        );
        bytes32 connId2 = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("svc-conn-qf-2")),
            address(connector),
            owner,
            0.5 ether
        );
        (bool ok,) = address(connector).call{value: 1 ether}("");
        require(ok, "fund connector failed");

        service.sendMessage(channelId, connId1, hex"1122334455", hex"01");
        service.sendMessage(channelId, connId2, hex"1122334455", hex"02");
        vm.expectRevert(ClprTypes.ClprQueueFull.selector);
        service.sendMessage(channelId, connId1, hex"1122334455", hex"03");
    }

    /// @dev Verifies that the sender field in the queued DATA message is stamped
    ///      as msg.sender (address A), not any caller-supplied value.
    function test_sendMessage_stampsCallerAsSender() public {
        _registerTestConnector();

        address callerA = makeAddr("callerA");
        vm.prank(callerA);
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");

        ClprTypes.MessageValue memory mv = service.getMessage(channelId, msgId);
        ClprTypes.DecodedDataMessage memory decoded = ClprProtobuf.decodeDataMessage(mv.payload);
        assertEq(decoded.sender, abi.encodePacked(callerA), "sender must be stamped as msg.sender (callerA)");
    }

    /// @dev Verifies that a different caller (address B) yields sender == B,
    ///      proving the stamp is per-call and cannot be forged.
    function test_sendMessage_stampsCallerAsSender_differentCallers() public {
        _registerTestConnector();

        address callerA = makeAddr("callerA");
        address callerB = makeAddr("callerB");

        vm.prank(callerA);
        uint64 msgIdA = service.sendMessage(channelId, connectorId, hex"1122334455", hex"AABB");
        vm.prank(callerB);
        uint64 msgIdB = service.sendMessage(channelId, connectorId, hex"1122334455", hex"CCDD");

        ClprTypes.DecodedDataMessage memory decodedA =
            ClprProtobuf.decodeDataMessage(service.getMessage(channelId, msgIdA).payload);
        ClprTypes.DecodedDataMessage memory decodedB =
            ClprProtobuf.decodeDataMessage(service.getMessage(channelId, msgIdB).payload);

        assertEq(decodedA.sender, abi.encodePacked(callerA), "message from A must have sender == callerA");
        assertEq(decodedB.sender, abi.encodePacked(callerB), "message from B must have sender == callerB");
        assertTrue(
            keccak256(decodedA.sender) != keccak256(decodedB.sender),
            "different callers must produce different sender stamps"
        );
    }

    /// @dev sendMessage rejects payloads that exceed the peer's maxMessagePayloadBytes limit,
    ///      distinct from the local-config limit tested by test_sendMessage_revert_payloadTooLarge.
    function test_sendMessage_rejectsPayloadOverPeerLimit() public {
        // Set peer cap to 10 bytes, local cap to 1000 bytes.
        defaultThrottles.maxMessagePayloadBytes = 10;
        verifier.setPeerThrottles(defaultThrottles);

        channelId = _openExtraChannel(bytes32(uint256(43)));
        // Local config has maxMessagePayloadBytes=1000
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
        _setupDefaultEconomicConfig();
        _registerTestConnector();

        bytes memory elevenBytes = new bytes(11);
        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(channelId, connectorId, hex"1122334455", elevenBytes);
    }

    // submitBundle_revert_callerNotRegisteredEndpoint moved to
    // test/logic/bundle-logic/BundleLogic_ErrorHandling.t.sol (tests BundleLogic's endpoint
    // gate, not MessagingLogic).
}

contract ClprService_Redaction is ClprServiceTestBase {
    function test_redactMessage() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");
        service.redactMessage(channelId, msgId);
        ClprTypes.MessageValue memory msg_ = service.getMessage(channelId, msgId);
        assertEq(uint8(ClprProtobuf.getMessageType(msg_.payload)), uint8(ClprTypes.MessageType.REDACTED));
    }

    function test_redactMessage_revert_alreadyRedacted() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");
        service.redactMessage(channelId, msgId);
        vm.expectRevert(ClprTypes.ClprMessageAlreadyRedacted.selector);
        service.redactMessage(channelId, msgId);
    }

    function test_redactMessage_revert_notOwner() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");
        vm.prank(address(0x99));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x99)));
        service.redactMessage(channelId, msgId);
    }

    function test_redactMessage_revert_messageIdZero() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");
        vm.expectRevert(ClprTypes.ClprInvalidMessageId.selector);
        service.redactMessage(channelId, 0);
    }

    function test_redactMessage_revert_messageIdAtNextMessageIdBoundary() public {
        _registerTestConnector();
        vm.expectRevert(ClprTypes.ClprInvalidMessageId.selector);
        service.redactMessage(channelId, 1);
    }

    function test_redactMessage_preserves_runningHashAfterProcessing() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");
        bytes32 hashBefore = service.getMessage(channelId, msgId).runningHashAfterProcessing;
        service.redactMessage(channelId, msgId);
        ClprTypes.MessageValue memory mv = service.getMessage(channelId, msgId);
        assertEq(uint8(ClprProtobuf.getMessageType(mv.payload)), uint8(ClprTypes.MessageType.REDACTED));
        assertEq(mv.runningHashAfterProcessing, hashBefore);
    }

    function test_redactMessage_revert_notRedactable_nonDataMessage() public {
        // A CONTROL message auto-injected by sendMessage must not be redactable.
        vm.warp(block.timestamp + 1);
        service.updateLedgerConfiguration(hex"ABCD", _defaultThrottles(), "", "");
        service.updateEconomicConfiguration(_defaultEconomicConfig());
        _registerTestConnector();

        ClprTypes.Channel memory before = service.getChannel(channelId);
        uint64 controlId = before.nextMessageId;
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");

        vm.expectRevert(ClprTypes.ClprMessageNotRedactable.selector);
        service.redactMessage(channelId, controlId);
    }

    function test_redactMessage_storesHashOfOriginalPayload() public {
        _registerTestConnector();
        uint64 msgId = service.sendMessage(channelId, connectorId, hex"1122334455", hex"48454C4C4F");
        bytes memory originalPayload = service.getMessage(channelId, msgId).payload;
        bytes32 expectedHash = sha256(originalPayload);

        service.redactMessage(channelId, msgId);

        bytes memory redactedPayload = service.getMessage(channelId, msgId).payload;
        assertEq(
            uint8(ClprProtobuf.getMessageType(redactedPayload)),
            uint8(ClprTypes.MessageType.REDACTED),
            "slot must carry REDACTED type"
        );
        bytes32 storedHash;
        assembly {
            // skip 32-byte length prefix, then 4 bytes of proto framing (outer key, outer len, inner key, inner len).
            storedHash := mload(add(add(redactedPayload, 32), 4))
        }
        assertEq(storedHash, expectedHash, "embedded hash must equal SHA-256(original_payload)");
    }
}
