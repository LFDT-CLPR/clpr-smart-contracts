// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {EthRejector} from "@test/mocks/EthRejector.sol";
import {ClprServiceStorageSlots} from "@test/helpers/ClprServiceStorageSlots.sol";
import {ClprStorageLayoutLib} from "@test/helpers/ClprServiceStorageSlots.sol";
import {ClprConnectorRegisterHelper} from "@test/helpers/ClprConnectorRegisterHelper.sol";
import {ClprInvariantEthLib} from "@test/helpers/ClprInvariantEthLib.sol";
import {ClprHandler} from "@test/invariants/ClprHandler.sol";

contract ClprInvariantTest is StdInvariant, Test {
    ClprService internal service;
    MockClprVerifier internal verifier;
    MockClprConnector internal bootstrapConnector;
    MockClprApplication internal app;
    EthRejector internal ethRejector;
    ClprHandler internal handler;
    /// @dev Never registered by `ClprHandler` — safe for `submitBundle` / owner-only ACL probes.
    address internal aclProbe;
    uint256 internal _highWaterChannelCount;
    /// @dev Per-channel high water for INV-CONN-2 / INV-CONN-3 monotonicity checks.
    mapping(bytes32 => uint64) internal _highWaterAckedMessageId;
    mapping(bytes32 => uint64) internal _highWaterNextMessageId;
    mapping(bytes32 => uint64) internal _highWaterReceivedMessageId;

    function setUp() public {
        vm.startMappingRecording();
        vm.fee(1 gwei);
        address owner = address(this);
        service = ClprDeployHelper.deployServiceForTests(owner, 1, "eip155:1337");
        verifier = MockClprVerifier(deployCode("MockClprVerifier.sol:MockClprVerifier"));
        bootstrapConnector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));

        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 4096,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1024,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });

        verifier.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
        verifier.setPeerThrottles(throttles);

        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] = ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex"01"});
        verifier.setSeedEndpoints(seeds);

        ClprTypes.EconomicConfig memory econ = ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            maxChannels: 0,
            maxConnectors: 0,
            connectorPaymentGasLimit: 200_000
        });
        service.initialize(hex"1234", throttles, "", "", econ);
        service.setClprEnabled(true);

        aclProbe = makeAddr("clpr_invariant_acl_probe");
        vm.deal(aclProbe, 1 ether);

        app = MockClprApplication(deployCode("MockClprApplication.sol:MockClprApplication"));
        app.setResponse(hex"504F4E47");
        ethRejector = EthRejector(payable(deployCode("EthRejector.sol:EthRejector")));

        ClprConnectorRegisterHelper connHelper =
            ClprConnectorRegisterHelper(deployCode("ClprConnectorRegisterHelper.sol:ClprConnectorRegisterHelper"));
        bytes memory handlerArgs = abi.encode(
            address(service), address(verifier), address(app), address(ethRejector), address(connHelper), owner
        );
        handler = ClprHandler(deployCode("ClprHandler.sol:ClprHandler", handlerArgs));
        handler.notePendingCandidate(aclProbe);
        targetContract(address(handler));
        _targetHandlerMutators(address(handler));
    }

    function _targetHandlerMutators(address h) internal {
        bytes4[] memory selectors = new bytes4[](25);
        selectors[0] = ClprHandler.registerChannel.selector;
        selectors[1] = ClprHandler.completeChannel.selector;
        selectors[2] = ClprHandler.closeChannel.selector;
        selectors[3] = ClprHandler.registerEndpoint.selector;
        selectors[4] = ClprHandler.removeEndpoint.selector;
        // topUpBond removed with the flat endpoint registry; reuse register to keep the action count.
        selectors[5] = ClprHandler.registerEndpoint.selector;
        selectors[6] = ClprHandler.registerConnector.selector;
        selectors[7] = ClprHandler.removeConnector.selector;
        selectors[8] = ClprHandler.topUpConnectorStake.selector;
        selectors[9] = ClprHandler.sendMessage.selector;
        selectors[10] = ClprHandler.setClprEnabled.selector;
        selectors[11] = ClprHandler.updateLedger.selector;
        selectors[12] = ClprHandler.updateEconomic.selector;
        selectors[13] = ClprHandler.submitEmptyBundle.selector;
        selectors[14] = ClprHandler.submitInboundBundle.selector;
        selectors[15] = ClprHandler.submitAckBundle.selector;
        selectors[16] = ClprHandler.collectPending.selector;
        selectors[17] = ClprHandler.setVerifierRevert.selector;
        selectors[18] = ClprHandler.setTightResourceCaps.selector;
        selectors[19] = ClprHandler.attemptCompleteAtChannelCap.selector;
        selectors[20] = ClprHandler.attemptRegisterAtConnectorCap.selector;
        selectors[21] = ClprHandler.probeReEnableWhenDisabled.selector;
        selectors[22] = ClprHandler.collectPendingWhileDisabled.selector;
        selectors[23] = ClprHandler.submitInboundSlashPendingEthRejector.selector;
        selectors[24] = ClprHandler.submitInboundChargeFailSlashPendingEthRejector.selector;
        targetSelector(FuzzSelector({addr: h, selectors: selectors}));
    }

    function invariant_channelCountMonotonic() external {
        uint256 cur = service.channelCount();
        assertGe(cur, _highWaterChannelCount, "INV-CNT-1: channelCount decreased");
        _highWaterChannelCount = cur;
    }

    /// @dev INV-ETH-1: service balance covers all on-chain locked stake, endpoint bonds, and pending withdrawals.
    function invariant_ethSolvency() external view {
        uint256 liabilities = ClprInvariantEthLib.sumGlobalLiabilities(address(service));
        assertGe(address(service).balance, liabilities, "INV-ETH-1: service insolvency");
    }

    /// @dev INV-ETH-2: every `service.balance` change is captured by handler ghosts (global for the router).
    function invariant_ethBalanceConservation() external view {
        assertEq(
            address(service).balance + handler.ghostEthOut(),
            handler.ghostEthIn() + handler.initialServiceBalance(),
            "INV-ETH-2: global service balance conservation"
        );
    }

    function invariant_channelMapsAndCounters() external {
        for (uint256 i = 0; i < handler.channelLen(); i++) {
            (bytes32 channelId, bytes32 commitment,, bool pending, bool completed) = handler.getChannel(i);
            bool onchainExists =
                _boolAt(ClprStorageLayoutLib.mapBytes32Slot(channelId, ClprServiceStorageSlots.CHANNEL_EXISTS));
            bytes32 onchainReverseCommitment = vm.load(
                address(service),
                ClprStorageLayoutLib.mapBytes32Slot(channelId, ClprServiceStorageSlots.CHANNEL_TO_COMMITMENT)
            );

            assertEq(onchainReverseCommitment, handler.ghostChannelCommitment(channelId), "reverse index mismatch");
            assertEq(onchainExists, handler.ghostChannelCompleted(channelId), "channelExists mismatch");

            bool pendingOnchain =
                _boolAt(ClprStorageLayoutLib.mapBytes32Slot(commitment, ClprServiceStorageSlots.PENDING_COMMITMENTS));
            assertEq(pendingOnchain, handler.ghostPendingCommitment(commitment), "pending commitment mismatch");

            if (pending) {
                assertFalse(onchainExists, "pending channel should not be completed");
                assertFalse(completed, "handler pending/completed flags conflict");
            }
        }

        assertEq(
            service.channelCount(),
            uint256(vm.load(address(service), bytes32(ClprServiceStorageSlots.CHANNEL_COUNT))),
            "channelCount reader drift"
        );
        assertEq(
            service.channelCount(),
            handler.ghostCompletedChannelCount(),
            "INV-CNT: channelCount vs handler completion ghost"
        );
    }

    function invariant_connectorAndEndpointCounts() external {
        assertFalse(handler.ghostConnectorCountReaderMismatchSeen(), "connectorCount reader mismatch seen");
        assertEq(service.connectorCount(), handler.ghostConnectorCount(), "connectorCount mismatch");
        assertEq(
            service.connectorCount(),
            uint256(vm.load(address(service), bytes32(ClprServiceStorageSlots.CONNECTOR_COUNT))),
            "connectorCount slot drift"
        );

        assertEq(service.endpointCount(), handler.ghostEndpointCount(), "endpointCount mismatch");
        for (uint256 i = 0; i < handler.actorLen(); i++) {
            address actor = handler.actorAt(i);
            // On-chain "has a manifest entry" = entries[actor].status != NONE(0).
            bytes32 entryBase =
                ClprStorageLayoutLib.mapAddressSlot(actor, ClprServiceStorageSlots.ENDPOINT_MANIFEST_ENTRIES);
            bool onchain = _boolAt(bytes32(uint256(entryBase) + ClprServiceStorageSlots.ENDPOINT_ENTRY_STATUS_MEMBER));
            assertEq(onchain, handler.ghostEndpointRegistered(actor), "endpoint entry existence mismatch");
        }

        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (bytes32 digest, bytes32 channelId, bytes32 connectorId,,,, bool live) = handler.getConnector(i);
            if (!live) continue;
            assertTrue(service.hasConnector(channelId, connectorId), "INV-MAP: live connector missing on-chain");
            assertTrue(
                _boolAt(ClprStorageLayoutLib.mapBytes32Slot(digest, ClprServiceStorageSlots.CONNECTOR_EXISTS)),
                "INV-MAP: connectorExists slot false"
            );
            ClprTypes.Connector memory onchain = service.getConnector(channelId, connectorId);
            assertEq(handler.ghostConnectorStake(digest), onchain.lockedStake, "INV-MAP: connector stake ghost drift");
            assertGt(onchain.lockedStake, 0, "INV-MAP: live connector lockedStake zero");
        }
    }

    function invariant_configBoundsAndLimits() external {
        ClprTypes.EconomicConfig memory econ = service.getEconomicConfig();
        assertLt(econ.connectorQueueQuotaPct, 100, "connectorQueueQuotaPct must stay < 100");
        assertFalse(handler.ghostMaxChannelsViolatedOnCreate(), "maxChannels violated during successful create");
        assertFalse(handler.ghostMaxConnectorsViolatedOnCreate(), "maxConnectors violated during successful create");
    }

    function invariant_queueAndOrderingBounds() external {
        for (uint256 i = 0; i < handler.channelLen(); i++) {
            (bytes32 channelId,,,, bool completed) = handler.getChannel(i);
            if (!completed) continue;
            ClprTypes.Channel memory channel = service.getChannel(channelId);

            _assertChannelMessageOrdering(channelId, channel);

            // Note: `max_queue_depth` bounds only the sendMessage path (spec §4.3 step 5 /
            // §3.4.4). Protocol-mandated REPLY/CONTROL enqueues during bundle processing
            // intentionally bypass the cap to preserve drain liveness, so total queue depth
            // is not globally bounded.

            // The roster is derived from the cached peer manifest (no dedup / empty-accountId
            // filtering any more — it mirrors the manifest's endpoint list exactly).
            uint256 expectedPeers = verifier.seedEndpointCount();
            assertGt(expectedPeers, 0, "INV-PEER: harness requires at least one manifest endpoint");

            ClprTypes.PeerEndpoint[] memory roster = service.getPeerEndpointRoster(channelId);
            assertEq(roster.length, expectedPeers, "INV-PEER: derived roster length vs verifier manifest");

            _assertPeerRosterAccountsFromVerifier(channelId, verifier);
        }

        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId, bytes32 connectorKey, bytes32 quotaKey,, bool live) =
                handler.getConnector(i);
            if (!live) continue;
            ClprTypes.Channel memory connForQuota = service.getChannel(channelId);
            if (connForQuota.status != ClprTypes.ChannelStatus.ACTIVE) continue;

            uint256 inflightOnchain = uint256(
                vm.load(
                    address(service),
                    ClprStorageLayoutLib.mapBytes32Slot(connectorKey, ClprServiceStorageSlots.CONNECTOR_INFLIGHT)
                )
            );
            uint32 quotaOnchain = uint32(
                uint256(
                    vm.load(
                        address(service),
                        ClprStorageLayoutLib.nestedMapBytes32Bytes32Slot(
                            channelId,
                            keccak256(abi.encodePacked(connectorId)),
                            ClprServiceStorageSlots.CONNECTOR_QUEUE_COUNTS
                        )
                    )
                )
            );

            assertEq(inflightOnchain, handler.ghostInflight(connectorKey), "inflight ghost drift");
            assertEq(quotaOnchain, handler.ghostQuota(quotaKey), "quota ghost drift");
            uint32 queueDepth = uint32(connForQuota.nextMessageId - connForQuota.ackedMessageId - 1);
            assertLe(quotaOnchain, queueDepth, "connector quota cannot exceed queue depth");

            if (handler.lastEnqueueLimitsRevision(channelId) == handler.queueLimitsRevision()) {
                ClprTypes.LedgerConfiguration memory cfgStable = service.getLedgerConfiguration();
                ClprTypes.EconomicConfig memory econStable = service.getEconomicConfig();
                uint32 quotaCap = uint32(
                    (uint256(cfgStable.throttles.maxQueueDepth) * uint256(econStable.connectorQueueQuotaPct)) / 100
                );
                assertLe(quotaOnchain, quotaCap, "INV-CON-2: quota exceeds cap (stable limits)");
            }
        }
        assertFalse(handler.ghostQueueDepthViolatedOnEnqueue(), "queue depth cap violated during successful send");
        assertFalse(handler.ghostQuotaViolatedOnEnqueue(), "quota cap violated during successful send");

        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId, bytes32 connectorKey,,, bool live) = handler.getConnector(i);
            if (live) continue;
            if (service.hasConnector(channelId, connectorId)) continue;
            uint256 inflightAfterRemove = uint256(
                vm.load(
                    address(service),
                    ClprStorageLayoutLib.mapBytes32Slot(connectorKey, ClprServiceStorageSlots.CONNECTOR_INFLIGHT)
                )
            );
            assertEq(inflightAfterRemove, 0, "INV-CON-1: removed connector inflight must be zero");
        }
    }

    /// @dev INV-KILL-1: owner may re-enable while disabled (`setClprEnabled` is not gated by `whenEnabled`).
    function invariant_killSwitch_ownerReEnableAllowedWhenDisabled() external view {
        assertFalse(
            handler.ghostReEnableBlockedByDisabled(),
            "INV-KILL-1: setClprEnabled(true) must not revert ClprDisabled when off"
        );
    }

    /// @dev INV-KILL-1: pull-payment collection stays available while disabled.
    function invariant_killSwitch_collectPendingAllowedWhenDisabled() external view {
        assertFalse(
            handler.ghostCollectPendingBlockedByDisabled(),
            "INV-KILL-1: collectPending must not revert ClprDisabled when off"
        );
    }

    function invariant_aclKillSwitchWhenDisabled() external {
        if (_clprEnabled()) return;
        vm.prank(aclProbe);
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerConnector(bytes32(uint256(1)));
    }

    function invariant_aclKillSwitch_registerChannel() external {
        if (_clprEnabled()) return;
        vm.prank(aclProbe);
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerChannel(bytes32(uint256(99)), bytes32(uint256(100)));
    }

    function invariant_aclKillSwitch_registerEndpoint() external {
        if (_clprEnabled()) return;
        vm.prank(aclProbe);
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerEndpoint{value: 0}(
            ClprTypes.Endpoint({ipAddress: "1.2.3.4", port: 1, tlsCertificate: "", accountId: hex"01"})
        );
    }

    function invariant_aclKillSwitch_sendMessage() external {
        if (_clprEnabled()) return;
        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId,,,, bool live) = handler.getConnector(i);
            if (!live) continue;
            vm.prank(aclProbe);
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.sendMessage(channelId, connectorId, hex"", hex"");
            return;
        }
    }

    function invariant_aclKillSwitch_submitBundle() external {
        if (_clprEnabled()) return;
        if (handler.actorLen() == 0) return;
        for (uint256 i = 0; i < handler.channelLen(); i++) {
            (bytes32 channelId,,,, bool completed) = handler.getChannel(i);
            if (!completed) continue;
            vm.prank(handler.actorAt(0));
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.submitBundle(channelId, hex"");
            return;
        }
    }

    function invariant_aclKillSwitch_updateEconomic() external {
        if (_clprEnabled()) return;
        vm.prank(address(this));
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.updateEconomicConfiguration(
            ClprTypes.EconomicConfig({
                messageExecutionCost: 1,
                endpointMarginPercent: 1,
                minLockedStake: 1,
                minEndpointBond: 0,
                basePenalty: 1,
                penaltyMultiplier: 1,
                slashBanThreshold: 1,
                connectorQueueQuotaPct: 1,
                connectorInboundGasStipend: 500_000,
                maxChannels: 0,
                maxConnectors: 0,
                connectorPaymentGasLimit: 200_000
            })
        );
    }

    function invariant_aclKillSwitch_closeChannel() external {
        if (_clprEnabled()) return;
        for (uint256 i = 0; i < handler.channelLen(); i++) {
            (bytes32 channelId,,,, bool completed) = handler.getChannel(i);
            if (!completed) continue;
            vm.prank(address(this));
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.closeChannel(channelId);
            return;
        }
    }

    function invariant_aclKillSwitch_completeChannel() external {
        if (_clprEnabled()) return;
        vm.prank(aclProbe);
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.completeChannel(bytes32(uint256(1)), hex"", hex"", bytes32(0), address(verifier), hex"", "");
    }

    // invariant_aclKillSwitch_topUpBond removed — topUpBond no longer exists (flat endpoint registry
    // replaced by the two-step manifest; the bond is posted once at registerEndpoint).

    function invariant_aclKillSwitch_removeEndpoint() external {
        if (_clprEnabled()) return;
        for (uint256 i = 0; i < handler.actorLen(); i++) {
            address actor = handler.actorAt(i);
            if (!handler.ghostEndpointRegistered(actor)) continue;
            vm.prank(actor);
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.removeEndpoint(actor);
            return;
        }
    }

    function invariant_aclKillSwitch_topUpConnectorStake() external {
        if (_clprEnabled()) return;
        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId,,,, bool live) = handler.getConnector(i);
            if (!live) continue;
            vm.prank(address(this));
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.topUpConnectorStake(channelId, connectorId, 0);
            return;
        }
    }

    function invariant_aclKillSwitch_removeConnector() external {
        if (_clprEnabled()) return;
        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId,,,, bool live) = handler.getConnector(i);
            if (!live) continue;
            vm.prank(address(this));
            vm.expectRevert(ClprTypes.ClprDisabled.selector);
            service.removeConnector(channelId, connectorId, address(this));
            return;
        }
    }

    function invariant_aclKillSwitch_completeConnector() external {
        if (_clprEnabled()) return;
        vm.prank(aclProbe);
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.completeConnector{value: 0}(hex"01", hex"", hex"", bytes32(0), bytes32(0), address(0), address(0));
    }

    function invariant_aclKillSwitch_updateLedger() external {
        if (_clprEnabled()) return;
        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 1,
            maxMessagePayloadBytes: 1,
            maxGasPerMessage: 1,
            maxQueueDepth: 1,
            maxSyncBytes: 1,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        vm.prank(address(this));
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.updateLedgerConfiguration(hex"01", throttles, "", "");
    }

    function invariant_aclSetClprEnabledRequiresOwner() external {
        vm.prank(aclProbe);
        vm.expectRevert();
        service.setClprEnabled(_clprEnabled());
    }

    function invariant_aclUpdateEconomicRequiresOwner() external {
        vm.prank(aclProbe);
        vm.expectRevert();
        service.updateEconomicConfiguration(
            ClprTypes.EconomicConfig({
                messageExecutionCost: 1,
                endpointMarginPercent: 1,
                minLockedStake: 1,
                minEndpointBond: 0,
                basePenalty: 1,
                penaltyMultiplier: 1,
                slashBanThreshold: 1,
                connectorQueueQuotaPct: 1,
                connectorInboundGasStipend: 500_000,
                maxChannels: 0,
                maxConnectors: 0,
                connectorPaymentGasLimit: 200_000
            })
        );
    }

    function invariant_aclUpdateLedgerRequiresOwner() external {
        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 1,
            maxMessagePayloadBytes: 1,
            maxGasPerMessage: 1,
            maxQueueDepth: 1,
            maxSyncBytes: 1,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        vm.prank(aclProbe);
        vm.expectRevert();
        service.updateLedgerConfiguration(hex"01", throttles, "", "");
    }

    function invariant_aclCloseChannelRequiresOwner() external {
        for (uint256 i = 0; i < handler.channelLen(); i++) {
            (bytes32 channelId,,,, bool completed) = handler.getChannel(i);
            if (!completed) continue;
            vm.prank(aclProbe);
            vm.expectRevert();
            service.closeChannel(channelId);
            return;
        }
    }

    function invariant_aclRemoveConnectorRequiresAdmin() external {
        for (uint256 i = 0; i < handler.connectorLen(); i++) {
            (, bytes32 channelId, bytes32 connectorId,,,, bool live) = handler.getConnector(i);
            if (!live) continue;
            if (!service.hasConnector(channelId, connectorId)) continue;

            vm.prank(aclProbe);
            vm.expectRevert();
            service.removeConnector(channelId, connectorId, aclProbe);
            return;
        }
    }

    /// @dev Every endpoint of the verifier's manifest must appear (by accountId) in the roster
    ///      derived from the Channel's cached peer manifest.
    function _assertPeerRosterAccountsFromVerifier(bytes32 channelId, MockClprVerifier v) internal {
        ClprTypes.PeerEndpoint[] memory roster = service.getPeerEndpointRoster(channelId);
        uint256 n = v.seedEndpointCount();
        for (uint256 i = 0; i < n; i++) {
            ClprTypes.Endpoint memory ep = v.getSeedEndpoint(i);
            bool found;
            for (uint256 j = 0; j < roster.length; j++) {
                if (keccak256(roster[j].accountId) == keccak256(ep.accountId)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "INV-PEER: manifest accountId missing from derived roster");
        }
    }

    function _clprEnabled() internal view returns (bool) {
        bytes32 packed = vm.load(address(service), bytes32(ClprServiceStorageSlots.PACKED_MISC));
        return ((uint256(packed) >> ClprServiceStorageSlots.CLPR_ENABLED_BIT_SHIFT) & 0xFF) != 0;
    }

    function _boolAt(bytes32 slot) internal view returns (bool) {
        return _boolWord(vm.load(address(service), slot));
    }

    function _boolWord(bytes32 word) internal pure returns (bool) {
        return uint256(word) != 0;
    }

    /// @dev INV-CONN-2: outbound window (`acked < next`, monotonic `ackedMessageId` / `nextMessageId`).
    ///      INV-CONN-3: inbound high-water (`receivedMessageId` monotonic, `nextMessageId >= 1`).
    function _assertChannelMessageOrdering(bytes32 channelId, ClprTypes.Channel memory channel) internal {
        assertGe(channel.nextMessageId, 1, "INV-CONN-3: nextMessageId baseline");
        assertLt(channel.ackedMessageId, channel.nextMessageId, "INV-CONN-2: acked < next");

        uint64 prevAcked = _highWaterAckedMessageId[channelId];
        assertGe(channel.ackedMessageId, prevAcked, "INV-CONN-2: ackedMessageId monotonic");
        if (channel.ackedMessageId > prevAcked) {
            _highWaterAckedMessageId[channelId] = channel.ackedMessageId;
        }

        uint64 prevNext = _highWaterNextMessageId[channelId];
        assertGe(channel.nextMessageId, prevNext, "INV-CONN-2: nextMessageId monotonic");
        if (channel.nextMessageId > prevNext) {
            _highWaterNextMessageId[channelId] = channel.nextMessageId;
        }

        uint64 prevReceived = _highWaterReceivedMessageId[channelId];
        assertGe(channel.receivedMessageId, prevReceived, "INV-CONN-3: receivedMessageId monotonic");
        if (channel.receivedMessageId > prevReceived) {
            _highWaterReceivedMessageId[channelId] = channel.receivedMessageId;
        }
    }
}
