// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";

/// @dev Helper whose receive() always reverts, exercising the ClprTransferFailed path on collectPending.
contract RevertingReceiver {
    receive() external payable {
        revert();
    }

    function doCollectPending(ClprService svc) external {
        svc.collectPending();
    }
}

contract AdminLogicTest is ClprTestBase {
    function test_collectPending_reverts_zeroBalance() public {
        vm.expectRevert(ClprTypes.ClprNothingToCollect.selector);
        service.collectPending();
    }

    // NOTE: removeEndpoint no longer pushes ETH — the bond is credited to pendingWithdrawals
    // (pull-payment), so there is no ClprTransferFailed path on removal to test here.

    /// @dev collectPending: pending balance > 0, but msg.sender.call fails.
    ///      Seed _pendingWithdrawals[rr] via vm.store (slot 11 per storage-layout.json),
    ///      then call collectPending() from the reverting receiver.
    function test_collectPending_transferFailed() public {
        RevertingReceiver rr = new RevertingReceiver();

        // _pendingWithdrawals is at storage slot 11; mapping slot = keccak256(key || slot)
        bytes32 slot = keccak256(abi.encode(address(rr), uint256(11)));
        vm.store(address(service), slot, bytes32(uint256(1 ether)));
        assertEq(service.pendingWithdrawals(address(rr)), 1 ether);

        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        rr.doCollectPending(service);
    }

    /// @dev collectPending transfers the full accumulated amount to msg.sender and clears the balance.
    function test_collectPending_transfersFundsAndClearsBalance() public {
        address payable recipient = payable(makeAddr("recipient"));
        uint256 amount = 0.05 ether;

        bytes32 slot = keccak256(abi.encode(recipient, uint256(11)));
        vm.store(address(service), slot, bytes32(amount));
        vm.deal(address(service), amount);

        uint256 balBefore = recipient.balance;
        vm.prank(recipient);
        service.collectPending();

        assertEq(recipient.balance, balBefore + amount, "recipient should receive pending ETH");
        assertEq(service.pendingWithdrawals(recipient), 0, "pending balance should be cleared");
    }

    /// @dev collectPending is not idempotent: once the pending balance is collected and
    ///      cleared, a second call reverts instead of being a no-op.
    function test_collectPending_revertsOnDoubleCollect() public {
        address payable recipient = payable(makeAddr("recipient"));
        uint256 amount = 0.05 ether;

        bytes32 slot = keccak256(abi.encode(recipient, uint256(11)));
        vm.store(address(service), slot, bytes32(amount));
        vm.deal(address(service), amount);

        vm.prank(recipient);
        service.collectPending();

        vm.expectRevert(ClprTypes.ClprNothingToCollect.selector);
        vm.prank(recipient);
        service.collectPending();
    }

    receive() external payable {}
}

contract EndpointManagerTest is ClprTestBase {
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    function setUp() public override {
        service = _deployClprService(1, "eip155:1337");

        _setEconomicConfig(0.5 ether);

        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ── Endpoint manifest: two-step admission ──────────────────────────

    function _ep(bytes memory accountId) internal pure returns (ClprTypes.Endpoint memory) {
        return ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: accountId});
    }

    function test_register_createsPendingEntry_notInManifest() public {
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));

        ClprTypes.EndpointManifestEntry memory e = service.getEndpointEntry(alice);
        assertEq(uint256(e.status), uint256(ClprTypes.EndpointStatus.PENDING));
        assertEq(e.bond, 0.5 ether);
        // Pending entries are not advertised in the live manifest.
        assertEq(service.endpointCount(), 0);
        assertEq(service.getEndpointManifest().endpoints.length, 0);
    }

    function test_register_revert_alreadyRegistered() public {
        vm.startPrank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        vm.expectRevert(ClprTypes.ClprEndpointAlreadyRegistered.selector);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        vm.stopPrank();
    }

    function test_register_revert_belowMinBond() public {
        vm.prank(alice);
        vm.expectRevert(ClprTypes.ClprInsufficientBond.selector);
        service.registerEndpoint{value: 0.4 ether}(_ep(hex"01"));
    }

    function test_addEndpoint_promotesPending_usesSelfData_bumpsVersion() public {
        uint64 v0 = service.getEndpointManifest().version;
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));

        service.addEndpoint(alice, _ep(hex"FF")); // endpoint arg ignored — self-registered data used

        ClprTypes.EndpointManifestEntry memory e = service.getEndpointEntry(alice);
        assertEq(uint256(e.status), uint256(ClprTypes.EndpointStatus.LIVE));
        assertEq(e.bond, 0.5 ether);
        assertEq(e.endpoint.accountId, hex"01");
        assertEq(service.endpointCount(), 1);
        assertEq(service.getEndpointManifest().version, v0 + 1);
    }

    function test_addEndpoint_directAdd_noBond() public {
        service.addEndpoint(bob, _ep(hex"02"));
        ClprTypes.EndpointManifestEntry memory e = service.getEndpointEntry(bob);
        assertEq(uint256(e.status), uint256(ClprTypes.EndpointStatus.LIVE));
        assertEq(e.bond, 0);
        assertEq(service.endpointCount(), 1);
    }

    function test_addEndpoint_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        service.addEndpoint(alice, _ep(hex"01"));
    }

    function test_removeEndpoint_live_refundsPending_bumpsVersion() public {
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        service.addEndpoint(alice, _ep(hex"01"));
        uint64 vLive = service.getEndpointManifest().version;

        vm.prank(alice);
        service.removeEndpoint(alice);

        assertEq(uint256(service.getEndpointEntry(alice).status), uint256(ClprTypes.EndpointStatus.NONE));
        assertEq(service.endpointCount(), 0);
        assertEq(service.pendingWithdrawals(alice), 0.5 ether);
        assertEq(service.getEndpointManifest().version, vLive + 1);
    }

    function test_removeEndpoint_pending_cancels_noVersionBump() public {
        uint64 v0 = service.getEndpointManifest().version;
        vm.startPrank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        service.removeEndpoint(alice);
        vm.stopPrank();

        assertEq(uint256(service.getEndpointEntry(alice).status), uint256(ClprTypes.EndpointStatus.NONE));
        assertEq(service.pendingWithdrawals(alice), 0.5 ether);
        assertEq(service.getEndpointManifest().version, v0);
    }

    function test_removeEndpoint_byOwner_creditsPending() public {
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        service.addEndpoint(alice, _ep(hex"01"));

        service.removeEndpoint(alice); // owner (this test contract)

        assertEq(uint256(service.getEndpointEntry(alice).status), uint256(ClprTypes.EndpointStatus.NONE));
        assertEq(service.pendingWithdrawals(alice), 0.5 ether);
    }

    function test_removeEndpoint_unauthorized() public {
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));

        vm.prank(bob);
        vm.expectRevert(ClprTypes.ClprEndpointUnauthorized.selector);
        service.removeEndpoint(alice);
    }

    function test_removeEndpoint_revert_notRegistered() public {
        vm.expectRevert(ClprTypes.ClprEndpointNotRegistered.selector);
        service.removeEndpoint(alice);
    }

    function test_updateEndpointManifest_batchAdd_bumpsVersionOnce() public {
        vm.prank(alice);
        service.registerEndpoint{value: 0.5 ether}(_ep(hex"01"));
        uint64 v0 = service.getEndpointManifest().version;

        ClprTypes.ManifestUpdateEntry[] memory adds = new ClprTypes.ManifestUpdateEntry[](2);
        adds[0] = ClprTypes.ManifestUpdateEntry({registrantAccount: alice, endpoint: _ep(hex"FF")});
        adds[1] = ClprTypes.ManifestUpdateEntry({registrantAccount: bob, endpoint: _ep(hex"02")});
        address[] memory removes = new address[](0);
        service.updateEndpointManifest(adds, removes);

        assertEq(service.endpointCount(), 2);
        assertEq(service.getEndpointManifest().version, v0 + 1);
    }

    function test_getEndpointManifest_empty_atVersion1() public {
        ClprTypes.ClprEndpointManifest memory m = service.getEndpointManifest();
        assertEq(m.endpoints.length, 0);
        assertEq(m.version, 1);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    function _setEconomicConfig(uint256 minBond) internal {
        ClprTypes.EconomicConfig memory econ = ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: minBond,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            maxChannels: 0,
            maxConnectors: 0,
            connectorPaymentGasLimit: 200_000
        });
        service.initialize(hex"1234", defaultThrottles, "", "", econ);
        service.setClprEnabled(true);
    }
}

contract ClprService_Configuration is ClprServiceTestBase {
    function test_updateLedgerConfiguration() public {
        defaultThrottles.maxMessagePayloadBytes = 65536;

        service.updateLedgerConfiguration(
            hex"1234", // serviceAddress
            defaultThrottles,
            "", // trustAnchor
            "" // trustAnchorId
        );

        ClprTypes.LedgerConfiguration memory config = service.getLedgerConfiguration();
        assertEq(config.throttles.maxMessagesPerBundle, 100);
        assertEq(config.throttles.maxGasPerMessage, 1_000_000);
        assertTrue(config.nanosSinceEpoch > 0);
        assertEq(config.protocolVersion, 1);
        assertEq(config.chainId, "eip155:1337");
    }

    function test_updateLedgerConfiguration_revert_notOwner() public {
        ClprTypes.Throttles memory throttles = _defaultThrottles();
        vm.prank(address(0x99));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x99)));
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");
    }

    function test_updateLedgerConfiguration_revert_trustAnchorMismatch_anchorOnly() public {
        ClprTypes.Throttles memory throttles = _defaultThrottles();
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"00", throttles, hex"aabbcc", "");
    }

    function test_updateLedgerConfiguration_revert_trustAnchorMismatch_idOnly() public {
        ClprTypes.Throttles memory throttles = _defaultThrottles();
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"00", throttles, "", hex"112233");
    }

    function test_updateEconomicConfiguration_revert_quotaPct100() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 100;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateEconomicConfiguration(econ);
    }

    function test_updateEconomicConfiguration_revert_quotaPctOver100() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 150;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateEconomicConfiguration(econ);
    }

    function test_updateEconomicConfiguration_succeeds_quotaPct99() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorQueueQuotaPct = 99;
        service.updateEconomicConfiguration(econ);
    }

    /// The stipend only funds the inbound notification, so any value is the operator's call; 0 turns
    /// the notification off.
    function test_updateEconomicConfiguration_acceptsAZeroStipend() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorInboundGasStipend = 0;
        service.updateEconomicConfiguration(econ);
        assertEq(service.getEconomicConfig().connectorInboundGasStipend, 0);
    }

    /// A payment budget too small for `payForExecution` would fail every charge and slash every
    /// funded connector.
    function testFuzz_updateEconomicConfiguration_revert_paymentGasLimitBelowMinimum(uint256 seed) public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorPaymentGasLimit = uint64(bound(seed, 0, ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT - 1));
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateEconomicConfiguration(econ);
    }

    function test_updateEconomicConfiguration_succeeds_paymentGasLimitAtMinimum() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorPaymentGasLimit = uint64(ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT);
        service.updateEconomicConfiguration(econ);
        assertEq(service.getEconomicConfig().connectorPaymentGasLimit, ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT);
    }

    function test_initialize_revert_paymentGasLimitBelowMinimum() public {
        ClprService freshService = _deployClprService(1, "eip155:1337");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorPaymentGasLimit = uint64(ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT - 1);
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        freshService.initialize(hex"1234", defaultThrottles, "", "", econ);
    }

    function test_initialize_acceptsAZeroStipend() public {
        ClprService freshService = _deployClprService(1, "eip155:1337");
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.connectorInboundGasStipend = 0;
        freshService.initialize(hex"1234", defaultThrottles, "", "", econ);
        assertEq(freshService.getEconomicConfig().connectorInboundGasStipend, 0);
    }

    // ── Endpoint validation at manifest intake (was: seed endpoints) ───

    function test_addEndpoint_validIP_passes() public {
        ClprTypes.Endpoint memory ep =
            ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 8080, tlsCertificate: hex"", accountId: hex""});
        service.addEndpoint(address(0xE1), ep);
    }

    function test_addEndpoint_revert_invalidIP() public {
        ClprTypes.Endpoint memory ep =
            ClprTypes.Endpoint({ipAddress: "bad.hostname", port: 8080, tlsCertificate: hex"", accountId: hex""});
        vm.expectRevert(ClprTypes.ClprInvalidEndpointAddress.selector);
        service.addEndpoint(address(0xE1), ep);
    }

    function test_addEndpoint_revert_invalidCert() public {
        ClprTypes.Endpoint memory ep =
            ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 8080, tlsCertificate: hex"deadbeef", accountId: hex""});
        vm.expectRevert(ClprTypes.ClprInvalidEndpointCertificate.selector);
        service.addEndpoint(address(0xE1), ep);
    }

    // ── Throttle validation (validateThrottles) ───────────────────────────────

    function test_updateLedgerConfiguration_revert_zeroGasPerMessage() public {
        ClprTypes.Throttles memory t = _defaultThrottles();
        t.maxGasPerMessage = 0;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"1234", t, "", "");
    }

    function test_updateLedgerConfiguration_revert_zeroMessagesPerBundle() public {
        ClprTypes.Throttles memory t = _defaultThrottles();
        t.maxMessagesPerBundle = 0;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"1234", t, "", "");
    }

    function test_updateLedgerConfiguration_revert_zeroMessagePayloadBytes() public {
        ClprTypes.Throttles memory t = _defaultThrottles();
        t.maxMessagePayloadBytes = 0;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"1234", t, "", "");
    }

    function test_updateLedgerConfiguration_revert_zeroQueueDepth() public {
        ClprTypes.Throttles memory t = _defaultThrottles();
        t.maxQueueDepth = 0;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"1234", t, "", "");
    }

    function test_updateLedgerConfiguration_revert_zeroSyncBytes() public {
        ClprTypes.Throttles memory t = _defaultThrottles();
        t.maxSyncBytes = 0;
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.updateLedgerConfiguration(hex"1234", t, "", "");
    }
}

contract AdminLogic_KillSwitch is ClprServiceTestBase {
    // Kill switch disables all mutating operations.
    function test_killSwitch_disablesMutatingOps() public {
        // Pre-state: active channel + connector + endpoint + one message (all created while enabled).
        _setupDefaultConfig();
        _registerTestConnector();
        service.registerEndpoint{value: 0}(
            ClprTypes.Endpoint({ipAddress: "1.2.3.4", port: 1, tlsCertificate: "", accountId: hex"01"})
        );
        uint64 mid = service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");

        // Now disable.
        service.setClprEnabled(false);

        bytes memory pubKey2 = _signerPubKey();
        bytes32 cid2 = _deriveTestChannelId(pubKey2, bytes32(uint256(99)));
        bytes32 comm2 = keccak256(abi.encodePacked(cid2, pubKey2));

        // registerChannel
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerChannel(cid2, comm2);

        // completeChannel
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.completeChannel(cid2, pubKey2, new bytes(65), bytes32(0), address(verifier), hex"0001", "");

        // closeChannel
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.closeChannel(channelId);

        // sendMessage
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.sendMessage(channelId, connectorId, hex"1122334455", hex"01");

        // submitBundle
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.submitBundle(channelId, hex"00");

        // redactMessage
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.redactMessage(channelId, mid);

        // registerConnector
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerConnector(bytes32(0));

        // removeConnector
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.removeConnector(channelId, connectorId, address(this));

        // topUpConnectorStake
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.topUpConnectorStake{value: 0}(channelId, connectorId);

        // registerEndpoint
        ClprTypes.Endpoint memory ep =
            ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex"01"});
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerEndpoint{value: 0}(ep);

        // addEndpoint
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.addEndpoint(address(0xA11CE), ep);

        // removeEndpoint
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.removeEndpoint(address(0xA11CE));

        // updateLedgerConfiguration
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.updateLedgerConfiguration(hex"00", _defaultThrottles(), "", "");

        // updateEconomicConfiguration
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.updateEconomicConfiguration(_defaultEconomicConfig());
    }

    function test_killSwitch_canReEnable() public {
        service.setClprEnabled(false);

        bytes memory pubKey = _signerPubKey();
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerChannel(channelId, commitment);

        service.setClprEnabled(true);
        service.registerChannel(channelId, commitment);
        assertTrue(service.pendingCommitments(commitment));
    }

    function test_killSwitch_onlyOwner() public {
        vm.prank(address(0x99));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x99)));
        service.setClprEnabled(false);
    }
}
