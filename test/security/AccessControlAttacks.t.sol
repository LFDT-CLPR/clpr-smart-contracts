// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {SecurityTestBase} from "@test/security/SecurityTestBase.sol";

/// @notice Attacks on the service's privileged operations: who may call them, what they may
///         reach, and which values they must never move.
contract AccessControlAttacksTest is SecurityTestBase {
    /// Every owner-gated router entry point rejects an unprivileged caller.
    ///
    /// One call per `onlyOwner` function on `ClprService`, each asserted against the exact
    /// `OwnableUnauthorizedAccount(attacker)` payload. The loop keeps the row and the test
    /// one-to-one while still naming the offending function on failure.
    function test_X1_ownerOnlyEntryPoints_rejectNonOwner() public {
        ClprTypes.Throttles memory throttles = defaultThrottles;
        ClprTypes.ManifestUpdateEntry[] memory adds = new ClprTypes.ManifestUpdateEntry[](0);
        address[] memory removals = new address[](0);

        string[8] memory labels = [
            "closeChannel",
            "redactMessage",
            "setClprEnabled",
            "initialize",
            "updateLedgerConfiguration",
            "updateEconomicConfiguration",
            "addEndpoint",
            "updateEndpointManifest"
        ];

        bytes[8] memory calls = [
            abi.encodeCall(service.closeChannel, (channelId)),
            abi.encodeCall(service.redactMessage, (channelId, 1)),
            abi.encodeCall(service.setClprEnabled, (false)),
            abi.encodeCall(service.initialize, (hex"1234", throttles, "", "", defaultEcon)),
            abi.encodeCall(service.updateLedgerConfiguration, (hex"1234", throttles, "", "")),
            abi.encodeCall(service.updateEconomicConfiguration, (defaultEcon)),
            abi.encodeCall(service.addEndpoint, (attacker, _peerEndpointSeedEntry())),
            abi.encodeCall(service.updateEndpointManifest, (adds, removals))
        ];

        bytes memory expected = abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", attacker);

        for (uint256 i = 0; i < calls.length; i++) {
            vm.prank(attacker);
            (bool ok, bytes memory ret) = address(service).call(calls[i]);
            assertFalse(ok, string.concat(labels[i], ": should have reverted for a non-owner"));
            assertEq(ret, expected, string.concat(labels[i], ": wrong revert reason"));
        }

        // None of the rejected calls took effect. There is no getter for the enabled flag, so
        // the kill switch is probed through a `whenEnabled`-gated owner call: it would revert
        // ClprDisabled had the attacker's setClprEnabled(false) landed.
        service.updateEconomicConfiguration(defaultEcon);
    }

    /// The owner check runs before any state or argument validation.
    ///
    /// `initialize` would revert `ClprAlreadyInitialized` for the owner at this point, so a
    /// non-owner seeing `OwnableUnauthorizedAccount` proves the gate is reached first and does
    /// not leak whether the service was already initialized.
    function test_X1_ownerCheck_precedesStateValidation() public {
        vm.prank(attacker);
        _expectOwnableRevert(attacker);
        service.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);

        // Sanity: for the owner the same call fails on the one-shot latch instead.
        vm.expectRevert(ClprTypes.ClprAlreadyInitialized.selector);
        service.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);
    }

    /// Only a connector's own admin may deregister it and reclaim its stake.
    ///
    /// The owner has no override, so the attacker cannot reach the stake by any route.
    function test_X4_nonAdmin_cannotDeregisterConnector() public {
        _registerTestConnector();

        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprConnectorUnauthorized.selector);
        service.removeConnector(channelId, connectorId, attacker);

        // The connector is untouched and its stake is still held by the service.
        assertEq(service.connectorCount(), 1, "connector must survive the attack");
    }

    /// A caller may only withdraw its own pending balance.
    ///
    /// `collectPending` takes no arguments and reads `_pendingWithdrawals[msg.sender]`, so there
    /// is no `withdraw(to, amount)` to abuse and no owner sweep. Seeding a victim's balance and
    /// attacking from another account must leave it intact.
    function test_X7_attacker_cannotCollectAnotherAccountsBalance() public {
        address victim = makeAddr("victim");
        uint256 amount = 0.05 ether;

        // _pendingWithdrawals is at storage slot 11 (storage-layout.json).
        vm.store(address(service), keccak256(abi.encode(victim, uint256(11))), bytes32(amount));
        vm.deal(address(service), amount);

        uint256 attackerBalanceBefore = attacker.balance;

        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprNothingToCollect.selector);
        service.collectPending();

        // The owner has no privileged path to it either.
        vm.expectRevert(ClprTypes.ClprNothingToCollect.selector);
        service.collectPending();

        assertEq(attacker.balance, attackerBalanceBefore, "attacker must gain nothing");
        assertEq(service.pendingWithdrawals(victim), amount, "victim's balance must be intact");

        // And the victim can still collect it.
        vm.prank(victim);
        service.collectPending();
        assertEq(victim.balance, amount, "victim must receive its own balance");
    }

    /// `protocolVersion` and `chainId` survive an owner configuration update.
    ///
    /// Both are written once in the `ClprService` constructor and are not `immutable`; their
    /// constancy rests on no code path rewriting them. A config update rewrites five sibling
    /// fields of the same struct, which is the realistic way they would be lost.
    function test_X12_configUpdate_doesNotMutateProtocolVersionOrChainId() public {
        ClprTypes.LedgerConfiguration memory before = service.getLedgerConfiguration();
        assertEq(before.protocolVersion, 1, "precondition: constructor set protocolVersion");
        assertEq(before.chainId, "eip155:1337", "precondition: constructor set chainId");

        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxQueueDepth = 7;
        service.updateLedgerConfiguration(hex"BEEF", throttles, hex"AA", hex"BB");

        ClprTypes.LedgerConfiguration memory current = service.getLedgerConfiguration();
        assertEq(current.protocolVersion, before.protocolVersion, "protocolVersion must not change");
        assertEq(current.chainId, before.chainId, "chainId must not change");
        // The update did land, so the assertions above are not vacuous.
        assertEq(current.throttles.maxQueueDepth, 7, "throttle update should have applied");
        assertEq(current.serviceAddress, hex"BEEF", "serviceAddress update should have applied");
    }

    receive() external payable {}
}
