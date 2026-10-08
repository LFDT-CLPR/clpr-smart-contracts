// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ChannelLogic} from "@hiero-ledger/clpr/logic/ChannelLogic.sol";
import {LogicModuleBase} from "@hiero-ledger/clpr/logic/base/LogicModuleBase.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";

/// @title LogicModuleBase Tests
/// @notice Tests for the abstract base contract authorization pattern.
contract LogicModuleBaseTest is Test {
    ChannelLogic internal channelLogic;
    ClprService internal service;

    function setUp() public {
        service = ClprDeployHelper.deployServiceForTests(address(this));
        // Content doesn't matter for these tests — just needs to satisfy initialize()
        // so setClprEnabled(true) doesn't revert with ClprNotInitialized.
        service.initialize(
            hex"1234",
            ClprTypes.Throttles({
                maxMessagesPerBundle: 100,
                maxMessagePayloadBytes: 1024,
                maxGasPerMessage: 1_000_000,
                maxQueueDepth: 1000,
                maxSyncBytes: 1_048_576,
                maxLocalEndpoints: 0,
                maxPeerEndpoints: 0
            }),
            "",
            "",
            ClprTypes.EconomicConfig({
                messageExecutionCost: 0,
                endpointMarginPercent: 0,
                minLockedStake: 0,
                minEndpointBond: 0,
                basePenalty: 0,
                penaltyMultiplier: 0,
                slashBanThreshold: 0,
                connectorQueueQuotaPct: 50,
                connectorInboundGasStipend: 500_000,
                maxChannels: 0,
                maxConnectors: 0,
                connectorPaymentGasLimit: 200_000
            })
        );
        service.setClprEnabled(true);
        ClprDeployHelper.Modules memory modules = ClprDeployHelper.deployModules();
        channelLogic = ChannelLogic(modules.channelLogic);
    }

    /// @notice Test that onlyService modifier reverts when called from non-ClprService address.
    /// @dev Directly calls ChannelLogic (not via delegatecall) to trigger UnauthorizedCaller.
    /// This covers the uncovered revert branch in LogicModuleBase.onlyService().
    function test_onlyService_revert_unauthorizedCaller() public {
        address attacker = address(0x1234);

        vm.prank(attacker);
        vm.expectRevert(LogicModuleBase.UnauthorizedCaller.selector);
        channelLogic.registerChannel(bytes32(0), bytes32(0));
    }

    /// @notice Test that onlyService modifier allows authorized ClprService address.
    /// @dev Tests the success path where address(this) == _authorizedService.
    /// This covers line 33 in LogicModuleBase: the implicit continue (no revert) branch.
    function test_onlyService_success_whenAuthorized() public {
        // The success branch (no revert) is triggered when address(this) == _authorizedService
        // In the delegatecall context from ClprService:
        // - address(this) resolves to ClprService (the caller's address)
        // - _authorizedService is set to ClprService during initialization
        // - Condition: address(this) != _authorizedService is FALSE
        // - Therefore: no revert, success path is taken (implicit continue at line 33)

        // We verify this by calling registerChannel (a protected function) through ClprService
        // If the success branch wasn't taken, it would revert with UnauthorizedCaller
        bytes32 testChannelId = keccak256(abi.encodePacked("test", uint256(1)));
        bytes32 testCommitment = keccak256(abi.encodePacked("commitment", uint256(1)));

        // This call goes through ClprService.registerChannel, which delegatecalls
        // ChannelLogic.registerChannel, making address(this) == ClprService
        // The onlyService() modifier checks pass (success branch taken)
        service.registerChannel(testChannelId, testCommitment);

        // Verify the channel was registered (proof the function executed)
        assertTrue(service.pendingCommitments(testCommitment), "commitment should be pending");
    }
}
