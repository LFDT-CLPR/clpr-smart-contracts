// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {MockFeeToken} from "@test/mocks/MockFeeToken.sol";
import {ReentrantPayConnector} from "@test/mocks/ReentrantPayConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @notice A connector that answers `payForExecution` by re-entering a stake top-up must not have
///         that deposit counted as both the charge and new stake: the re-entry reverts, the charge
///         fails, and the connector is slashed.
abstract contract ChargeReentrancyBase is BundleLibTestBase {
    ReentrantPayConnector internal evil;
    bytes32 internal evilId;

    function _serviceBalance() internal view virtual returns (uint256);

    function _submitCharge() internal {
        _submitSingleInboundMessage(
            ClprProtobuf.encodeDataMessage(evilId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304")
        );
    }

    function _assertSlashedAndSolvent(uint256 stakeBefore) internal {
        uint256 stakeAfter = service.getConnector(channelId, evilId).lockedStake;
        assertEq(service.getConnector(channelId, evilId).slashCount, 1, "failed charge slashes");
        assertLt(stakeAfter, stakeBefore, "no stake credited from the re-entered top-up");
        assertEq(
            _serviceBalance(),
            stakeAfter + service.pendingWithdrawals(address(this)),
            "service holds exactly what it owes"
        );
    }
}

contract BundleLib_ChargeReentrancyNativeTest is ChargeReentrancyBase {
    function _serviceBalance() internal view override returns (uint256) {
        return address(service).balance;
    }

    function test_reenteredTopUpConnectorStake_failsCharge() public {
        evil = new ReentrantPayConnector(IClprService(address(service)), address(0));
        evilId = ConnectorRegistrar.register(
            IClprService(address(service)), channelId, keccak256("reentrant-native"), address(evil), owner, 0.5 ether
        );
        evil.arm(channelId, evilId);
        vm.deal(address(evil), 1 ether);
        vm.txGasPrice(1 gwei);
        uint256 stakeBefore = service.getConnector(channelId, evilId).lockedStake;

        _submitCharge();

        _assertSlashedAndSolvent(stakeBefore);
        assertEq(address(evil).balance, 1 ether, "connector paid nothing");
    }
}

contract BundleLib_ChargeReentrancyTokenTest is ChargeReentrancyBase {
    MockFeeToken internal usd;

    function _feeTokenForDeploy() internal override returns (address) {
        usd = new MockFeeToken(6);
        return address(usd);
    }

    function _beforeInitialize() internal override {
        defaultEcon.minLockedStake = 100e6;
        defaultEcon.basePenalty = 1e6;
        usd.mint(address(this), 1_000e6);
        usd.approve(address(service), type(uint256).max);
    }

    function _serviceBalance() internal view override returns (uint256) {
        return usd.balanceOf(address(service));
    }

    function test_reenteredTopUpConnectorStakeAmount_failsCharge() public {
        evil = new ReentrantPayConnector(IClprService(address(service)), address(usd));
        evilId = ConnectorRegistrar.registerTokenMode(
            IClprService(address(service)), channelId, keccak256("reentrant-token"), address(evil), owner
        );
        evil.arm(channelId, evilId);
        usd.mint(address(evil), 10e6);
        vm.txGasPrice(2e10);
        uint256 stakeBefore = service.getConnector(channelId, evilId).lockedStake;

        _submitCharge();

        _assertSlashedAndSolvent(stakeBefore);
        assertEq(usd.balanceOf(address(evil)), 10e6, "connector paid nothing");
    }
}
