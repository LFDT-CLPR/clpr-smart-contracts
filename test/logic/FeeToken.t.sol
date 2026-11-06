// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {FeeAssetLib} from "@hiero-ledger/clpr/libraries/service/FeeAssetLib.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprServiceStorageSlots} from "@test/helpers/ClprServiceStorageSlots.sol";
import {MockFeeToken} from "@test/mocks/MockFeeToken.sol";
import {EthRejector} from "@test/mocks/EthRejector.sol";

/// @notice A service running in token mode with USD amounts: a 6-decimal fee token,
///         100 USD connector stake, 10 USD endpoint bond, 1 USD base penalty.
abstract contract FeeTokenModeBase is ClprTestBase {
    MockFeeToken internal usd;

    function _feeTokenForDeploy() internal virtual override returns (address) {
        usd = new MockFeeToken(6);
        return address(usd);
    }

    function _beforeInitialize() internal virtual override {
        defaultEcon.minLockedStake = 100e6;
        defaultEcon.minEndpointBond = 10e6;
        defaultEcon.basePenalty = 1e6;
        usd.mint(address(this), 1_000e6);
        usd.approve(address(service), type(uint256).max);
    }

    function _registerTokenConnector(bytes32 seed) internal returns (bytes32) {
        return ConnectorRegistrar.registerTokenMode(
            IClprService(address(service)), channelId, seed, address(connector), owner
        );
    }
}

contract FeeTokenModeTest is FeeTokenModeBase {
    function _endpoint() internal pure returns (ClprTypes.Endpoint memory) {
        return ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex""});
    }

    /// @dev Commit phase plus the reveal signature, leaving completeConnector to the test.
    function _commitConnector(bytes32 seed) internal returns (bytes32 id, bytes memory pubKey, bytes memory sig) {
        uint256 pk = uint256(keccak256(abi.encodePacked("fee-token.connector", seed)));
        Vm.Wallet memory w = vm.createWallet(pk);
        pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        id = service.deriveConnectorId(channelId, pubKey, bytes32(0));
        service.registerConnector(keccak256(abi.encodePacked(id, pubKey)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _ethSignedHash(keccak256(abi.encodePacked(id, address(service)))));
        sig = abi.encodePacked(r, s, v);
    }

    function test_getFeeToken_returnsConfiguredToken() public {
        assertEq(service.getFeeToken(), address(usd));
    }

    function test_receive_revertsOnNativeValue() public {
        (bool ok, bytes memory ret) = address(service).call{value: 1}("");
        assertFalse(ok, "token mode rejects native value");
        assertEq(ret, abi.encodeWithSelector(ClprTypes.ClprNativeValueMismatch.selector));
    }

    /// @notice The fee token is fixed at construction: the service has no function that changes it.
    function test_feeToken_hasNoSetter() public {
        (bool ok,) = address(service).call(abi.encodeWithSignature("setFeeToken(address)", address(0)));
        assertFalse(ok, "no setFeeToken on the service");
        assertEq(service.getFeeToken(), address(usd));
    }

    // ── Connector stake ───────────────────────────────────────────────

    function test_completeConnector_pullsMinLockedStake() public {
        uint256 before = usd.balanceOf(address(this));
        bytes32 id = _registerTokenConnector("c1");

        assertEq(service.getConnector(channelId, id).lockedStake, 100e6);
        assertEq(usd.balanceOf(address(service)), 100e6);
        assertEq(before - usd.balanceOf(address(this)), 100e6);
    }

    function test_completeConnector_revertsOnNativeValue() public {
        (bytes32 id, bytes memory pubKey, bytes memory sig) = _commitConnector("c1");
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        service.completeConnector{value: 1}(id, pubKey, sig, bytes32(0), channelId, address(connector), owner);
    }

    function test_completeConnector_revertsWithoutAllowance() public {
        (bytes32 id, bytes memory pubKey, bytes memory sig) = _commitConnector("c1");
        usd.approve(address(service), 0);
        vm.expectRevert();
        service.completeConnector(id, pubKey, sig, bytes32(0), channelId, address(connector), owner);
    }

    function test_completeConnector_revertsForFeeOnTransferToken() public {
        (bytes32 id, bytes memory pubKey, bytes memory sig) = _commitConnector("c1");
        usd.setTransferFee(1);
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        service.completeConnector(id, pubKey, sig, bytes32(0), channelId, address(connector), owner);
    }

    function test_topUpConnectorStake_pullsAmount() public {
        bytes32 id = _registerTokenConnector("c1");
        service.topUpConnectorStake(channelId, id, 25e6);

        assertEq(service.getConnector(channelId, id).lockedStake, 125e6);
        assertEq(usd.balanceOf(address(service)), 125e6);
    }

    function test_topUpConnectorStake_revertsOnNativeValue() public {
        bytes32 id = _registerTokenConnector("c1");
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        service.topUpConnectorStake{value: 25e6}(channelId, id, 25e6);
    }

    function test_removeConnector_returnsStakeInToken() public {
        bytes32 id = _registerTokenConnector("c1");
        address recipient = makeAddr("recipient");
        service.removeConnector(channelId, id, recipient);

        assertEq(usd.balanceOf(recipient), 100e6);
        assertEq(usd.balanceOf(address(service)), 0);
    }

    function test_removeConnector_revertsWhenTokenTransferFails() public {
        bytes32 id = _registerTokenConnector("c1");
        address recipient = makeAddr("recipient");
        usd.setBlocked(recipient, true);
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        service.removeConnector(channelId, id, recipient);
    }

    // ── Endpoint bond ─────────────────────────────────────────────────

    function test_registerEndpoint_pullsMinBond_andRefundsThroughCollectPending() public {
        address ep = makeAddr("endpoint");
        usd.mint(ep, 10e6);

        vm.startPrank(ep);
        usd.approve(address(service), 10e6);
        service.registerEndpoint(_endpoint());
        assertEq(service.getEndpointEntry(ep).bond, 10e6);
        assertEq(usd.balanceOf(ep), 0);

        service.removeEndpoint(ep);
        assertEq(service.pendingWithdrawals(ep), 10e6);
        service.collectPending();
        vm.stopPrank();

        assertEq(usd.balanceOf(ep), 10e6);
        assertEq(usd.balanceOf(address(service)), 0);
    }

    function test_collectPendingTo_paysAnotherAddress_whenTheTokenBlocksTheCreditedAccount() public {
        address ep = makeAddr("endpoint");
        address rescue = makeAddr("rescue");
        usd.mint(ep, 10e6);
        vm.startPrank(ep);
        usd.approve(address(service), 10e6);
        service.registerEndpoint(_endpoint());
        service.removeEndpoint(ep);
        vm.stopPrank();
        usd.setBlocked(ep, true);

        vm.prank(ep);
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        service.collectPending();

        vm.prank(ep);
        service.collectPendingTo(rescue);
        assertEq(usd.balanceOf(rescue), 10e6);
        assertEq(service.pendingWithdrawals(ep), 0);
    }

    function test_collectPendingTo_revertsOnZeroRecipient() public {
        vm.expectRevert(ClprTypes.ClprZeroRecipient.selector);
        service.collectPendingTo(address(0));
    }

    function test_collectPendingTo_revertsWithNothingToCollect() public {
        vm.expectRevert(ClprTypes.ClprNothingToCollect.selector);
        service.collectPendingTo(makeAddr("rescue"));
    }

    function test_registerEndpoint_revertsOnNativeValue() public {
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        service.registerEndpoint{value: 1}(_endpoint());
    }
}

/// @notice The default native mode: `topUpConnectorStake` takes `msg.value`.
contract FeeTokenNativeModeTest is ClprTestBase {
    function test_getFeeToken_isNativeByDefault() public {
        assertEq(service.getFeeToken(), address(0));
    }

    function test_topUpConnectorStake_nativeMode_addsMatchingValue() public {
        _registerTestConnector();
        service.topUpConnectorStake{value: 0.2 ether}(channelId, connectorId, 0.2 ether);
        assertEq(service.getConnector(channelId, connectorId).lockedStake, 0.7 ether);
    }

    function test_topUpConnectorStake_nativeMode_revertsOnValueMismatch() public {
        _registerTestConnector();
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        service.topUpConnectorStake{value: 0.1 ether}(channelId, connectorId, 0.2 ether);
    }

    function test_topUpConnectorStake_revertsOnZeroAmount() public {
        _registerTestConnector();
        vm.expectRevert(ClprTypes.ClprInsufficientStake.selector);
        service.topUpConnectorStake(channelId, connectorId, 0);
    }
}

/// @notice The fee token is a ClprService constructor argument.
contract FeeTokenConstructorTest is Test {
    function _deploy(address feeToken) internal returns (ClprService) {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        return new ClprService(
            address(this),
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            feeToken
        );
    }

    function _storedFeeAsset(ClprService service) internal view returns (address token, uint256 decimals) {
        uint256 packed = uint256(vm.load(address(service), bytes32(ClprServiceStorageSlots.FEE_ASSET)));
        // forge-lint: disable-next-line(unsafe-typecast)
        return (address(uint160(packed)), uint8(packed >> 160));
    }

    function test_constructor_sixDecimalToken_storesTokenAndDecimals() public {
        MockFeeToken usd = new MockFeeToken(6);
        ClprService service = _deploy(address(usd));

        (address token, uint256 decimals) = _storedFeeAsset(service);
        assertEq(token, address(usd));
        assertEq(decimals, 6);
        assertEq(service.getFeeToken(), address(usd));
    }

    function test_constructor_acceptsMoreThanEighteenDecimals() public {
        ClprService service = _deploy(address(new MockFeeToken(24)));
        (, uint256 decimals) = _storedFeeAsset(service);
        assertEq(decimals, 24);
    }

    function test_constructor_acceptsMaxDecimals() public {
        ClprService service = _deploy(address(new MockFeeToken(FeeAssetLib.MAX_DECIMALS)));
        (, uint256 decimals) = _storedFeeAsset(service);
        assertEq(decimals, FeeAssetLib.MAX_DECIMALS);
    }

    function test_constructor_revertsAboveMaxDecimals() public {
        MockFeeToken token = new MockFeeToken(FeeAssetLib.MAX_DECIMALS + 1);
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprTypes.ClprInvalidFeeToken.selector);
        new ClprService(
            address(this),
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(token)
        );
    }

    function test_constructor_zeroAddress_isNativeValue() public {
        ClprService service = _deploy(address(0));
        (address token, uint256 decimals) = _storedFeeAsset(service);
        assertEq(token, address(0));
        assertEq(decimals, 0);
        assertEq(service.getFeeToken(), address(0));
    }

    function test_constructor_revertsWhenDecimalsUnreadable() public {
        address eoa = makeAddr("eoa");
        address noDecimals = address(new EthRejector());
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprTypes.ClprInvalidFeeToken.selector);
        new ClprService(
            address(this),
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            eoa
        );

        vm.expectRevert(ClprTypes.ClprInvalidFeeToken.selector);
        new ClprService(
            address(this),
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            noDecimals
        );
    }
}
