// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {FeeAssetLib} from "@hiero-ledger/clpr/libraries/service/FeeAssetLib.sol";
import {MockFeeToken} from "@test/mocks/MockFeeToken.sol";
import {EthRejector} from "@test/mocks/EthRejector.sol";

/// @dev Exposes FeeAssetLib's internal functions; plays the role of ClprService (the custodian).
contract FeeAssetLibHarness {
    ClprTypes.FeeAsset public asset;

    receive() external payable {}

    function setToken(address t) external {
        asset.token = t;
    }

    function balanceOf(address account) external view returns (uint256) {
        return FeeAssetLib.balanceOf(asset, account);
    }

    function scale(address token, uint8 decimals) external pure returns (uint256 multiplier, uint256 divisor) {
        return FeeAssetLib.scale(ClprTypes.FeeAsset({token: token, decimals: decimals}));
    }

    function pullAtLeast(uint256 minAmount) external payable returns (uint256) {
        return FeeAssetLib.pullAtLeast(asset, minAmount);
    }

    function pullExact(uint256 amount) external payable {
        FeeAssetLib.pullExact(asset, amount);
    }

    function trySend(address to, uint256 amount) external returns (bool) {
        return FeeAssetLib.trySend(asset, to, amount);
    }

    function send(address to, uint256 amount) external {
        FeeAssetLib.send(asset, to, amount);
    }
}

contract FeeAssetLibTest is Test {
    FeeAssetLibHarness internal harness;
    MockFeeToken internal usd;
    address internal alice = makeAddr("alice");

    function setUp() public {
        harness = new FeeAssetLibHarness();
        usd = new MockFeeToken(6);
    }

    function _tokenMode() internal {
        harness.setToken(address(usd));
    }

    // ── balanceOf ─────────────────────────────────────────────────────

    function test_balanceOf_nativeMode_readsNativeBalance() public {
        vm.deal(alice, 3 ether);
        usd.mint(alice, 5e6);
        assertEq(harness.balanceOf(alice), 3 ether);
    }

    function test_balanceOf_tokenMode_readsTokenBalance() public {
        _tokenMode();
        vm.deal(alice, 3 ether);
        usd.mint(alice, 5e6);
        assertEq(harness.balanceOf(alice), 5e6);
    }

    // ── scale ─────────────────────────────────────────────────────────

    function test_scale_nativeMode_isOneToOne() public view {
        (uint256 multiplier, uint256 divisor) = harness.scale(address(0), 0);
        assertEq(multiplier, 1);
        assertEq(divisor, 1);
    }

    function test_scale_sixDecimals_dividesBy1e12() public view {
        (uint256 multiplier, uint256 divisor) = harness.scale(address(usd), 6);
        assertEq(multiplier, 1);
        assertEq(divisor, 1e12);
    }

    function test_scale_eighteenDecimals_isOneToOne() public view {
        (uint256 multiplier, uint256 divisor) = harness.scale(address(usd), 18);
        assertEq(multiplier, 1);
        assertEq(divisor, 1);
    }

    function test_scale_maxDecimals_multipliesBy1e77() public view {
        (uint256 multiplier, uint256 divisor) = harness.scale(address(usd), FeeAssetLib.MAX_DECIMALS);
        assertEq(multiplier, 1e77);
        assertEq(divisor, 1);
    }

    // ── pullAtLeast ───────────────────────────────────────────────────

    function test_pullAtLeast_nativeMode_takesMsgValueAndIgnoresMinAmount() public {
        assertEq(harness.pullAtLeast{value: 2 ether}(7e6), 2 ether);
        assertEq(address(harness).balance, 2 ether);
    }

    function test_pullAtLeast_tokenMode_pullsExactlyMinAmount() public {
        _tokenMode();
        usd.mint(address(this), 10e6);
        usd.approve(address(harness), 10e6);

        assertEq(harness.pullAtLeast(4e6), 4e6);
        assertEq(usd.balanceOf(address(harness)), 4e6);
        assertEq(usd.balanceOf(address(this)), 6e6);
    }

    function test_pullAtLeast_tokenMode_zeroAmountPullsNothing() public {
        _tokenMode();
        assertEq(harness.pullAtLeast(0), 0);
        assertEq(usd.balanceOf(address(harness)), 0);
    }

    function test_pullAtLeast_tokenMode_revertsOnNativeValue() public {
        _tokenMode();
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        harness.pullAtLeast{value: 1}(0);
    }

    function test_pullAtLeast_tokenMode_revertsWithoutAllowance() public {
        _tokenMode();
        usd.mint(address(this), 10e6);
        vm.expectRevert();
        harness.pullAtLeast(1e6);
    }

    function test_pullAtLeast_tokenMode_revertsWhenLessArrives() public {
        _tokenMode();
        usd.mint(address(this), 10e6);
        usd.approve(address(harness), 10e6);
        usd.setTransferFee(1);
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        harness.pullAtLeast(4e6);
    }

    // ── pullExact ─────────────────────────────────────────────────────

    function test_pullExact_nativeMode_acceptsExactValue() public {
        harness.pullExact{value: 2 ether}(2 ether);
        assertEq(address(harness).balance, 2 ether);
    }

    function test_pullExact_nativeMode_revertsOnDifferentValue() public {
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        harness.pullExact{value: 1 ether}(2 ether);
    }

    function test_pullExact_tokenMode_pullsAmount() public {
        _tokenMode();
        usd.mint(address(this), 10e6);
        usd.approve(address(harness), 10e6);

        harness.pullExact(4e6);
        assertEq(usd.balanceOf(address(harness)), 4e6);
    }

    function test_pullExact_tokenMode_revertsOnNativeValue() public {
        _tokenMode();
        vm.expectRevert(ClprTypes.ClprNativeValueMismatch.selector);
        harness.pullExact{value: 1}(1e6);
    }

    // ── trySend / send ────────────────────────────────────────────────

    function test_trySend_nativeMode_sendsValue() public {
        vm.deal(address(harness), 1 ether);
        assertTrue(harness.trySend(alice, 1 ether));
        assertEq(alice.balance, 1 ether);
    }

    function test_trySend_nativeMode_returnsFalseWhenRecipientRejects() public {
        vm.deal(address(harness), 1 ether);
        EthRejector rejector = new EthRejector();
        assertFalse(harness.trySend(address(rejector), 1 ether));
        assertEq(address(harness).balance, 1 ether);
    }

    function test_trySend_tokenMode_sendsToken() public {
        _tokenMode();
        usd.mint(address(harness), 3e6);
        assertTrue(harness.trySend(alice, 3e6));
        assertEq(usd.balanceOf(alice), 3e6);
    }

    function test_trySend_tokenMode_returnsFalseWhenTransferReverts() public {
        _tokenMode();
        usd.mint(address(harness), 3e6);
        usd.setBlocked(alice, true);
        assertFalse(harness.trySend(alice, 3e6));
        assertEq(usd.balanceOf(address(harness)), 3e6);
    }

    function test_send_revertsWithTransferFailed() public {
        _tokenMode();
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        harness.send(alice, 1e6);
    }
}
