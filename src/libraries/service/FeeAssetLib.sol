// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title FeeAssetLib
/// @notice Moves the service's fee asset: native value when `token == address(0)`, otherwise the
///         configured ERC-20 (`ClprTypes.FeeAsset.token`). Runs in ClprService's context, so
///         `address(this)` is the custodian.
library FeeAssetLib {
    using SafeERC20 for IERC20;

    /// @dev Largest fee-token `decimals()` the ClprService constructor accepts. `scale` computes
    ///      10^(decimals - 18), and 10^77 is the largest power of ten that fits in a uint256.
    uint8 internal constant MAX_DECIMALS = 18 + 77;

    function balanceOf(ClprTypes.FeeAsset memory asset, address account) internal view returns (uint256) {
        return asset.token == address(0) ? account.balance : IERC20(asset.token).balanceOf(account);
    }

    /// @dev An 18-decimal gas cost × `multiplier` / `divisor` is in fee-asset units; one of the two is 1.
    function scale(ClprTypes.FeeAsset memory asset) internal pure returns (uint256 multiplier, uint256 divisor) {
        uint256 decimals = asset.token == address(0) ? 18 : asset.decimals;
        return decimals > 18 ? (10 ** (decimals - 18), uint256(1)) : (uint256(1), 10 ** (18 - decimals));
    }

    /// @dev Takes a stake or bond of at least `minAmount` from `msg.sender` and returns the amount
    ///      received. Native mode returns `msg.value` unchecked against `minAmount`, so the caller
    ///      enforces the minimum. Token mode pulls exactly `minAmount` (see `pullExact`).
    // Can be slither disabled because every caller is a payable logic-module entry point.
    // slither-disable-next-line msg-value-in-nonpayable
    function pullAtLeast(ClprTypes.FeeAsset memory asset, uint256 minAmount) internal returns (uint256 amount) {
        if (asset.token == address(0)) return msg.value;
        pullExact(asset, minAmount);
        return minAmount;
    }

    /// @dev Takes exactly `amount` from `msg.sender`. Native mode reverts with ClprNativeValueMismatch
    ///      unless `msg.value == amount`. Token mode requires `msg.value == 0` and reverts with
    ///      ClprTransferFailed unless the service's balance grows by exactly `amount`, which rejects
    ///      fee-on-transfer tokens.
    // slither-disable-next-line msg-value-in-nonpayable
    function pullExact(ClprTypes.FeeAsset memory asset, uint256 amount) internal {
        if (asset.token == address(0)) {
            if (msg.value != amount) revert ClprTypes.ClprNativeValueMismatch();
            return;
        }
        if (msg.value != 0) revert ClprTypes.ClprNativeValueMismatch();
        if (amount == 0) return;
        IERC20 token = IERC20(asset.token);
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        if (token.balanceOf(address(this)) != before + amount) revert ClprTypes.ClprTransferFailed();
    }

    function trySend(ClprTypes.FeeAsset memory asset, address to, uint256 amount) internal returns (bool ok) {
        if (asset.token == address(0)) {
            (ok,) = to.call{value: amount}("");
        } else {
            ok = IERC20(asset.token).trySafeTransfer(to, amount);
        }
    }

    function send(ClprTypes.FeeAsset memory asset, address to, uint256 amount) internal {
        if (!trySend(asset, to, amount)) revert ClprTypes.ClprTransferFailed();
    }
}
