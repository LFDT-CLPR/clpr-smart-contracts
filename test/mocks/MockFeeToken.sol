// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice ERC-20 fee token for token-mode tests, with configurable decimals. `setBlocked` makes
///         transfers to or from an account revert, like a token with a transfer blocklist.
///         `setTransferFee` burns a fixed amount from every transfer, like a fee-on-transfer token.
contract MockFeeToken is ERC20 {
    uint8 private immutable _DECIMALS;
    mapping(address => bool) public blocked;
    uint256 public transferFee;

    constructor(uint8 decimals_) ERC20("Mock USD", "mUSD") {
        _DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setBlocked(address account, bool isBlocked) external {
        blocked[account] = isBlocked;
    }

    function setTransferFee(uint256 fee) external {
        transferFee = fee;
    }

    function _update(address from, address to, uint256 value) internal override {
        require(!blocked[from] && !blocked[to], "transfer policy");
        if (transferFee != 0 && from != address(0) && to != address(0)) {
            super._update(from, address(0), transferFee);
            value -= transferFee;
        }
        super._update(from, to, value);
    }
}
