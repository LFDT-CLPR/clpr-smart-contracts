// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";

/// @notice A connector that reenters the service from inside its authorization callback.
/// @dev Exists because `MockClprConnector` wraps the inner failure in its own `require` string,
///      which makes the reentrancy guard's `ReentrancyGuardReentrantCall` selector unobservable.
///      This attacker **bubbles the raw revert data**, so a test can assert the exact error the
///      guard raised rather than accepting any revert.
///
///      Deliberately lives in `test/security/` rather than `test/mocks/`: it is an attack tool for
///      one row of `docs/security-test-matrix.md` (M7), not shared scaffolding, and changing the
///      shared mock would ripple through unrelated suites.
contract ReentrantConnector is IClprConnector {
    /// @dev Call made on reentry. Set to attack; left empty to behave.
    address private _target;
    bytes private _payload;

    /// @dev Raw revert data captured from the reentrant call, for tests that want to inspect it
    ///      rather than have it bubble.
    bytes public lastInnerRevert;

    /// @dev When true the reentrant call's revert is swallowed and only recorded, so the outer
    ///      call can be observed succeeding or failing on its own terms.
    bool private _swallow;

    function arm(address target, bytes calldata payload, bool swallow) external {
        _target = target;
        _payload = payload;
        _swallow = swallow;
    }

    function authorizeOutboundMessage(bytes32, bytes calldata, bytes calldata, bytes calldata)
        external
        override
        returns (bool)
    {
        if (_target != address(0)) {
            address target = _target;
            bytes memory payload = _payload;
            // One shot: without this the reentry recurses until it runs out of gas, which would
            // mask the guard with an out-of-gas instead of its own error.
            _target = address(0);

            (bool ok, bytes memory ret) = target.call(payload);
            if (!ok) {
                lastInnerRevert = ret;
                if (!_swallow) {
                    // Bubble the inner revert verbatim so the caller sees the guard's own error.
                    assembly ("memory-safe") {
                        revert(add(ret, 0x20), mload(ret))
                    }
                }
            }
        }
        return true;
    }

    function payForExecution(uint256 amount) external override {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay failed");
    }

    function onInboundMessage(bytes32, uint64, bytes calldata, bytes calldata, bytes calldata) external override {}

    receive() external payable {}
}
