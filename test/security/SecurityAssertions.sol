// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Assertions shared by every attacker-framed suite in `test/security/`.
/// @dev Kept separate from a test base so suites can pair it with whichever domain base they
///      need — `SecurityTestBase` for the service-level rows, `BundleLogicTestBase` for the
///      bundle rows, which owns the mock-verifier and payload helpers.
abstract contract SecurityAssertions is Test {
    /// @dev `Panic(uint256)`. A bare `vm.expectRevert()` is satisfied by this, which is why
    ///      hostile-input rows assert through {_assertRevertsWith} instead.
    bytes4 internal constant PANIC_SELECTOR = 0x4e487b71;

    /// @dev The unprivileged caller the access-control rows attack with. Deliberately not
    ///      `owner`, not a registered connector, and not a registered endpoint.
    address internal constant attacker = address(0xA77ACC);

    /// @dev Assert the next call reverts with OpenZeppelin's `OwnableUnauthorizedAccount(caller)`.
    ///      Asserting the selector *and* its argument is the point: a bare `vm.expectRevert()`
    ///      passes on any revert, including one that never reached the owner check.
    function _expectOwnableRevert(address caller) internal {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
    }

    /// @dev Call `target` with `callData` as `caller` and assert it reverted with exactly
    ///      `expectedError`, without using `vm.expectRevert`.
    ///
    ///      Needed because `vm.expectRevert(selector)` cannot distinguish a guard firing from
    ///      a Solidity `Panic` raised earlier on hostile input — the same reason
    ///      `ClprVerifierComplianceTest._assertBundleRejectedWithoutPanic` drops to a
    ///      low-level call. Use this wherever a Panic could masquerade as a pass.
    function _assertRevertsWith(address caller, address target, bytes memory callData, bytes memory expectedError)
        internal
    {
        vm.prank(caller);
        (bool ok, bytes memory ret) = target.call(callData);
        assertFalse(ok, "call should have reverted");
        assertGe(ret.length, 4, "revert carried no error data");
        assertTrue(_selectorOf(ret) != PANIC_SELECTOR, "reverted with a Solidity Panic, not a named error");
        assertEq(ret, expectedError, "wrong revert reason");
    }

    /// @dev First four bytes of returndata, or `0x0` when there are fewer than four.
    function _selectorOf(bytes memory ret) internal pure returns (bytes4 selector) {
        if (ret.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(ret, 0x20))
        }
    }
}
