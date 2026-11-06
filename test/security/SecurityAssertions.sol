// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Assertions shared by every attacker-framed suite in `test/security/`.
/// @dev Kept separate from a test base so suites can pair it with whichever domain base they
///      need — `SecurityTestBase` for the service-level rows, `BundleLogicTestBase` for the
///      bundle rows, which owns the mock-verifier and payload helpers.
///
///      Reverts are asserted with `vm.prank` + `vm.expectRevert(selector)`, matching the rest of
///      the repo. One caveat worth knowing: `vm.expectRevert` attaches to the next external call,
///      so if evaluating an argument makes one — building a proof that calls a precompile, say —
///      the expectation is consumed by the wrong call and the test reports "did not revert as
///      expected" while the code under test reverted correctly. Hoist such arguments into locals
///      before the cheatcode.
abstract contract SecurityAssertions is Test {
    /// @dev The unprivileged caller the access-control rows attack with. Deliberately not
    ///      `owner`, not a registered connector, and not a registered endpoint.
    address internal constant attacker = address(0xA77ACC);

    /// @dev Assert the next call reverts with OpenZeppelin's `OwnableUnauthorizedAccount(caller)`.
    ///      Asserting the selector *and* its argument is the point: a bare `vm.expectRevert()`
    ///      passes on any revert, including one that never reached the owner check.
    function _expectOwnableRevert(address caller) internal {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
    }

    /// @dev First four bytes of returndata, or `0x0` when there are fewer than four.
    function _selectorOf(bytes memory ret) internal pure returns (bytes4 selector) {
        if (ret.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(ret, 0x20))
        }
    }
}
