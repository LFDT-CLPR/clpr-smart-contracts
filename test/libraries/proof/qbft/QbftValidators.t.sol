// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";

contract QbftValidatorsTest is Test {
    /// @dev quorum must equal Besu's ceil(2N/3) for every N. If not, the contract rejects valid blocks.
    function test_quorum_matchesBesuCeil() public pure {
        assertEq(QbftValidators.quorum(1), 1);
        assertEq(QbftValidators.quorum(2), 2);
        assertEq(QbftValidators.quorum(3), 2);
        assertEq(QbftValidators.quorum(4), 3);
        assertEq(QbftValidators.quorum(5), 4);
        assertEq(QbftValidators.quorum(6), 4);
        assertEq(QbftValidators.quorum(7), 5);
        assertEq(QbftValidators.quorum(10), 7);
        assertEq(QbftValidators.quorum(21), 14);
    }

    /// @dev quorum(n) equals ceil(2n/3) for any n.
    function testFuzz_quorum_isCeilTwoThirds(uint16 n) public pure {
        uint256 q = QbftValidators.quorum(n);
        uint256 expected = (2 * uint256(n) + 2) / 3;
        assertEq(q, expected, "quorum must be ceil(2n/3)");
        if (n > 0) {
            assertLe(q, n, "quorum never exceeds N");
            // ceil(2n/3) is at least two-thirds. It equals two-thirds when n is a multiple of 3.
            assertGe(3 * q, 2 * uint256(n), "quorum must be at least two-thirds");
        }
    }

    function test_commit_isDeterministic() public pure {
        ValidatorSet memory a = _set(address(0x1), address(0x2), address(0x3));
        ValidatorSet memory b = _set(address(0x1), address(0x2), address(0x3));
        assertEq(QbftValidators.commit(a), QbftValidators.commit(b), "equal sets commit equal");
    }

    function test_commit_dependsOnOrder() public pure {
        // The commitment depends on order. This shows the sorted-ascending rule.
        ValidatorSet memory sorted = _set(address(0x1), address(0x2), address(0x3));
        ValidatorSet memory shuffled = _set(address(0x2), address(0x1), address(0x3));
        assertTrue(QbftValidators.commit(sorted) != QbftValidators.commit(shuffled), "order matters");
    }

    function test_commit_dependsOnMembership() public pure {
        ValidatorSet memory two = _set2(address(0x1), address(0x2));
        ValidatorSet memory three = _set(address(0x1), address(0x2), address(0x3));
        assertTrue(QbftValidators.commit(two) != QbftValidators.commit(three), "different members differ");
    }

    function _set(address x, address y, address z) private pure returns (ValidatorSet memory s) {
        s.members = new address[](3);
        s.members[0] = x;
        s.members[1] = y;
        s.members[2] = z;
    }

    function _set2(address x, address y) private pure returns (ValidatorSet memory s) {
        s.members = new address[](2);
        s.members[0] = x;
        s.members[1] = y;
    }
}
