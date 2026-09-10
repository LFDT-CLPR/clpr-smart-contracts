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

    /// @dev sortInPlace must agree with sortedDedup on every input: same ascending order, and the
    ///      returned distinct count equals the deduped length.
    function testFuzz_sortInPlace_matchesSortedDedup(address[] memory input, uint8 dupMask) public pure {
        vm.assume(input.length <= 64);
        // Plant duplicates so the distinct count is exercised.
        for (uint256 i = 1; i < input.length; i++) {
            if ((dupMask >> (i % 8)) & 1 == 1) input[i] = input[i - 1];
        }
        address[] memory a = _copy(input);
        address[] memory b = _copy(input);

        uint256 distinct = QbftValidators.sortInPlace(a);
        address[] memory deduped = QbftValidators.sortedDedup(b);

        assertEq(distinct, deduped.length, "distinct count");
        assertEq(a.length, input.length, "sorted in place, same length");
        for (uint256 i = 1; i < a.length; i++) {
            assertTrue(uint160(a[i - 1]) <= uint160(a[i]), "ascending");
        }
        if (distinct == a.length) {
            for (uint256 i = 0; i < a.length; i++) {
                assertEq(a[i], deduped[i], "no duplicates: identical to sortedDedup");
            }
        }
    }

    function test_sortInPlace_edges() public pure {
        address[] memory empty = new address[](0);
        assertEq(QbftValidators.sortInPlace(empty), 0);

        address[] memory one = new address[](1);
        one[0] = address(0x5);
        assertEq(QbftValidators.sortInPlace(one), 1);

        address[] memory dups = new address[](3);
        dups[0] = address(0x7);
        dups[1] = address(0x7);
        dups[2] = address(0x7);
        assertEq(QbftValidators.sortInPlace(dups), 1);

        address[] memory rev = new address[](4);
        rev[0] = address(0x4);
        rev[1] = address(0x3);
        rev[2] = address(0x2);
        rev[3] = address(0x1);
        assertEq(QbftValidators.sortInPlace(rev), 4);
        assertEq(rev[0], address(0x1));
        assertEq(rev[3], address(0x4));
    }

    function _copy(address[] memory a) private pure returns (address[] memory b) {
        b = new address[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
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
