// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";

contract QuorumHarness {
    function trustLinkRequired(uint256 n, bool fullQuorum) external pure returns (uint256) {
        return ClprQbftQuorum.trustLinkRequired(n, fullQuorum);
    }

    function verifyRotationStep(address[] memory listed, address[] memory trusted, bytes memory header) external pure {
        ClprQbftQuorum.verifyRotationStep(
            ValidatorSet({members: QbftValidators.sortedDedup(listed)}),
            ValidatorSet({members: QbftValidators.sortedDedup(trusted)}),
            ClprQbftSeal.decodeHeader(RLP.decodeList(header))
        );
    }
}

contract ClprQbftQuorumTest is QbftContractProofs {
    QuorumHarness internal h;

    function setUp() public {
        h = new QuorumHarness();
    }

    function _members(string memory seed, uint256 n) internal pure returns (address[] memory s) {
        s = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = vm.addr(uint256(keccak256(abi.encodePacked(seed, i))));
        }
    }

    function _pks(string memory seed, uint256[] memory idx) internal pure returns (uint256[] memory p) {
        p = new uint256[](idx.length);
        for (uint256 i = 0; i < idx.length; i++) {
            p[i] = uint256(keccak256(abi.encodePacked(seed, idx[i])));
        }
    }

    function _idx(uint256 a) internal pure returns (uint256[] memory i) {
        i = new uint256[](1);
        i[0] = a;
    }

    function _idx(uint256 a, uint256 b) internal pure returns (uint256[] memory i) {
        i = new uint256[](2);
        i[0] = a;
        i[1] = b;
    }

    function _idx(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory i) {
        i = new uint256[](3);
        i[0] = a;
        i[1] = b;
        i[2] = c;
    }

    /// @dev The table from qbft-header-mode.md §2: quorum - 1, at least 1; the full quorum when asked.
    function test_trustLinkRequired_table() public view {
        uint256[6] memory sizes = [uint256(1), 2, 3, 4, 7, 10];
        uint256[6] memory minusOne = [uint256(1), 1, 1, 2, 4, 6];
        uint256[6] memory full = [uint256(1), 2, 2, 3, 5, 7];
        for (uint256 i = 0; i < sizes.length; i++) {
            assertEq(h.trustLinkRequired(sizes[i], false), minusOne[i], "quorum - 1");
            assertEq(h.trustLinkRequired(sizes[i], true), full[i], "full quorum");
        }
    }

    function testFuzz_trustLinkRequired_bounds(uint8 n) public view {
        vm.assume(n > 0);
        uint256 minusOne = h.trustLinkRequired(n, false);
        assertGe(minusOne, 1, "never below one signer");
        assertLe(minusOne, QbftValidators.quorum(n), "never above a quorum");
        assertEq(h.trustLinkRequired(n, true), QbftValidators.quorum(n));
    }

    // ── no change ────────────────────────────────────────────────────────────

    function test_sameSet_quorumOfIt() public {
        address[] memory set = _members("s", 3);
        h.verifyRotationStep(set, set, _buildListedSealedHeader(1, bytes32(0), set, _pks("s", _idx(0, 1))));
        bytes memory oneSeal = _buildListedSealedHeader(1, bytes32(0), set, _pks("s", _idx(0)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 1, 2));
        h.verifyRotationStep(set, set, oneSeal);
    }

    // ── one member added ─────────────────────────────────────────────────────

    /// @dev {a, b} -> {a, b, c} sealed by a and c: quorum(2) - 1 = 1 old signer, and the newcomer
    ///      signed. This is the block Besu produces when c joins.
    function test_addition_oneOldSignerAndNewcomer_accepted() public view {
        address[] memory old = _members("add", 2);
        address[] memory grown = _members("add", 3);
        h.verifyRotationStep(grown, old, _buildListedSealedHeader(1, bytes32(0), grown, _pks("add", _idx(0, 2))));
    }

    /// @dev {a, b, c} -> {a, b, c, d} sealed by a only: one old signer would do with d's seal, but
    ///      d is silent, so the full old quorum (2) is required.
    function test_addition_newcomerSilent_needsFullOldQuorum() public {
        address[] memory old = _members("silent", 3);
        address[] memory grown = _members("silent", 4);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), grown, _pks("silent", _idx(0)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TrustLinkNotReached.selector, 1, 2));
        h.verifyRotationStep(grown, old, header);
        // With the full old quorum the newcomer's seal is not needed (a, b, c = quorum(4) as well).
        h.verifyRotationStep(grown, old, _buildListedSealedHeader(1, bytes32(0), grown, _pks("silent", _idx(0, 1, 2))));
    }

    /// @dev {a, b, c} -> {a, b, c, d} sealed by a and d: the old side passes (1 = quorum - 1 with d
    ///      signing) but the new list needs quorum(4) = 3.
    function test_addition_listedQuorumNotReached() public {
        address[] memory old = _members("lq", 3);
        address[] memory grown = _members("lq", 4);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), grown, _pks("lq", _idx(0, 3)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 2, 3));
        h.verifyRotationStep(grown, old, header);
    }

    /// @dev {a} -> {a, b}: quorum(1) - 1 would be 0; the floor keeps one old signer required.
    function test_addition_fromSingleValidator_needsTheOldOne() public {
        address[] memory old = _members("one", 1);
        address[] memory grown = _members("one", 2);
        h.verifyRotationStep(grown, old, _buildListedSealedHeader(1, bytes32(0), grown, _pks("one", _idx(0, 1))));
        bytes memory onlyNew = _buildListedSealedHeader(1, bytes32(0), grown, _pks("one", _idx(1)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TrustLinkNotReached.selector, 0, 1));
        h.verifyRotationStep(grown, old, onlyNew);
    }

    // ── one member removed ───────────────────────────────────────────────────

    /// @dev {a, b, c, d} -> {a, b, c} sealed by a and b: 2 = quorum(4) - 1 old signers, and a
    ///      quorum of the new list.
    function test_removal_quorumMinusOne_accepted() public view {
        address[] memory old = _members("rm", 4);
        address[] memory shrunk = _members("rm", 3);
        h.verifyRotationStep(shrunk, old, _buildListedSealedHeader(1, bytes32(0), shrunk, _pks("rm", _idx(0, 1))));
    }

    /// @dev {a, b, c} -> {a, b} sealed by a only: the old side passes (1 = quorum(3) - 1), the new
    ///      list does not (quorum(2) = 2).
    function test_removal_listedQuorumNotReached() public {
        address[] memory old = _members("rm2", 3);
        address[] memory shrunk = _members("rm2", 2);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), shrunk, _pks("rm2", _idx(0)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 1, 2));
        h.verifyRotationStep(shrunk, old, header);
    }

    /// @dev A header sealed only by an outsider: no trusted signer at all.
    function test_removal_noTrustedSigner_reverts() public {
        address[] memory old = _members("out", 3);
        address[] memory shrunk = _members("out", 2);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), shrunk, _pks("stranger", _idx(0)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TrustLinkNotReached.selector, 0, 1));
        h.verifyRotationStep(shrunk, old, header);
    }

    // ── more than one change ─────────────────────────────────────────────────

    function test_twoChanges_reverts() public {
        address[] memory old = _members("two", 2);
        address[] memory next = new address[](3);
        next[0] = old[0];
        next[1] = vm.addr(uint256(keccak256("c")));
        next[2] = vm.addr(uint256(keccak256("d")));
        uint256[] memory sealers = new uint256[](3);
        sealers[0] = uint256(keccak256(abi.encodePacked("two", uint256(0))));
        sealers[1] = uint256(keccak256("c"));
        sealers[2] = uint256(keccak256("d"));
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), next, sealers);
        // Two added, one removed: rejected before any seal is recovered.
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TooManySetChanges.selector, 2, 1));
        h.verifyRotationStep(next, old, header);
    }

    function test_swap_reverts() public {
        address[] memory old = _members("swap", 3);
        address[] memory next = _members("swap", 3);
        next[2] = vm.addr(uint256(keccak256("replacement")));
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), next, _pks("swap", _idx(0, 1)));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TooManySetChanges.selector, 1, 1));
        h.verifyRotationStep(next, old, header);
    }

    /// @dev A legitimate one-member addition sealed the way Besu seals it — a quorum of the new list
    ///      that includes the newcomer — is always accepted, for any set size.
    function testFuzz_addition_sealedByQuorumWithNewcomer_accepted(uint8 nRaw) public view {
        uint256 n = bound(uint256(nRaw), 1, 24);
        address[] memory old = _members("fz", n);
        address[] memory grown = _members("fz", n + 1);
        uint256 q = QbftValidators.quorum(n + 1);
        uint256[] memory idx = new uint256[](q);
        idx[0] = n; // the newcomer
        for (uint256 i = 1; i < q; i++) {
            idx[i] = i - 1;
        }
        h.verifyRotationStep(grown, old, _buildListedSealedHeader(1, bytes32(0), grown, _pks("fz", idx)));
    }

    /// @dev A legitimate one-member removal sealed by a quorum of the remaining list is always accepted.
    function testFuzz_removal_sealedByQuorumOfRest_accepted(uint8 nRaw) public view {
        uint256 n = bound(uint256(nRaw), 2, 25);
        address[] memory old = _members("fr", n);
        address[] memory shrunk = _members("fr", n - 1);
        uint256 q = QbftValidators.quorum(n - 1);
        uint256[] memory idx = new uint256[](q);
        for (uint256 i = 0; i < q; i++) {
            idx[i] = i;
        }
        h.verifyRotationStep(shrunk, old, _buildListedSealedHeader(1, bytes32(0), shrunk, _pks("fr", idx)));
    }

    // ── shapes ───────────────────────────────────────────────────────────────

    function test_emptySets_revert() public {
        address[] memory one = new address[](1);
        one[0] = address(1);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), one, new uint256[](0));
        vm.expectRevert(ClprQbftQuorum.EmptyValidatorSet.selector);
        h.verifyRotationStep(new address[](0), one, header);
        vm.expectRevert(ClprQbftQuorum.EmptyValidatorSet.selector);
        h.verifyRotationStep(one, new address[](0), header);
        vm.expectRevert(ClprQbftQuorum.EmptySeals.selector);
        h.verifyRotationStep(one, one, header);
    }

    function test_noSeals_onChange_reverts() public {
        address[] memory old = _members("ns", 2);
        address[] memory grown = _members("ns", 3);
        bytes memory header = _buildListedSealedHeader(1, bytes32(0), grown, new uint256[](0));
        vm.expectRevert(ClprQbftQuorum.EmptySeals.selector);
        h.verifyRotationStep(grown, old, header);
    }
}
