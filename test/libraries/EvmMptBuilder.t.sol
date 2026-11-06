// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EvmMptBuilder} from "@test/helpers/EvmMptBuilder.sol";
import {MptWalk} from "@test/helpers/MptWalk.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Unit tests for the test-only trie builder.
contract EvmMptBuilderTest is Test {
    using Memory for bytes;

    EvmMptBuilder internal trie;

    function setUp() public {
        trie = new EvmMptBuilder();
    }

    /// @dev The value shape a storage leaf carries: RLP(scalar), wrapped once more by the leaf.
    function _slotValue(uint256 v) internal pure returns (bytes memory) {
        return RLP.encode(v);
    }

    function _nodes(bytes32 key) internal view returns (Memory.Slice) {
        return trie.proofRlp(key).asSlice();
    }

    // ── Inclusion ───────────────────────────────────────────────────────────

    function test_singleKey_inclusion() public {
        bytes32[] memory keys = new bytes32[](1);
        bytes[] memory vals = new bytes[](1);
        keys[0] = keccak256("k0");
        vals[0] = _slotValue(42);

        bytes32 root = trie.build(keys, vals);
        assertEq(trie.proofDepth(keys[0]), 1, "lone key is the root leaf");

        bytes memory got = MptWalk.verifyInclusion(root, keys[0], _nodes(keys[0]));
        assertEq(RLP.decodeUint256(RLP.decodeBytes(got)), 42);
    }

    /// @dev The case the single-leaf shortcut in QbftSyntheticProofs cannot express: two distinct
    ///      non-zero values under one root, each proven by its own node list.
    function test_twoKeys_bothProvenUnderOneRoot() public {
        bytes32[] memory keys = new bytes32[](2);
        bytes[] memory vals = new bytes[](2);
        keys[0] = keccak256("alpha");
        keys[1] = keccak256("beta");
        vals[0] = _slotValue(7);
        vals[1] = _slotValue(type(uint256).max);

        bytes32 root = trie.build(keys, vals);

        assertEq(RLP.decodeUint256(RLP.decodeBytes(MptWalk.verifyInclusion(root, keys[0], _nodes(keys[0])))), 7);
        assertEq(
            RLP.decodeUint256(RLP.decodeBytes(MptWalk.verifyInclusion(root, keys[1], _nodes(keys[1])))),
            type(uint256).max
        );
    }

    function test_manyKeys_allProven() public {
        uint256 n = 40;
        bytes32[] memory keys = new bytes32[](n);
        bytes[] memory vals = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = keccak256(abi.encodePacked("key", i));
            vals[i] = _slotValue(i + 1);
        }
        bytes32 root = trie.build(keys, vals);

        for (uint256 i = 0; i < n; i++) {
            bytes memory got = MptWalk.verifyInclusion(root, keys[i], _nodes(keys[i]));
            assertEq(RLP.decodeUint256(RLP.decodeBytes(got)), i + 1, "value round-trips");
        }
    }

    // ── Exclusion ───────────────────────────────────────────────────────────

    function test_absentKey_provenAbsent() public {
        bytes32[] memory keys = new bytes32[](3);
        bytes[] memory vals = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = keccak256(abi.encodePacked("present", i));
            vals[i] = _slotValue(i + 1);
        }
        bytes32 root = trie.build(keys, vals);

        bytes32 missing = keccak256("absent");
        // Resolve the proof BEFORE arming expectRevert: `proofRlp` is itself an external call, and
        // vm.expectRevert applies to the very next one.
        bytes memory proofRlp = trie.proofRlp(missing);
        assertEq(MptWalk.getOrEmpty(root, missing, proofRlp.asSlice()).length, 0, "absent slot reads as empty");
        // The strict walker must reject what the lenient one tolerates.
        vm.expectRevert();
        this.verifyInclusionExt(root, missing, proofRlp);
    }

    function verifyInclusionExt(bytes32 root, bytes32 key, bytes memory proofRlp) external pure {
        MptWalk.verifyInclusion(root, key, proofRlp.asSlice());
    }

    // ── Depth control ───────────────────────────────────────────────────────

    /// @dev Depth is the whole point of the builder: MPT walk gas is proportional to it, so the
    ///      padding helpers must hit the requested depth exactly, not approximately.
    function test_padKeysPresent_forcesExactDepth() public {
        uint256 depth = 8;
        bytes32 target = keccak256("target");
        bytes32[] memory pad = trie.padKeysPresent(target, depth);

        bytes32[] memory keys = new bytes32[](depth + 1);
        bytes[] memory vals = new bytes[](depth + 1);
        keys[0] = target;
        vals[0] = _slotValue(0xDEAD);
        for (uint256 i = 0; i < depth; i++) {
            keys[i + 1] = pad[i];
            vals[i + 1] = _slotValue(i + 1);
        }

        bytes32 root = trie.build(keys, vals);
        assertEq(trie.proofDepth(target), depth + 1, "depth branches + leaf");

        bytes memory got = MptWalk.verifyInclusion(root, target, _nodes(target));
        assertEq(RLP.decodeUint256(RLP.decodeBytes(got)), 0xDEAD);
    }

    function test_padKeysAbsent_forcesExactDepth() public {
        uint256 depth = 6;
        bytes32 target = keccak256("ghost");
        bytes32[] memory pad = trie.padKeysAbsent(target, depth);

        bytes[] memory vals = new bytes[](depth);
        for (uint256 i = 0; i < depth; i++) {
            vals[i] = _slotValue(i + 1);
        }

        bytes32 root = trie.build(pad, vals);
        assertEq(trie.proofDepth(target), depth + 1, "target never inserted, path still deep");
        assertEq(MptWalk.getOrEmpty(root, target, _nodes(target)).length, 0, "reads as zero");
    }

    /// @dev Deeper proof ⇒ strictly more gas. This is the relationship the gas report leans on when
    ///      it reports MPT cost at a mainnet-shaped depth rather than at a toy trie's depth.
    function test_deeperProofCostsMoreGas() public {
        assertGt(_inclusionGasAtDepth(8), _inclusionGasAtDepth(1), "gas grows with depth");
    }

    function _inclusionGasAtDepth(uint256 depth) internal returns (uint256 gasUsed) {
        EvmMptBuilder t = new EvmMptBuilder();
        bytes32 target = keccak256("measured");
        bytes32[] memory pad = t.padKeysPresent(target, depth);

        bytes32[] memory keys = new bytes32[](depth + 1);
        bytes[] memory vals = new bytes[](depth + 1);
        keys[0] = target;
        vals[0] = _slotValue(1);
        for (uint256 i = 0; i < depth; i++) {
            keys[i + 1] = pad[i];
            vals[i + 1] = _slotValue(i + 2);
        }
        bytes32 root = t.build(keys, vals);
        assertEq(t.proof(target).length, depth + 1, "requested depth achieved");
        Memory.Slice proofItem = t.proofRlp(target).asSlice();

        uint256 g0 = gasleft();
        MptWalk.verifyInclusion(root, target, proofItem);
        gasUsed = g0 - gasleft();
    }
}
