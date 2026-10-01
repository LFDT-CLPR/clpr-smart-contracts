// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BeefyLib} from "@hiero-ledger/clpr/libraries/proof/substrate/BeefyLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {SubstrateTrieHarness} from "./SubstrateTrieHarness.sol";

/// @notice Unit tests of the Substrate proof libraries (BLAKE2b, SCALE, trie, header digest, BEEFY)
///         against reference vectors and the synthetic fixture (fixtures/synthetic.json, built by
///         test/e2e/relay/buildSubstrateSyntheticFixture.ts with an independent TS trie encoder).
contract SubstrateLibsTest is Test {
    SubstrateTrieHarness internal h;
    string internal json;

    bytes16 internal constant EVM = 0x1da53b775b270400e7e61ed5cbc5a146;
    bytes16 internal constant ACCOUNT_STORAGES = 0xab1160471b1418779239ba8e2b847e42;

    function setUp() public {
        h = new SubstrateTrieHarness();
        json = vm.readFile("test/verifiers/evm/grandpa/fixtures/synthetic.json");
    }

    // ── BLAKE2b (EIP-152 precompile) ─────────────────────────────────────────

    function _seq(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) {
            b[i] = bytes1(uint8(i));
        }
    }

    function test_blake2b256_vectors() public view {
        assertEq(h.blake2b256(""), 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8);
        assertEq(h.blake2b256("abc"), 0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319);
        // Block boundaries: exactly one block, one byte over, two full blocks.
        assertEq(h.blake2b256(_seq(128)), 0xc3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1);
        assertEq(h.blake2b256(_seq(129)), 0xf7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9);
        assertEq(h.blake2b256(_seq(256)), 0x39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835);
    }

    function test_blake2b128_vectors() public view {
        assertEq(h.blake2b128(""), bytes16(0xcae66941d9efbd404e4d88758ea67670));
        assertEq(
            h.blake2b128(abi.encodePacked(address(0x6647dcbeb030dc8E227D8B1A2Cb6A49F3C887E3c))),
            bytes16(0x01c05232e68d9964235c2c85e67c706d)
        );
    }

    // ── SCALE ────────────────────────────────────────────────────────────────

    function test_compact_roundTrip() public view {
        uint256[6] memory vs = [uint256(0), 63, 64, 16383, 16384, (1 << 30) - 1];
        for (uint256 i; i < vs.length; ++i) {
            bytes memory enc = h.encodeCompact(vs[i]);
            (uint256 v, uint256 next) = h.readCompact(enc);
            assertEq(v, vs[i]);
            assertEq(next, enc.length);
        }
    }

    function test_compact_rejectsNonCanonical() public {
        vm.expectRevert(ScaleCodec.ScaleCompactNonCanonical.selector);
        h.readCompact(hex"0500"); // 1 in two-byte mode
    }

    function test_compact_rejectsBigMode() public {
        vm.expectRevert(ScaleCodec.ScaleCompactTooLarge.selector);
        h.readCompact(hex"0300000040");
    }

    // ── Trie ─────────────────────────────────────────────────────────────────

    function _key(address a, bytes32 slot) internal view returns (bytes memory) {
        return abi.encodePacked(
            EVM, ACCOUNT_STORAGES, h.blake2b128(abi.encodePacked(a)), a, h.blake2b128(abi.encodePacked(slot)), slot
        );
    }

    function test_trie_readsEveryServiceSlot() public view {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.root");
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        address service = vm.parseJsonAddress(json, ".service");
        bytes32[] memory slots = vm.parseJsonBytes32Array(json, ".evm.slotNumbers");
        bytes32[] memory values = vm.parseJsonBytes32Array(json, ".evm.slotValues");
        for (uint256 i; i < slots.length; ++i) {
            (bool exists, bytes memory v) = h.get(root, nodes, _key(service, slots[i]));
            assertTrue(exists);
            assertEq(bytes32(v), values[i]);
        }
    }

    function test_trie_inlineNodesBranchValueAndHashedValue() public view {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.root");
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        (bool e1, bytes memory v1) = h.get(root, nodes, hex"01"); // branch with value
        (bool e2, bytes memory v2) = h.get(root, nodes, hex"0102"); // inline leaf
        (bool e3, bytes memory v3) = h.get(root, nodes, bytes("long-value-key")); // hashed value node
        assertTrue(e1 && e2 && e3);
        assertEq(v1, hex"07");
        assertEq(v2, hex"08");
        assertEq(v3.length, 40);
    }

    function test_trie_absentKeys() public view {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.root");
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        address service = vm.parseJsonAddress(json, ".service");
        (bool e1,) = h.get(root, nodes, _key(service, bytes32(uint256(12345))));
        (bool e2,) = h.get(root, nodes, hex"0104"); // missing child of the 0x01 branch
        (bool e3,) = h.get(root, nodes, hex"01020304"); // runs past a leaf
        (bool e4,) = h.get(root, nodes, hex""); // empty key: root branch has no value
        assertFalse(e1 || e2 || e3 || e4);
    }

    function test_trie_revertsOnMissingNode() public {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.root");
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        bytes[] memory onlyRoot = new bytes[](1);
        onlyRoot[0] = nodes[nodes.length - 1];
        bytes memory key = _key(vm.parseJsonAddress(json, ".service"), bytes32(uint256(25)));
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        h.get(root, onlyRoot, key);
    }

    function test_trie_revertsOnWrongRoot() public {
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        h.get(keccak256("not the root"), nodes, hex"01");
    }

    function test_trie_tamperedNodeIsNotFound() public {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.root");
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        bytes memory r = nodes[nodes.length - 1];
        r[r.length - 1] ^= 0x01;
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        h.get(root, nodes, hex"01");
    }

    // ── Header digest ────────────────────────────────────────────────────────

    function test_header_scheduledChange() public view {
        (bool present, bytes memory auth, uint32 delay) =
            h.grandpaChange(vm.parseJsonBytes(json, ".grandpa.b140.header"));
        assertTrue(present);
        assertEq(delay, 2);
        assertEq(auth, vm.parseJsonBytes(json, ".grandpa.authorities.set2"));
        (present,,) = h.grandpaChange(vm.parseJsonBytes(json, ".grandpa.b100.header"));
        assertFalse(present);
    }

    function test_header_forcedChangeReverts() public {
        bytes memory b150 = vm.parseJsonBytes(json, ".grandpa.b150.header");
        vm.expectRevert(SubstrateHeader.ForcedChangeUnsupported.selector);
        h.grandpaChange(b150);
    }

    function test_header_trailingBytesRejected() public {
        bytes memory b = abi.encodePacked(vm.parseJsonBytes(json, ".grandpa.b100.header"), hex"00");
        vm.expectRevert(SubstrateHeader.InvalidHeader.selector);
        h.headerStateRoot(b);
    }

    function test_header_unknownDigestItemRejected() public {
        bytes memory b = vm.parseJsonBytes(json, ".grandpa.b100.header");
        // First digest item kind byte sits right after parent(32) ‖ compact(100)=2 bytes ‖ 2 roots ‖ count(1).
        b[32 + 2 + 64 + 1] = 0x07;
        vm.expectRevert(SubstrateHeader.InvalidDigestItem.selector);
        h.headerStateRoot(b);
    }

    function test_header_shortTrailingConsensusItem() public view {
        // parent ‖ Compact(5) ‖ state ‖ extrinsics ‖ [Consensus("FRNK", [0x03])] — a 1-byte log at the very end.
        bytes memory hdr = abi.encodePacked(
            bytes32(uint256(1)), hex"14", bytes32(uint256(2)), bytes32(uint256(3)), hex"0404", "FRNK", hex"0403"
        );
        (bytes32 root, uint32 number) = h.headerStateRoot(hdr);
        assertEq(root, bytes32(uint256(2)));
        assertEq(number, 5);
        (bool present,,) = h.grandpaChange(hdr);
        assertFalse(present);
    }

    // ── BEEFY ────────────────────────────────────────────────────────────────

    function test_beefy_keysetRoot() public view {
        assertEq(
            h.keysetRoot(vm.parseJsonBytes(json, ".beefy.addresses.set10")),
            vm.parseJsonBytes32(json, ".beefy.sets.set10.root")
        );
        // Odd sizes promote the last node: 3 leaves → H(H(l0‖l1)‖l2).
        bytes memory three = abi.encodePacked(address(1), address(2), address(3));
        bytes32 l0 = keccak256(abi.encodePacked(address(1)));
        bytes32 l1 = keccak256(abi.encodePacked(address(2)));
        bytes32 l2 = keccak256(abi.encodePacked(address(3)));
        assertEq(h.keysetRoot(three), keccak256(abi.encodePacked(keccak256(abi.encodePacked(l0, l1)), l2)));
        assertEq(h.keysetRoot(abi.encodePacked(address(1))), l0);
    }

    function test_beefy_mmrLeafInsideMountain() public view {
        h.verifyMmrLeaf(
            vm.parseJsonBytes32(json, ".beefy.mmrInner.root"),
            vm.parseJsonBytes(json, ".beefy.mmrInner.leaf"),
            vm.parseJsonBytes32Array(json, ".beefy.mmrInner.path"),
            vm.parseJsonUint(json, ".beefy.mmrInner.sides")
        );
    }

    function test_beefy_mmrWrongSidesRejected() public {
        bytes32 root = vm.parseJsonBytes32(json, ".beefy.mmrInner.root");
        bytes memory leaf = vm.parseJsonBytes(json, ".beefy.mmrInner.leaf");
        bytes32[] memory path = vm.parseJsonBytes32Array(json, ".beefy.mmrInner.path");
        uint256 sides = vm.parseJsonUint(json, ".beefy.mmrInner.sides");
        vm.expectRevert(BeefyLib.MmrProofMismatch.selector);
        h.verifyMmrLeaf(root, leaf, path, sides ^ 1);
    }

    function test_beefy_commitmentDecode() public view {
        BeefyLib.Commitment memory c = h.decodeCommitment(vm.parseJsonBytes(json, ".beefy.commitA.commitment"));
        assertEq(c.blockNumber, 206);
        assertEq(c.validatorSetId, 10);
    }

    function test_beefy_commitmentWithoutMmrRootRejected() public {
        // payload [("xx", 32 bytes)] ‖ block ‖ set id
        bytes memory c = abi.encodePacked(hex"04", "xx", hex"80", bytes32(0), hex"01000000", hex"0100000000000000");
        vm.expectRevert(BeefyLib.MissingMmrRoot.selector);
        h.decodeCommitment(c);
    }
}
