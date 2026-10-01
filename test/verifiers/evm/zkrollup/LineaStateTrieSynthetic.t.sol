// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ZkRollupTestBase} from "./ZkRollupLive.t.sol";
import {LineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/LineaStateTrieVerifier.sol";
import {ILineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/lib/ILineaStateTrieVerifier.sol";

/// @notice LineaStateTrieVerifier on SYNTHETIC storage tries where the channel slots are present (values
///         made up, trie construction as on Linea mainnet). Inputs: `fixtures/linea-synthetic.json`, written
///         by `npx tsx test/e2e/relay/buildLineaSyntheticFixture.ts`. These give the L2-storage cost of a
///         bundle from a real ClprService, which the live fixture's stand-in cannot show.
contract LineaStateTrieSyntheticTest is ZkRollupTestBase {
    string internal json;
    LineaStateTrieVerifier internal trie;

    function setUp() public {
        json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/zkrollup/fixtures/linea-synthetic.json"));
        trie = new LineaStateTrieVerifier(_deployPoseidon2());
    }

    function _run(string memory name) internal view returns (bytes32[] memory slots, bytes32[] memory values) {
        bytes memory proof = vm.parseJsonBytes(json, string.concat(".cases.", name, ".proof"));
        bytes32 root = vm.parseJsonBytes32(json, string.concat(".cases.", name, ".storageRoot"));
        uint256 g = gasleft();
        (slots, values) = trie.verifyStorage(proof, root);
        console.log(string.concat("verifyStorage gas (synthetic ", name, ")"), g - gasleft());
        console.log("  proof bytes", proof.length);
    }

    function test_fresh_sixPresentSlots() public view {
        (bytes32[] memory slots, bytes32[] memory values) = _run("fresh");
        assertEq(slots.length, 6);
        assertEq(uint64(uint256(values[0]) >> 168), vm.parseJsonUint(json, ".nextMessageId"));
        assertEq(uint256(values[4]), 1);
        assertTrue(values[5] != bytes32(0));
    }

    function test_busy_messageSlotFarAway() public view {
        (bytes32[] memory slots,) = _run("busy");
        assertEq(slots.length, 6);
    }

    function test_partial_twoAbsentSlots() public view {
        (bytes32[] memory slots, bytes32[] memory values) = _run("partial");
        assertEq(slots.length, 5);
        assertEq(values[3], bytes32(0));
        assertEq(values[4], bytes32(0));
        assertTrue(values[0] != bytes32(0));
    }

    function test_rejectsWrongValue() public {
        bytes memory proof = vm.parseJsonBytes(json, ".cases.fresh.proof");
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            abi.decode(proof, (ILineaStateTrieVerifier.MultiProof, ILineaStateTrieVerifier.SlotClaim[]));
        claims[1].value += 1;
        vm.expectRevert(
            abi.encodeWithSelector(LineaStateTrieVerifier.SlotValueMismatch.selector, bytes32(claims[1].slot))
        );
        trie.verifyStorage(abi.encode(mp, claims), vm.parseJsonBytes32(json, ".cases.fresh.storageRoot"));
    }

    function test_rejectsLeafIndexOutOfRange() public {
        bytes memory proof = vm.parseJsonBytes(json, ".cases.busy.proof");
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            abi.decode(proof, (ILineaStateTrieVerifier.MultiProof, ILineaStateTrieVerifier.SlotClaim[]));
        uint256 last = mp.leaves.length - 1;
        mp.leaves[last].index += 1 << 40; // same low 40 bits: would fold identically without the range check
        vm.expectRevert(
            abi.encodeWithSelector(LineaStateTrieVerifier.LeafIndexOutOfRange.selector, mp.leaves[last].index)
        );
        trie.verifyStorage(abi.encode(mp, claims), vm.parseJsonBytes32(json, ".cases.busy.storageRoot"));
    }
}
