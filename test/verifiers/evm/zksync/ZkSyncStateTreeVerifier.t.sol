// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ZkSyncStateTreeVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/ZkSyncStateTreeVerifier.sol";
import {IZkSyncStateTreeVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/lib/IZkSyncStateTreeVerifier.sol";
import {Blake2sHarness} from "@test/verifiers/evm/zksync/Blake2sHarness.sol";

/// @notice Blake2s known answers and ZKsync state-tree proofs: zksync-era's reference root, synthetic
///         multi-leaf trees (inclusion and exclusion), a live ZKsync Sepolia proof, and every rejection.
contract ZkSyncStateTreeVerifierTest is Test {
    struct Entry {
        address account;
        bytes32 key;
        string name;
        uint256 pathLen;
        bytes proof;
        bytes32 value;
    }

    ZkSyncStateTreeVerifier internal tree;
    Blake2sHarness internal blake;
    string internal json;
    bytes32 internal root;
    Entry[] internal entries;

    function setUp() public {
        tree = new ZkSyncStateTreeVerifier();
        blake = new Blake2sHarness();
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/zksync/fixtures/synthetic.json"));
        root = vm.parseJsonBytes32(json, ".l2.root");
        Entry[] memory all = abi.decode(vm.parseJson(json, ".entries"), (Entry[]));
        for (uint256 i = 0; i < all.length; i++) {
            entries.push(all[i]);
        }
    }

    function _one(address account, bytes32 key) internal pure returns (address[] memory a, bytes32[] memory k) {
        a = new address[](1);
        k = new bytes32[](1);
        a[0] = account;
        k[0] = key;
    }

    function _verifyOne(Entry memory e, bytes32 r) internal view returns (bytes32) {
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        return tree.verifyStorage(r, a, k, e.proof)[0];
    }

    // ── Blake2s known answers (vectors from @noble/hashes blake2s) ──────────────

    function test_blake2s_64ByteVectors() public view {
        assertEq(
            blake.hash64(
                0xee32df451e888917fb94359433e3609c07d1954e54853d885151dea20dcc77ec,
                0x0c4bc756126225501d940571fa2fa44b89cca6a545a15e28a103f886bbc047ba
            ),
            0xdceadb86d480e1f9580ac9ed4a70ca3bbacd1794b99a5b2f9c11b4c5dec9ca98
        );
        assertEq(
            blake.hash64(
                0x494892456ce06264771e954c89a5e0f824d07bb656906ce043ec34f00a292e56,
                0x0873a3e78f0e7d7c46d91eb8c63cb07bf52906b97bfc5a52b9189574c55b3a9e
            ),
            0xe0bfad73a46a5c0e33fb807d2a026818025c720209c8eeebfcb849c5aabc1f49
        );
        assertEq(blake.hash64(0, 0), 0xae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3);
    }

    function test_blake2s_40ByteVectors() public view {
        assertEq(
            blake.hash40(
                0x9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b,
                0x2d711642b726b044000000000000000000000000000000000000000000000000
            ),
            0x22399170204ffb27881253afba0812bf2ef6c2469508c797d6492d2539731100
        );
        // The empty leaf of the ZKsync tree.
        assertEq(blake.hash40(0, 0), 0x94bb15542026f4f607416f019dffe21bb39bbb32cc92085ab615660a6b5fbef4);
    }

    function test_blake2s_gasPerCompression() public view {
        (, uint256 g1) = blake.chain(bytes32(uint256(1)), 1);
        (, uint256 g257) = blake.chain(bytes32(uint256(1)), 257);
        console.log("Blake2s 64-byte compression (lane form), gas each:", (g257 - g1) / 256);
    }

    // ── Reference root (zksync-era merkle_tree tests, compute_tree_hash_works_correctly) ──

    /// One entry: address 0x4b3a…f7b2, key 0, leaf index 1, value 0x01…01. Every sibling is an empty
    /// subtree, so the proof has no path and the whole empty-subtree table is exercised.
    function test_referenceRoot_fromZkSyncEra() public view {
        bytes32 expected = 0x7f00a6b2eede960857703c8cb9e96f28b910e6693412cea4b006f24239b681e0;
        (address[] memory a, bytes32[] memory k) = _one(0x4B3aF74f66Ab1F0da3f2E4eC7A3cb99bAF1AF7B2, 0);
        bytes memory proof = abi.encodePacked(bytes32(type(uint256).max / 255), uint64(1), uint16(0));
        bytes32[] memory v = tree.verifyStorage(expected, a, k, proof);
        assertEq(v[0], bytes32(type(uint256).max / 255));
    }

    // ── Synthetic trees ────────────────────────────────────────────────────────

    function test_synthetic_inclusionAndExclusion() public view {
        for (uint256 i = 0; i < entries.length; i++) {
            assertEq(_verifyOne(entries[i], root), entries[i].value, entries[i].name);
        }
        assertEq(entries[2].value, bytes32(0), "absent slot proves zero");
    }

    function test_synthetic_batchOfEntries() public view {
        address[] memory a = new address[](entries.length);
        bytes32[] memory k = new bytes32[](entries.length);
        bytes memory proof;
        for (uint256 i = 0; i < entries.length; i++) {
            a[i] = entries[i].account;
            k[i] = entries[i].key;
            proof = bytes.concat(proof, entries[i].proof);
        }
        uint256 g = gasleft();
        bytes32[] memory v = tree.verifyStorage(root, a, k, proof);
        console.log("verifyStorage, 3 entries, gas:", g - gasleft());
        for (uint256 i = 0; i < entries.length; i++) {
            assertEq(v[i], entries[i].value);
        }
    }

    function test_gasPerSlot() public view {
        Entry memory e = entries[1];
        uint256 g = gasleft();
        _verifyOne(e, root);
        console.log("verifyStorage, 1 entry (external call incl.), gas:", g - gasleft());
    }

    // ── Rejections ─────────────────────────────────────────────────────────────

    function _expectRejected(Entry memory e, bytes32 r, bytes memory err) internal {
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        vm.expectRevert(err);
        tree.verifyStorage(r, a, k, e.proof);
    }

    function _mismatch() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IZkSyncStateTreeVerifier.StorageProofRootMismatch.selector, 0);
    }

    function test_rejectsWrongValue() public {
        Entry memory e = entries[1];
        e.proof[31] = bytes1(uint8(e.proof[31]) ^ 1);
        _expectRejected(e, root, _mismatch());
    }

    function test_rejectsWrongLeafIndex() public {
        Entry memory e = entries[0];
        e.proof[39] = bytes1(uint8(e.proof[39]) ^ 1);
        _expectRejected(e, root, _mismatch());
    }

    function test_rejectsTamperedSibling() public {
        Entry memory e = entries[1];
        e.proof[42 + 5] = bytes1(uint8(e.proof[42 + 5]) ^ 0x80);
        _expectRejected(e, root, _mismatch());
    }

    /// Dropping a sibling (claiming it is an empty subtree) changes the fold.
    function test_rejectsDroppedSibling() public {
        Entry memory e = entries[1];
        bytes memory p = new bytes(e.proof.length - 32);
        for (uint256 i = 0; i < 40; i++) {
            p[i] = e.proof[i];
        }
        uint16 n = uint16(e.pathLen - 1);
        p[40] = bytes1(uint8(n >> 8));
        p[41] = bytes1(uint8(n));
        for (uint256 i = 42; i < p.length; i++) {
            p[i] = e.proof[i]; // keeps the root-side siblings, drops the deepest one
        }
        e.proof = p;
        _expectRejected(e, root, _mismatch());
    }

    function test_rejectsOtherKeyOrAccount() public {
        Entry memory e = entries[1];
        e.key = bytes32(uint256(e.key) + 1);
        _expectRejected(e, root, _mismatch());
        e = entries[1];
        e.account = address(uint160(e.account) ^ 1);
        _expectRejected(e, root, _mismatch());
    }

    function test_rejectsOtherRoot() public {
        _expectRejected(entries[1], vm.parseJsonBytes32(json, ".l2.olderRoot"), _mismatch());
    }

    /// An absent slot cannot be passed off as holding a value: with leaf index 0 the value must be 0.
    function test_rejectsValueWithoutLeafIndex() public {
        Entry memory e = entries[2];
        e.proof[31] = 0x01;
        _expectRejected(
            e, root, abi.encodeWithSelector(IZkSyncStateTreeVerifier.NonZeroValueWithoutLeafIndex.selector, 0)
        );
    }

    /// …nor can a present slot be passed off as absent.
    function test_rejectsPresentSlotClaimedAbsent() public {
        Entry memory e = entries[1];
        for (uint256 i = 0; i < 40; i++) {
            e.proof[i] = 0; // value 0, leaf index 0
        }
        _expectRejected(e, root, _mismatch());
    }

    function test_rejectsMalformedProofs() public {
        Entry memory e = entries[1];
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        // Truncated.
        bytes memory cut = new bytes(e.proof.length - 1);
        for (uint256 i = 0; i < cut.length; i++) {
            cut[i] = e.proof[i];
        }
        vm.expectRevert(IZkSyncStateTreeVerifier.MalformedStorageProof.selector);
        tree.verifyStorage(root, a, k, cut);
        // Trailing bytes.
        vm.expectRevert(IZkSyncStateTreeVerifier.MalformedStorageProof.selector);
        tree.verifyStorage(root, a, k, bytes.concat(e.proof, hex"00"));
        // Shorter than a header.
        vm.expectRevert(IZkSyncStateTreeVerifier.MalformedStorageProof.selector);
        tree.verifyStorage(root, a, k, hex"0102");
        // pathLen > 256.
        bytes memory big = abi.encodePacked(bytes32(0), uint64(0), uint16(257), new bytes(257 * 32));
        vm.expectRevert(IZkSyncStateTreeVerifier.MalformedStorageProof.selector);
        tree.verifyStorage(root, a, k, big);
        // More keys than entries.
        address[] memory a2 = new address[](2);
        bytes32[] memory k2 = new bytes32[](2);
        a2[0] = e.account;
        k2[0] = e.key;
        vm.expectRevert(IZkSyncStateTreeVerifier.MalformedStorageProof.selector);
        tree.verifyStorage(root, a2, k2, e.proof);
        // Mismatched arrays.
        vm.expectRevert(IZkSyncStateTreeVerifier.AccountsKeysLengthMismatch.selector);
        tree.verifyStorage(root, a2, k, e.proof);
    }

    // ── Records ───────────────────────────────────────────────────────────────

    function _recordedEntry(bytes32 value) internal pure returns (bytes memory) {
        return abi.encodePacked(value, uint64(0), uint16(0xffff));
    }

    function test_record_thenReferenceCheaply() public {
        Entry memory e = entries[1];
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        vm.expectEmit(address(tree));
        emit IZkSyncStateTreeVerifier.StorageRecorded(root, e.account, e.key, e.value);
        bytes32[] memory v = tree.recordStorage(root, a, k, e.proof);
        assertEq(v[0], e.value);
        assertEq(tree.recordedValueHash(root, e.account, e.key), keccak256(abi.encode(e.value)));

        uint256 g = gasleft();
        v = tree.verifyStorage(root, a, k, _recordedEntry(e.value));
        console.log("verifyStorage, 1 RECORDED entry, gas:", g - gasleft());
        assertEq(v[0], e.value);
    }

    function test_record_rejectsWrongValueOrUnrecordedEntry() public {
        Entry memory e = entries[1];
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        bytes memory err = abi.encodeWithSelector(IZkSyncStateTreeVerifier.EntryNotRecorded.selector, 0);
        // Nothing recorded yet.
        vm.expectRevert(err);
        tree.verifyStorage(root, a, k, _recordedEntry(e.value));
        tree.recordStorage(root, a, k, e.proof);
        // Another value.
        vm.expectRevert(err);
        tree.verifyStorage(root, a, k, _recordedEntry(bytes32(uint256(e.value) ^ 1)));
        // The same entry under another root.
        vm.expectRevert(err);
        tree.verifyStorage(vm.parseJsonBytes32(json, ".l2.olderRoot"), a, k, _recordedEntry(e.value));
        // Another key.
        (address[] memory a2, bytes32[] memory k2) = _one(e.account, bytes32(uint256(e.key) + 1));
        vm.expectRevert(err);
        tree.verifyStorage(root, a2, k2, _recordedEntry(e.value));
    }

    /// Recording runs the full proof: a bad proof records nothing.
    function test_record_rejectsInvalidProof() public {
        Entry memory e = entries[1];
        e.proof[31] = bytes1(uint8(e.proof[31]) ^ 1);
        (address[] memory a, bytes32[] memory k) = _one(e.account, e.key);
        vm.expectRevert(_mismatch());
        tree.recordStorage(root, a, k, e.proof);
        assertEq(tree.recordedValueHash(root, e.account, e.key), bytes32(0));
    }

    function test_emptyRequest_returnsNothing() public view {
        assertEq(tree.verifyStorage(root, new address[](0), new bytes32[](0), "").length, 0);
    }
}
