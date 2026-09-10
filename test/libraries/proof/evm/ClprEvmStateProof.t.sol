// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {MerklePatriciaProof} from "@hiero-ledger/clpr/libraries/proof/evm/MerklePatriciaProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {EvmMptBuilder} from "@test/helpers/EvmMptBuilder.sol";
import {MptWire} from "@test/helpers/MptWire.sol";

contract ClprEvmStateProofHarness {
    using Memory for bytes;

    function verifyAccountFields(bytes memory accountProofRlp, bytes32 stateRoot, address account)
        external
        pure
        returns (bytes32 storageRoot, bytes32 codeHash)
    {
        return ClprEvmStateProof.verifyAccountFields(accountProofRlp.asSlice(), stateRoot, account);
    }

    /// @dev Accepts an RLP-encoded outer list of entries (each a 2-item list [slot, proofList]).
    function verifyProvenSlots(bytes memory entriesEncoded, bytes32 storageRoot, bytes32[] memory expectedSlots)
        external
        pure
        returns (bytes32[] memory)
    {
        return ClprEvmStateProof.verifyProvenSlots(entriesEncoded.asSlice(), storageRoot, expectedSlots);
    }
}

contract ClprEvmStateProofTest is Test {
    address internal constant ACCOUNT = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;

    ClprEvmStateProofHarness internal h;

    function setUp() public {
        h = new ClprEvmStateProofHarness();
    }

    // ── verifyAccountFields ───────────────────────────────────────────────────

    function test_verifyAccountFields_success() public view {
        bytes32 expectedStorage = bytes32(uint256(0xdeadbeef));
        bytes32 expectedCode = bytes32(uint256(0xcafebabe));
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(1)); // nonce
        fields[1] = RLP.encode(uint256(0)); // balance
        fields[2] = RLP.encode(expectedStorage); // storageRoot
        fields[3] = RLP.encode(expectedCode); // codeHash
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        (bytes32 storageRoot, bytes32 codeHash) = h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
        assertEq(storageRoot, expectedStorage);
        assertEq(codeHash, expectedCode);
    }

    function test_verifyAccountFields_reverts_wrongFieldCount() public {
        // 3-item list instead of the expected 4-item account RLP.
        bytes[] memory fields = new bytes[](3);
        fields[0] = RLP.encode(uint256(0)); // nonce
        fields[1] = RLP.encode(uint256(0)); // balance
        fields[2] = RLP.encode(bytes32(0)); // storageRoot only (missing codeHash)
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_twoFieldAccount() public {
        bytes[] memory fields = new bytes[](2);
        fields[0] = RLP.encode(uint256(0)); // nonce
        fields[1] = RLP.encode(uint256(0)); // balance — storageRoot/codeHash missing
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_fiveFieldAccount() public {
        bytes[] memory fields = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            fields[i] = RLP.encode(uint256(i));
        }
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_accountNotAList() public {
        // The leaf value wraps a byte string where the 4-item account list belongs.
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(bytes(hex"deadbeef")));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_oneFieldAccount() public {
        bytes[] memory fields = new bytes[](1);
        fields[0] = RLP.encode(uint256(0)); // nonce only: the balance skip runs out of fields
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    /// @dev The leaf's value item is a list instead of the byte-string envelope. The walker hands
    ///      a leaf value back verbatim, so the account decoder is where this is caught.
    function test_verifyAccountFields_reverts_leafValueIsList() public {
        bytes memory accountList = _buildAccountRlp(bytes32(uint256(1)), bytes32(uint256(2)));
        (bytes32 stateRoot, bytes memory proofRlp) =
            _buildLeafProofItem(keccak256(abi.encodePacked(ACCOUNT)), RLP.encode(_singleton(accountList)));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_storageRootIsList() public {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(0));
        fields[1] = RLP.encode(uint256(0));
        fields[2] = RLP.encode(_singleton(RLP.encode(uint256(1)))); // list where the root belongs
        fields[3] = RLP.encode(bytes32(uint256(2)));
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    function test_verifyAccountFields_reverts_codeHashIsList() public {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(0));
        fields[1] = RLP.encode(uint256(0));
        fields[2] = RLP.encode(bytes32(uint256(1)));
        fields[3] = RLP.encode(_singleton(RLP.encode(uint256(2)))); // list where the code hash belongs
        (bytes32 stateRoot, bytes memory proofRlp) = _buildAccountLeafProof(ACCOUNT, RLP.encode(fields));

        vm.expectRevert(ClprEvmStateProof.InvalidAccount.selector);
        h.verifyAccountFields(proofRlp, stateRoot, ACCOUNT);
    }

    // ── verifyProvenSlots ─────────────────────────────────────────────────────

    /// @dev The storage proof item itself must be a list filling its range.
    function test_verifyProvenSlots_proofNotAList_reverts() public {
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageProof.selector);
        h.verifyProvenSlots(RLP.encode(bytes(hex"deadbeef")), bytes32(0), slots);
    }

    function test_verifyProvenSlots_trailingBytesAfterList_reverts() public {
        bytes32 slot = bytes32(uint256(0x01));
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildLeafProof(keyHash, RLP.encode(uint256(7)));
        bytes memory outerList = bytes.concat(RLP.encode(_singleton(_buildEntry(slot, proofListRlp))), hex"00");
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(ClprEvmStateProof.InvalidStorageProof.selector);
        h.verifyProvenSlots(outerList, storageRoot, slots);
    }

    /// @dev A hash-valid leaf whose value item is a list, not the byte-string envelope.
    function test_verifyProvenSlots_leafValueIsList_reverts() public {
        bytes32 slot = bytes32(uint256(0x01));
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        (bytes32 storageRoot, bytes memory proofListRlp) =
            _buildLeafProofItem(keyHash, RLP.encode(_singleton(RLP.encode(uint256(7)))));
        bytes memory outerList = RLP.encode(_singleton(_buildEntry(slot, proofListRlp)));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, storageRoot, slots);
    }

    /// @dev An entry with three fields is rejected at the entry layer, whatever the fields hold.
    function test_verifyProvenSlots_threeFieldEntry_reverts() public {
        bytes[] memory entryItems = new bytes[](3);
        entryItems[0] = RLP.encode(bytes32(uint256(0x01)));
        entryItems[1] = RLP.encode(new bytes(0));
        entryItems[2] = RLP.encode(new bytes(0));
        bytes memory badEntry = RLP.encode(entryItems);
        bytes memory outerList = RLP.encode(_singleton(badEntry));

        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    /// @dev Three fields where the second is a VALID proof list: still an entry-shape error, so a
    ///      relay on the old `[slot, value, nodes]` shape learns that from the selector.
    function test_verifyProvenSlots_extraFieldAfterValidProof_reverts() public {
        bytes32 slot = bytes32(uint256(0x42));
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildLeafProof(keccak256(abi.encodePacked(slot)), hex"01");
        bytes[] memory entryItems = new bytes[](3);
        entryItems[0] = RLP.encode(slot);
        entryItems[1] = proofListRlp;
        entryItems[2] = RLP.encode(bytes(hex"deadbeef"));
        bytes memory outerList = RLP.encode(_singleton(RLP.encode(entryItems)));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, storageRoot, slots);
    }

    /// @dev Acceptance does not depend on entry order: a malformed entry placed AFTER every
    ///      matched one still reverts, even though the lookup never needs to probe it.
    function test_verifyProvenSlots_malformedUnmatchedEntry_reverts() public {
        bytes32 slot = bytes32(uint256(0x42));
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildLeafProof(keccak256(abi.encodePacked(slot)), hex"01");
        bytes[] memory entries = new bytes[](2);
        entries[0] = _buildEntry(slot, proofListRlp);
        entries[1] = RLP.encode(_singleton(RLP.encode(bytes32(uint256(0x99))))); // 1-field junk, never matched
        bytes memory outerList = RLP.encode(entries);
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, storageRoot, slots);
    }

    /// @dev A slot label longer than 32 bytes is an entry-shape error, not a cursor error.
    function test_verifyProvenSlots_oversizedSlotLabel_reverts() public {
        bytes[] memory entryItems = new bytes[](2);
        entryItems[0] = RLP.encode(new bytes(33));
        entryItems[1] = hex"c0";
        bytes memory outerList = RLP.encode(_singleton(RLP.encode(entryItems)));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(0);

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    /// @dev An entry that is the empty list: rejected as a malformed entry, not as a cursor error.
    function test_verifyProvenSlots_emptyListEntry_reverts() public {
        bytes memory outerList = RLP.encode(_singleton(hex"c0"));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    /// @dev A leaf whose value carries bytes after the scalar item: the scalar must fill the
    ///      inner payload exactly. This is a deliberate TIGHTENING over the OZ decode it replaced
    ///      (`RLP.decodeUint256` read the first item and ignored trailing bytes); the leaf is
    ///      hash-authenticated, so no honest encoder ever produces this shape.
    function test_verifyProvenSlots_leafScalarWithTrailingBytes_reverts() public {
        bytes32 slot = bytes32(uint256(0x77));
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        // inner payload = RLP(0x01) followed by junk
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildLeafProof(keyHash, hex"01deadbeef");
        bytes memory outerList = RLP.encode(_singleton(_buildEntry(slot, proofListRlp)));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, storageRoot, slots);
    }

    /// @dev A matched entry with no proof-node field at all.
    function test_verifyProvenSlots_oneFieldEntry_reverts() public {
        bytes memory badEntry = RLP.encode(_singleton(RLP.encode(bytes32(uint256(0x01)))));
        bytes memory outerList = RLP.encode(_singleton(badEntry));

        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    function test_verifyProvenSlots_slotNotFound_reverts() public {
        bytes32 slot = bytes32(uint256(0x01));
        bytes32 otherSlot = bytes32(uint256(0x02));
        bytes memory entry = _buildAbsentSlotEntry(otherSlot, slot); // entry is for otherSlot, not slot
        bytes memory outerList = RLP.encode(_singleton(entry));

        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        vm.expectRevert(abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, slot));
        h.verifyProvenSlots(outerList, keccak256("storageRoot"), slots);
    }

    function test_verifyProvenSlots_found_absentValue_returnsZero() public view {
        bytes32 slot = bytes32(uint256(0x42));
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildAbsentProof(keyHash);
        bytes memory entry = _buildEntry(slot, proofListRlp);
        bytes memory outerList = RLP.encode(_singleton(entry));

        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        bytes32[] memory values = h.verifyProvenSlots(outerList, storageRoot, slots);
        assertEq(values.length, 1);
        assertEq(values[0], bytes32(0));
    }

    function test_verifyProvenSlots_found_emptyLeaf_returnsZero() public view {
        // Leaf with empty value (0x80 = RLP of empty bytes) hits _decodeStorageScalar's
        // empty-inner-payload branch.
        bytes32 slot = bytes32(uint256(0x99));
        bytes32 keyHash = keccak256(abi.encodePacked(slot));
        (bytes32 storageRoot, bytes memory proofListRlp) = _buildEmptyValueLeafProof(keyHash);
        bytes memory entry = _buildEntry(slot, proofListRlp);
        bytes memory outerList = RLP.encode(_singleton(entry));

        bytes32[] memory slots = new bytes32[](1);
        slots[0] = slot;

        bytes32[] memory values = h.verifyProvenSlots(outerList, storageRoot, slots);
        assertEq(values[0], bytes32(0));
    }

    function test_verifyProvenSlots_entryNotAList_reverts() public {
        bytes memory outerList = RLP.encode(_singleton(RLP.encode(bytes(hex"deadbeef"))));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    function test_verifyProvenSlots_slotFieldIsList_reverts() public {
        bytes[] memory entryItems = new bytes[](2);
        entryItems[0] = RLP.encode(_singleton(RLP.encode(uint256(1)))); // list, not a scalar
        entryItems[1] = RLP.encode(new bytes(0));
        bytes memory outerList = RLP.encode(_singleton(RLP.encode(entryItems)));
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(uint256(0x01));

        vm.expectRevert(ClprEvmStateProof.InvalidStorageEntry.selector);
        h.verifyProvenSlots(outerList, bytes32(0), slots);
    }

    /// @dev Entries laid out in reverse of the expected-slot order: the rotating cursor must wrap
    ///      and still prove every slot (order independence of the wire format). The trie is built
    ///      by {EvmMptBuilder}, which handles shared key-hash prefixes correctly.
    function test_verifyProvenSlots_reversedEntryOrder_allProven() public {
        bytes32 slotA = bytes32(uint256(0x0a));
        bytes32 slotB = bytes32(uint256(0x0b));
        bytes32 keyA = keccak256(abi.encodePacked(slotA));
        bytes32 keyB = keccak256(abi.encodePacked(slotB));

        EvmMptBuilder trie = new EvmMptBuilder();
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = keyA;
        keys[1] = keyB;
        bytes[] memory vals = new bytes[](2);
        vals[0] = RLP.encode(uint256(0xa1)); // storage leaves double-wrap the scalar
        vals[1] = RLP.encode(uint256(0xb1));
        bytes32 storageRoot = trie.build(keys, vals);

        // Entries in [B, A] order; expected slots in [A, B] order.
        bytes[] memory entries = new bytes[](2);
        entries[0] = _buildEntry(slotB, trie.proofRlp(keyB));
        entries[1] = _buildEntry(slotA, trie.proofRlp(keyA));
        bytes memory outerList = RLP.encode(entries);

        bytes32[] memory slots = new bytes32[](2);
        slots[0] = slotA;
        slots[1] = slotB;

        bytes32[] memory values = h.verifyProvenSlots(outerList, storageRoot, slots);
        assertEq(values[0], bytes32(uint256(0xa1)));
        assertEq(values[1], bytes32(uint256(0xb1)));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// @dev Build a single-element bytes[] for RLP.encode(bytes[]).
    function _singleton(bytes memory item) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = item;
    }

    /// @dev Build an entry [slotBytes32, proofListRlp] for verifyProvenSlots.
    function _buildEntry(bytes32 slot, bytes memory proofListRlp) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(slot);
        items[1] = proofListRlp;
        return RLP.encode(items);
    }

    /// @dev Build an entry for `otherSlot` that will be skipped when looking for `targetSlot`.
    function _buildAbsentSlotEntry(
        bytes32 otherSlot,
        bytes32 /*targetSlot*/
    )
        internal
        pure
        returns (bytes memory)
    {
        // proof doesn't matter — we just need the slot number to not match targetSlot
        bytes32 keyHash = keccak256(abi.encodePacked(otherSlot));
        (, bytes memory proofListRlp) = _buildAbsentProof(keyHash);
        return _buildEntry(otherSlot, proofListRlp);
    }

    /// @dev Build a branch-all-empty proof (key absent) for the given keyHash.
    ///      Returns (storageRoot, proofListRlp) where proofListRlp is an RLP list of [RLP(branchNode)].
    function _buildAbsentProof(
        bytes32 /*keyHash*/
    )
        internal
        pure
        returns (bytes32 storageRoot, bytes memory proofListRlp)
    {
        bytes[] memory branchItems = new bytes[](17);
        for (uint256 i = 0; i < 17; i++) {
            branchItems[i] = RLP.encode(new bytes(0));
        }
        bytes memory branchNode = RLP.encode(branchItems);
        storageRoot = keccak256(branchNode);
        proofListRlp = MptWire.wrap(_singleton(branchNode));
    }

    /// @dev Build a leaf proof where the leaf value = 0x80 (RLP of empty bytes).
    function _buildEmptyValueLeafProof(bytes32 keyHash)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory proofListRlp)
    {
        return _buildLeafProof(keyHash, new bytes(0));
    }

    /// @dev Single-leaf account proof for `account`: the leaf covers the full 64-nibble
    ///      `keccak256(account)` path and carries `accountListRlp` as its value.
    function _buildAccountLeafProof(address account, bytes memory accountListRlp)
        internal
        pure
        returns (bytes32 stateRoot, bytes memory proofListRlp)
    {
        return _buildLeafProof(keccak256(abi.encodePacked(account)), accountListRlp);
    }

    /// @dev Single-leaf proof for `keyHash` with an even 64-nibble path holding `value`.
    function _buildLeafProof(bytes32 keyHash, bytes memory value)
        internal
        pure
        returns (bytes32 root, bytes memory proofListRlp)
    {
        return _buildLeafProofItem(keyHash, RLP.encode(value));
    }

    /// @dev {_buildLeafProof} with the value item supplied already encoded (to plant a list).
    function _buildLeafProofItem(bytes32 keyHash, bytes memory valueItem)
        internal
        pure
        returns (bytes32 root, bytes memory proofListRlp)
    {
        bytes memory leafNode = MptWire.leaf(keyHash, valueItem);
        root = keccak256(leafNode);
        proofListRlp = MptWire.wrapOne(leafNode);
    }

    function _buildAccountRlp(bytes32 storageRoot, bytes32 codeHash) internal pure returns (bytes memory) {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(0));
        fields[1] = RLP.encode(uint256(0));
        fields[2] = RLP.encode(storageRoot);
        fields[3] = RLP.encode(codeHash);
        return RLP.encode(fields);
    }
}
