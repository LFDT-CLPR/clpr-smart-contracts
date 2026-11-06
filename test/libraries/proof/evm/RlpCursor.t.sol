// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

contract RlpCursorHarness {
    using Memory for bytes;

    /// @dev Parse the header of the first item in `buf`; offsets are relative to the buffer start.
    function head(bytes memory buf) external pure returns (uint256 payloadOffset, uint256 payloadLen, bool isList) {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(buf.asSlice());
        (uint256 payloadPtr, uint256 len, bool list) = RlpCursor.head(ptr, end);
        return (payloadPtr - ptr, len, list);
    }

    /// @dev Read the first item of `buf` as a scalar (header parse + uintValue).
    function uintValue(bytes memory buf) external pure returns (uint256) {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(buf.asSlice());
        (uint256 payloadPtr, uint256 payloadLen,) = RlpCursor.head(ptr, end);
        return RlpCursor.uintValue(payloadPtr, payloadLen);
    }

    /// @dev uintValue over the WHOLE buffer as a raw payload (no RLP header).
    function uintOfPayload(bytes memory payload) external pure returns (uint256) {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(payload.asSlice());
        return RlpCursor.uintValue(ptr, end - ptr);
    }

    /// @dev Walk `buf` as one RLP list: parse the container, then every item in sequence.
    ///      Returns per-item (payloadOffset, payloadLen, isList) relative to the buffer start,
    ///      and requires the walk to consume the container payload exactly.
    function walkList(bytes memory buf)
        external
        pure
        returns (uint256[] memory offs, uint256[] memory lens, bool[] memory lists)
    {
        (uint256 base, uint256 bufEnd) = RlpCursor.bounds(buf.asSlice());
        (uint256 p, uint256 pLen, bool isList) = RlpCursor.head(base, bufEnd);
        require(isList, "not a list");
        uint256 end = p + pLen;

        // Count first.
        uint256 n;
        for (uint256 c = p; c < end; n++) {
            (uint256 ip, uint256 il,) = RlpCursor.head(c, end);
            c = ip + il;
        }
        offs = new uint256[](n);
        lens = new uint256[](n);
        lists = new bool[](n);
        uint256 cur = p;
        for (uint256 i = 0; i < n; i++) {
            (uint256 ip, uint256 il, bool l) = RlpCursor.head(cur, end);
            offs[i] = ip - base;
            lens[i] = il;
            lists[i] = l;
            cur = ip + il;
        }
        require(cur == end, "walk overshoot");
    }

    function copyRange(bytes memory buf, uint256 off, uint256 len) external pure returns (bytes memory) {
        return Memory.toBytes(Memory.slice(buf.asSlice(), off, len));
    }

    function payloadSlice(bytes memory buf) external pure returns (bytes memory) {
        return Memory.toBytes(RlpCursor.payloadSlice(buf.asSlice()));
    }

    function keccakRange(bytes memory buf, uint256 off, uint256 len) external pure returns (bytes32) {
        (uint256 ptr,) = RlpCursor.bounds(buf.asSlice());
        return RlpCursor.keccakOf(ptr + off, len);
    }

    function byteAtIndex(bytes memory buf, uint256 i) external pure returns (uint256) {
        (uint256 ptr,) = RlpCursor.bounds(buf.asSlice());
        return RlpCursor.byteAt(ptr + i);
    }

    function wordAt(bytes memory buf) external pure returns (bytes32) {
        (uint256 ptr,) = RlpCursor.bounds(buf.asSlice());
        return RlpCursor.word(ptr);
    }

    function boundsLength(bytes memory buf) external pure returns (uint256) {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(buf.asSlice());
        return end - ptr;
    }

    function boundsOfPacked(uint256 ptr, uint256 len) external pure returns (uint256, uint256) {
        return RlpCursor.bounds(Memory.Slice.wrap(bytes32((len << 128) | ptr)));
    }

    /// @dev The OZ decode, externalized so tests can `vm.expectRevert` its rejections.
    function ozDecodeBytes(bytes memory buf) external pure returns (bytes memory) {
        return RLP.decodeBytes(buf);
    }

    /// @dev bounds() over a sub-slice carved with Memory.slice — the shape OZ's readList returns.
    function subSlice(bytes memory buf, uint256 off, uint256 len)
        external
        pure
        returns (uint256 sliceLen, bytes memory content)
    {
        Memory.Slice s = Memory.slice(buf.asSlice(), off, len);
        (uint256 ptr, uint256 end) = RlpCursor.bounds(s);
        sliceLen = end - ptr;
        content = Memory.toBytes(s);
    }
}

contract RlpCursorTest is Test {
    using Memory for bytes;

    RlpCursorHarness internal h;

    function setUp() public {
        h = new RlpCursorHarness();
    }

    function test_head_singleByte_zero() public view {
        (uint256 off, uint256 len, bool isList) = h.head(hex"00");
        assertEq(off, 0); // the byte is its own payload
        assertEq(len, 1);
        assertFalse(isList);
    }

    function test_head_singleByte_max() public view {
        (uint256 off, uint256 len, bool isList) = h.head(hex"7f");
        assertEq(off, 0);
        assertEq(len, 1);
        assertFalse(isList);
    }

    function test_head_emptyString() public view {
        (uint256 off, uint256 len, bool isList) = h.head(hex"80");
        assertEq(off, 1);
        assertEq(len, 0);
        assertFalse(isList);
    }

    function test_head_oneByteString() public view {
        // 0x80 as content must be wrapped: [0x81, 0x80].
        (uint256 off, uint256 len, bool isList) = h.head(hex"8180");
        assertEq(off, 1);
        assertEq(len, 1);
        assertFalse(isList);
    }

    function test_head_shortString() public view {
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(bytes(hex"deadbeef")));
        assertEq(off, 1);
        assertEq(len, 4);
        assertFalse(isList);
    }

    function test_head_shortString_maxLen55() public view {
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(new bytes(55))); // prefix 0xb7
        assertEq(off, 1);
        assertEq(len, 55);
        assertFalse(isList);
    }

    function test_head_longString_minLen56() public view {
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(new bytes(56))); // 0xb8 0x38
        assertEq(off, 2); // prefix + 1 length byte
        assertEq(len, 56);
        assertFalse(isList);
    }

    function test_head_longString_twoLengthBytes() public view {
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(new bytes(300))); // 0xb9 0x01 0x2c
        assertEq(off, 3); // prefix + 2 length bytes
        assertEq(len, 300);
        assertFalse(isList);
    }

    function test_head_emptyList() public view {
        (uint256 off, uint256 len, bool isList) = h.head(hex"c0");
        assertEq(off, 1);
        assertEq(len, 0);
        assertTrue(isList);
    }

    function test_head_shortList() public view {
        bytes[] memory items = new bytes[](1);
        items[0] = RLP.encode(uint256(7));
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(items));
        assertEq(off, 1);
        assertEq(len, 1);
        assertTrue(isList);
    }

    function test_head_shortList_maxPayload55() public view {
        bytes[] memory items = new bytes[](1);
        items[0] = RLP.encode(new bytes(54)); // 1-byte header + 54 = 55 payload bytes → prefix 0xf7
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(items));
        assertEq(off, 1);
        assertEq(len, 55);
        assertTrue(isList);
    }

    function test_head_longList_minPayload56() public view {
        bytes[] memory items = new bytes[](1);
        items[0] = RLP.encode(new bytes(55)); // 1-byte header + 55 = 56 payload bytes → 0xf8 0x38
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(items));
        assertEq(off, 2);
        assertEq(len, 56);
        assertTrue(isList);
    }

    function test_head_longList_twoLengthBytes() public view {
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(new bytes(200)); // 0xb8 0xc8 + 200 = 202 bytes each
        items[1] = RLP.encode(new bytes(200));
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(items)); // 404 payload bytes
        assertEq(off, 3);
        assertEq(len, 404);
        assertTrue(isList);
    }

    function test_head_nestedList_returnsOuterOnly() public view {
        bytes[] memory inner = new bytes[](1);
        inner[0] = RLP.encode(uint256(1));
        bytes[] memory outer = new bytes[](1);
        outer[0] = RLP.encode(inner);
        (uint256 off, uint256 len, bool isList) = h.head(RLP.encode(outer));
        assertEq(off, 1);
        assertEq(len, 2); // the inner list's full encoding (0xc1 0x01)
        assertTrue(isList);
    }

    /// @dev An item ending exactly at `end` parses; the bounds check is not off by one.
    function test_head_itemEndsExactlyAtEnd() public view {
        (uint256 off, uint256 len,) = h.head(hex"84deadbeef");
        assertEq(off + len, 5);
    }

    function test_head_emptyRange_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head("");
    }

    function test_head_shortString_missingPayload_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"81");
    }

    function test_head_shortString_truncatedPayload_reverts() public {
        // Declares a 4-byte string but carries only 2 payload bytes.
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"84dead");
    }

    function test_head_longString_missingLengthBytes_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"b8");
    }

    function test_head_longString_truncatedPayload_reverts() public {
        // Long-string prefix claiming a length that overshoots the buffer.
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"b8ffdead");
    }

    function test_head_shortList_truncatedPayload_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"c2aa"); // claims 2 payload bytes, carries 1
    }

    function test_head_longList_missingLengthBytes_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"f8");
    }

    function test_head_longList_truncatedPayload_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(hex"f838aabb");
    }

    function testFuzz_head_truncated_reverts(bytes memory data, uint256 cut) public {
        bytes memory enc = RLP.encode(data);
        vm.assume(enc.length >= 2);
        cut = bound(cut, 1, enc.length - 1);
        assembly ("memory-safe") {
            mstore(enc, cut)
        }
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.head(enc);
    }

    /// @dev A single byte < 0x80 wrapped in a string header. OZ: RLPInvalidEncoding.
    function test_head_nonCanonical_wrappedSingleByte_accepted() public {
        (uint256 off, uint256 len, bool isList) = h.head(hex"8100");
        assertEq(off, 1);
        assertEq(len, 1);
        assertFalse(isList);
        assertEq(h.uintValue(hex"8100"), 0);

        vm.expectRevert(RLP.RLPInvalidEncoding.selector);
        h.ozDecodeBytes(hex"8100");
    }

    /// @dev Long-string form for a <= 55-byte payload. OZ requires len > 55 for the long form.
    function test_head_nonCanonical_longFormShortPayload_accepted() public {
        (uint256 off, uint256 len, bool isList) = h.head(hex"b802cafe");
        assertEq(off, 2);
        assertEq(len, 2);
        assertFalse(isList);

        vm.expectRevert(RLP.RLPInvalidEncoding.selector);
        h.ozDecodeBytes(hex"b802cafe");
    }

    /// @dev A zero-length payload in long form. OZ rejects; the cursor reads an empty payload.
    function test_head_nonCanonical_longFormZeroLength_accepted() public view {
        (uint256 off, uint256 len,) = h.head(hex"b800");
        assertEq(off, 2);
        assertEq(len, 0);
    }

    /// @dev A leading zero byte in the long length. OZ rejects the zero length byte.
    function test_head_nonCanonical_leadingZeroLength_accepted() public {
        bytes memory payload = new bytes(56);
        payload[0] = 0xaa;
        bytes memory enc = bytes.concat(hex"b90038", payload); // 0x0038 = 56, leading zero
        (uint256 off, uint256 len,) = h.head(enc);
        assertEq(off, 3);
        assertEq(len, 56);

        vm.expectRevert(RLP.RLPInvalidEncoding.selector);
        h.ozDecodeBytes(enc);
    }

    function test_uintValue_zeroLength_isZero() public view {
        assertEq(h.uintValue(hex"80"), 0); // empty string payload
    }

    function test_uintValue_singleByte() public view {
        assertEq(h.uintValue(hex"07"), 7);
        assertEq(h.uintValue(hex"7f"), 0x7f);
    }

    function test_uintValue_scalar() public view {
        assertEq(h.uintValue(RLP.encode(uint256(0xdeadbeef))), 0xdeadbeef);
        assertEq(h.uintValue(RLP.encode(type(uint256).max)), type(uint256).max);
    }

    function test_uintValue_full32BytePayload() public view {
        assertEq(h.uintOfPayload(abi.encodePacked(bytes32(uint256(1) << 255))), uint256(1) << 255);
    }

    /// @dev Leading zero bytes are accepted and ignored (same as OZ's readUint256).
    function test_uintValue_leadingZeros() public view {
        assertEq(h.uintOfPayload(hex"00ff"), 0xff);
        assertEq(h.uintOfPayload(hex"000000"), 0);
        assertEq(RLP.decodeUint256(hex"8300ff00"), 0xff00); // OZ accepts them too
    }

    function test_uintValue_over32Bytes_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorScalarTooLong.selector);
        h.uintOfPayload(new bytes(33));
    }

    function test_walk_mixedItems() public view {
        bytes[] memory inner = new bytes[](1);
        inner[0] = RLP.encode(uint256(9));
        bytes[] memory items = new bytes[](4);
        items[0] = RLP.encode(uint256(0x1234)); // 3-byte item
        items[1] = RLP.encode(new bytes(0)); // 0x80
        items[2] = RLP.encode(inner); // nested list
        items[3] = RLP.encode(new bytes(60)); // long string
        bytes memory enc = RLP.encode(items);

        (uint256[] memory offs, uint256[] memory lens, bool[] memory lists) = h.walkList(enc);
        assertEq(offs.length, 4);
        assertEq(lens[0], 2); // 0x1234 payload
        assertEq(lens[1], 0);
        assertTrue(lists[2]);
        assertEq(lens[3], 60);
        assertFalse(lists[0]);
        assertFalse(lists[1]);
        assertFalse(lists[3]);
        // Items are contiguous and in order.
        assertLt(offs[0], offs[1]);
        assertLt(offs[1], offs[2]);
        assertLt(offs[2], offs[3]);
    }

    function test_walk_emptyList() public view {
        (uint256[] memory offs,,) = h.walkList(hex"c0");
        assertEq(offs.length, 0);
    }

    function test_bounds_emptyBuffer() public view {
        assertEq(h.boundsLength(""), 0);
    }

    function test_bounds_matchesLength() public view {
        assertEq(h.boundsLength(hex"aabbcc"), 3);
        assertEq(h.boundsLength(new bytes(300)), 300);
    }

    function test_byteAt_everyPosition() public view {
        bytes memory buf = hex"a1b2c3d4e5";
        assertEq(h.byteAtIndex(buf, 0), 0xa1);
        assertEq(h.byteAtIndex(buf, 2), 0xc3);
        assertEq(h.byteAtIndex(buf, 4), 0xe5);
    }

    function test_word_readsFullWord() public view {
        bytes32 expected = keccak256("word");
        assertEq(h.wordAt(abi.encodePacked(expected, hex"ff")), expected);
    }

    function test_keccakOf_matchesKeccak256() public view {
        bytes memory buf = hex"0011223344556677";
        assertEq(h.keccakRange(buf, 0, buf.length), keccak256(buf));
        assertEq(h.keccakRange(buf, 2, 3), keccak256(hex"223344"));
        assertEq(h.keccakRange(buf, 0, 0), keccak256(""));
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Differential fuzz against the OZ implementation
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev For any byte string: cursor header parse agrees with the OZ decode.
    function testFuzz_head_matchesOz_bytes(bytes memory data) public view {
        bytes memory enc = RLP.encode(data);
        (uint256 off, uint256 len, bool isList) = h.head(enc);
        assertFalse(isList);
        assertEq(len, data.length, "payload length");
        assertEq(off + len, enc.length, "exact consumption");
        assertEq(h.copyRange(enc, off, len), data, "payload bytes");
        assertEq(RLP.decodeBytes(enc), data, "OZ agrees");
    }

    /// @dev For any uint: cursor scalar decode == OZ decode == the value.
    function testFuzz_uintValue_matchesOz(uint256 v) public view {
        bytes memory enc = RLP.encode(v);
        assertEq(h.uintValue(enc), v, "cursor");
        assertEq(RLP.decodeUint256(enc), v, "OZ");
    }

    /// @dev For any list of byte strings: the cursor's item walk lands on exactly the item
    ///      boundaries OZ's readList reports, and both recover the same payloads.
    function testFuzz_walk_matchesOz_list(bytes[] memory items) public view {
        vm.assume(items.length <= 8);
        uint256 totalLen;
        for (uint256 i = 0; i < items.length; i++) {
            vm.assume(items[i].length <= 128);
            totalLen += items[i].length;
        }
        vm.assume(totalLen <= 512);

        bytes[] memory encoded = new bytes[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            encoded[i] = RLP.encode(items[i]);
        }
        bytes memory listEnc = RLP.encode(encoded);

        (uint256[] memory offs, uint256[] memory lens, bool[] memory lists) = h.walkList(listEnc);
        Memory.Slice[] memory oz = RLP.decodeList(listEnc);

        assertEq(offs.length, oz.length, "item count");
        assertEq(offs.length, items.length, "expected count");
        for (uint256 i = 0; i < items.length; i++) {
            assertFalse(lists[i]);
            assertEq(lens[i], items[i].length, "payload length");
            assertEq(h.copyRange(listEnc, offs[i], lens[i]), items[i], "cursor payload");
            assertEq(RLP.readBytes(oz[i]), items[i], "OZ payload");
        }
    }

    /// @dev payloadSlice strips exactly the byte-string envelope, in place.
    function test_payloadSlice_stripsEnvelope() public view {
        assertEq(h.payloadSlice(hex"83010203"), hex"010203");
        assertEq(h.payloadSlice(hex"80"), hex"");
        bytes memory long = new bytes(60);
        long[0] = 0xaa;
        long[59] = 0xbb;
        assertEq(h.payloadSlice(RLP.encode(long)), long);
    }

    /// @dev A list where a byte string is expected (the contract-mode validator-source item shape).
    function test_payloadSlice_list_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorUnexpectedList.selector);
        h.payloadSlice(hex"c0");
        vm.expectRevert(RlpCursor.RlpCursorUnexpectedList.selector);
        h.payloadSlice(hex"c20102");
    }

    /// @dev The pointer floor: a Slice pointing below 32 would let the right-aligned loads wrap
    ///      below address 0, so bounds() rejects it. No allocated buffer sits there (the free-memory
    ///      pointer starts at 0x80), so the only way in is a hand-packed Slice.
    function test_bounds_lowPointer_reverts() public {
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.boundsOfPacked(0, 8);
        vm.expectRevert(RlpCursor.RlpCursorOutOfBounds.selector);
        h.boundsOfPacked(31, 8);
        (uint256 ptr, uint256 end) = h.boundsOfPacked(32, 8);
        assertEq(ptr, 32);
        assertEq(end, 40);
    }

    /// @dev bounds() must decode offset sub-slices (the shape OZ's readList hands back), pinning
    ///      the pointer half of the Slice packing that OZ keeps private.
    function test_bounds_offsetSlice() public view {
        bytes memory buf = hex"00112233445566778899aabbccddeeff";
        (uint256 len, bytes memory content) = h.subSlice(buf, 4, 7);
        assertEq(len, 7);
        assertEq(content, hex"445566778899aa");
    }
}
