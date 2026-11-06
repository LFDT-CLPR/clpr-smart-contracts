// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title RlpCursor
/// @notice A minimal RLP reader for the proof-verification hot paths. It parses item headers in
///         place over raw memory ranges and does not allocate memory.
/// @dev Why this library exists, and we're not using OZ instead:
///
///      - The Merkle-Patricia proof walk reads many small RLP items in tight loops.
///      - The generic `RLP.readList` allocates a slice array for each list it decodes. One
///        17-item branch node costs approximately 20,000 gas this way. The same parse with this
///        cursor costs less than 100 gas for each item.
///      - The cursor makes sure that each item stays inside its range. It does not reject
///        non-canonical encodings, which the generic library rejects. The accept set is NOT a
///        strict superset of OZ's, though: `ClprEvmStateProof._decodeStorageScalar` additionally
///        requires a storage leaf's scalar to fill its payload, which OZ's decode did not.
///
///      What the non-canonical acceptance means, precisely. Merkle-Patricia node CONTENTS are
///      keccak-checked against a committed hash before they are parsed, so a different encoding
///      of a node's fields cannot change the authenticated bytes. The framing layers parsed
///      WITHOUT being hashed themselves are: the outer proof-container header and each node's
///      byte-string envelope (the walk); the storage-proof list header, each entry's list header,
///      its slot label and its proof-nodes list header ({ClprEvmStateProof-indexEntries}); the
///      byte-string envelope around a contract-mode validator-source proof ({payloadSlice}); and
///      the contract-mode trusted-set list header and its address items. For those
///      layers the relaxation means one logical proof has many byte encodings that all verify
///      identically (the framed bytes still have to hash correctly, and slot keys are always
///      derived by the verifier, so no forged value is possible). Nothing in this repository keys
///      replay protection or deduplication off raw proof bytes; do not introduce code that does.
///
///      Memory-safety and the one PRECONDITION every caller owes this library. No helper reads
///      past the end of the caller's range. A load whose 32-byte window would cross that end is
///      right-aligned instead (it ends at the last needed byte), so it reaches up to 31 bytes
///      BEFORE the requested pointer. That is inside the enclosing allocation only because every
///      range sits at least one 32-byte length word into a `bytes` buffer — which is exactly what
///      {bounds} guarantees for slices produced by OZ's `RLP`/`Memory`, and enforces with a
///      `ptr >= 32` check. Raw `(ptr, end)` pairs handed to {head}, {uintValue}, {leftWord} or
///      {byteAt} MUST come from {bounds} or from arithmetic on such a range; never point them at
///      scratch space or a hand-built buffer below 0x80. This is what keeps every assembly block
///      here honestly `memory-safe`.
library RlpCursor {
    /// @notice An item's header or payload extends past the end of its enclosing range.
    error RlpCursorOutOfBounds();
    /// @notice A scalar item's payload exceeds 32 bytes.
    error RlpCursorScalarTooLong();
    /// @notice A byte-string item was expected but a list was found.
    error RlpCursorUnexpectedList();

    /// @dev The raw `(ptr, end)` range covered by a {Memory-Slice}.
    ///      LAYOUT DEPENDENCY: the pointer half is extracted from OZ's internal Slice packing
    ///      (`length << 128 | ptr`), which OZ does not expose publicly (only `Memory.length` is
    ///      public). An OZ upgrade that changes the packing breaks this function — the pinned
    ///      submodule and the proof test suites (which fail loudly on any mismatch) guard it.
    function bounds(Memory.Slice item) internal pure returns (uint256 ptr, uint256 end) {
        unchecked {
            ptr = uint256(Memory.Slice.unwrap(item)) & type(uint128).max;
            end = ptr + Memory.length(item);
        }
        // Rejects fabricated low pointers so the right-aligned (backward) loads can never wrap
        // below address 0. Every Solidity memory pointer is >= 0x80 and sits one length word into
        // its `bytes` buffer; this check is the structural floor, that fact is the allocation
        // argument (see the library note). All walks take a Slice, so this is the single door.
        if (ptr < 32) revert RlpCursorOutOfBounds();
    }

    /// @dev The payload of the byte-string item `item` as a Slice — the envelope stripped in place,
    ///      no copy. Reverts {RlpCursorUnexpectedList} if the item is a list. (Replaces
    ///      `RLP.readBytes` where the payload is large and only ever read as a slice.)
    function payloadSlice(Memory.Slice item) internal pure returns (Memory.Slice) {
        (uint256 ptr, uint256 end) = bounds(item);
        (uint256 payloadPtr, uint256 payloadLen, bool isList) = head(ptr, end);
        if (isList) revert RlpCursorUnexpectedList();
        unchecked {
            return Memory.slice(item, payloadPtr - ptr, payloadLen);
        }
    }

    /// @dev Parse the header of the RLP item at `ptr`, bounded by `end`.
    /// @return payloadPtr Start of the item's payload.
    /// @return payloadLen Payload length in bytes. The item ends at `payloadPtr + payloadLen`.
    /// @return isList     True for a list item, false for a byte-string item.
    function head(uint256 ptr, uint256 end)
        internal
        pure
        returns (uint256 payloadPtr, uint256 payloadLen, bool isList)
    {
        if (ptr >= end) revert RlpCursorOutOfBounds();
        uint256 prefix = byteAt(ptr);
        unchecked {
            if (prefix < 0x80) {
                // Single byte below 0x80 is its own payload.
                return (ptr, 1, false);
            }
            if (prefix < 0xb8) {
                // Short string (0-55 bytes).
                payloadPtr = ptr + 1;
                payloadLen = prefix - 0x80;
            } else if (prefix < 0xc0) {
                // Long string: 1-8 length bytes follow the prefix (0xb8..0xbf caps it at 8).
                uint256 lengthBytes = prefix - 0xb7;
                payloadPtr = ptr + 1 + lengthBytes;
                if (payloadPtr > end) revert RlpCursorOutOfBounds();
                payloadLen = _maskedLoad(ptr + 1, lengthBytes);
            } else if (prefix < 0xf8) {
                // Short list (0-55 payload bytes).
                payloadPtr = ptr + 1;
                payloadLen = prefix - 0xc0;
                isList = true;
            } else {
                // Long list: 1-8 length bytes (0xf8..0xff).
                uint256 lengthBytes = prefix - 0xf7;
                payloadPtr = ptr + 1 + lengthBytes;
                if (payloadPtr > end) revert RlpCursorOutOfBounds();
                payloadLen = _maskedLoad(ptr + 1, lengthBytes);
                isList = true;
            }
            if (payloadPtr + payloadLen > end) revert RlpCursorOutOfBounds();
        }
    }

    /// @dev The big-endian scalar held by a payload of at most 32 bytes (empty payload is 0).
    ///      Leading zero bytes are accepted (non-canonical, see the library note). Also used by
    ///      {head} for the 1-8 length bytes of long-form items.
    ///      PRECONDITION: `payloadPtr + payloadLen >= 32` inside an allocated buffer (backward read).
    function uintValue(uint256 payloadPtr, uint256 payloadLen) internal pure returns (uint256 value) {
        if (payloadLen > 32) revert RlpCursorScalarTooLong();
        if (payloadLen == 0) return 0;
        return _maskedLoad(payloadPtr, payloadLen);
    }

    /// @dev The word at `ptr`. CALLERS MUST GUARANTEE all 32 bytes lie inside their range
    ///      (used for the 32-byte child-hash reads, whose length is checked first).
    function word(uint256 ptr) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(ptr)
        }
    }

    /// @dev Up to 32 bytes at `[ptr, ptr + len)`, left-aligned and zero-filled past `len`.
    ///      Loads right-aligned when `len < 32`, so it never reads past `ptr + len`.
    ///      PRECONDITION: `ptr + len >= 32` inside an allocated buffer (backward read).
    function leftWord(uint256 ptr, uint256 len) internal pure returns (uint256 w) {
        if (len >= 32) {
            assembly ("memory-safe") {
                w := mload(ptr)
            }
        } else {
            assembly ("memory-safe") {
                w := shl(shl(3, sub(32, len)), mload(sub(add(ptr, len), 32)))
            }
        }
    }

    /// @dev The byte at `ptr`, read as the last byte of a word ending at `ptr + 1`.
    ///      PRECONDITION: `ptr >= 31` inside an allocated buffer (backward read).
    function byteAt(uint256 ptr) internal pure returns (uint256 b) {
        assembly ("memory-safe") {
            b := and(mload(sub(ptr, 31)), 0xff)
        }
    }

    /// @dev The big-endian value of the `len` bytes at `[ptr, ptr + len)`, `1 <= len <= 32`, via a
    ///      right-aligned load ending at the last byte — never reads past it. The single masked
    ///      load behind {uintValue} (scalars) and {head} (1-8 header length bytes).
    function _maskedLoad(uint256 ptr, uint256 len) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := and(mload(sub(add(ptr, len), 32)), shr(shl(3, sub(32, len)), not(0)))
        }
    }

    /// @dev keccak256 over the raw range `[ptr, ptr + len)`. Callers guarantee the range lies
    ///      inside an allocated buffer.
    function keccakOf(uint256 ptr, uint256 len) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(ptr, len)
        }
    }
}
