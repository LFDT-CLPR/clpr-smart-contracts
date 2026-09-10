// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";

/// @title MerklePatriciaProof
/// @notice Minimal Ethereum Merkle-Patricia-Trie inclusion-proof verifier.
/// @dev Supports branch (17-item), extension and leaf (2-item) nodes referenced by 32-byte
///      keccak256 hashes. Inline (sub-32-byte) child references are intentionally rejected
///      — the worked-against tries (state, storage) always hash-reference at this size class.
///      Trie keys are 32-byte hashes; callers pre-hash so this lib stays generic.
library MerklePatriciaProof {
    error MPTEmptyProof();
    error MPTInvalidHashRef();
    error MPTInvalidNode();
    error MPTInlineNodeUnsupported();
    error MPTKeyMismatch();
    error MPTKeyAbsent();
    error MPTProofEndedEarly();
    error MPTInvalidPathPrefix();

    /// @notice Strict walk: reverts when the key is absent or the path diverges. Returns the
    ///         range of the RLP-encoded leaf value inside the proof buffer, without copying it.
    /// @param proofItem The RLP list item whose payload is the sequence of node byte-strings (as
    ///        produced by an RLP list decode, or carved with `Memory.slice`); trailing bytes are
    ///        rejected. Taking a Slice keeps {RlpCursor-bounds} the single door into the raw walk.
    function requireValueRange(bytes32 root, bytes32 keyHash, Memory.Slice proofItem)
        internal
        pure
        returns (uint256 valuePtr, uint256 valueLen)
    {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(proofItem);
        return _walk(root, keyHash, ptr, end, true);
    }

    /// @notice Lenient walk: a key proven absent (or a diverging path) yields `(0, 0)` — the
    ///         caller reads the slot as the zero value. Structural defects (bad node shape, hash
    ///         mismatch, truncated proof) still revert.
    /// @dev Same `proofItem` contract as {requireValueRange}. Choosing this variant is a consensus
    ///      decision: it makes "slot not in the trie" verify as zero instead of failing.
    function valueRangeOrZero(bytes32 root, bytes32 keyHash, Memory.Slice proofItem)
        internal
        pure
        returns (uint256 valuePtr, uint256 valueLen)
    {
        (uint256 ptr, uint256 end) = RlpCursor.bounds(proofItem);
        return _walk(root, keyHash, ptr, end, false);
    }

    /// @dev The walk itself. With `strict` true an absent key or diverging path reverts;
    ///      otherwise it returns `(0, 0)`.
    function _walk(bytes32 root, bytes32 keyHash, uint256 itemPtr, uint256 itemEnd, bool strict)
        private
        pure
        returns (uint256, uint256)
    {
        (uint256 cur, uint256 listLen, bool isList) = RlpCursor.head(itemPtr, itemEnd);
        uint256 end;
        unchecked {
            end = cur + listLen;
        }
        // The proof container must be a list filling its range exactly (no trailing bytes).
        if (!isList || end != itemEnd) revert MPTInvalidNode();
        if (cur == end) revert MPTEmptyProof();

        bytes32 expectedHash = root;
        uint256 keyIdx = 0; // nibble cursor into keyHash (0..64)

        while (cur < end) {
            uint256 nodePtr;
            uint256 nodeEnd;
            {
                uint256 nodeLen;
                bool envelopeIsList;
                (nodePtr, nodeLen, envelopeIsList) = RlpCursor.head(cur, end);
                // Each proof element is a byte string wrapping the node's own RLP encoding.
                if (envelopeIsList) revert MPTInvalidNode();
                unchecked {
                    nodeEnd = nodePtr + nodeLen;
                    cur = nodeEnd;
                }
                if (RlpCursor.keccakOf(nodePtr, nodeLen) != expectedHash) revert MPTInvalidHashRef();
            }

            (uint256 payloadPtr, uint256 payloadLen, bool nodeIsList) = RlpCursor.head(nodePtr, nodeEnd);
            uint256 afterPayload;
            unchecked {
                afterPayload = payloadPtr + payloadLen;
            }
            if (!nodeIsList || afterPayload != nodeEnd) revert MPTInvalidNode();

            // Every node kind has at least two items; parse both up front.
            (uint256 aPtr, uint256 aLen, bool aIsList) = RlpCursor.head(payloadPtr, nodeEnd);
            uint256 bStart;
            unchecked {
                bStart = aPtr + aLen;
            }
            if (bStart >= nodeEnd) revert MPTInvalidNode();
            (uint256 bPtr, uint256 bLen, bool bIsList) = RlpCursor.head(bStart, nodeEnd);
            uint256 afterB;
            unchecked {
                afterB = bPtr + bLen;
            }

            if (afterB == nodeEnd) {
                // 2-item node: leaf or extension. Item 0 is the compact-encoded path.
                if (aIsList) revert MPTInvalidNode();
                (bool isLeaf, uint256 pathNibbles, uint256 shiftBits) = _decodePathPrefix(aPtr, aLen);
                if (
                    keyIdx + pathNibbles > 64
                        || (pathNibbles != 0 && !_pathMatches(aPtr, aLen, shiftBits, pathNibbles, keyHash, keyIdx))
                ) {
                    if (strict) revert MPTKeyMismatch();
                    return (0, 0);
                }
                unchecked {
                    keyIdx += pathNibbles;
                }
                if (isLeaf) {
                    if (keyIdx != 64) {
                        if (strict) revert MPTKeyMismatch();
                        return (0, 0);
                    }
                    // The range of the RLP-encoded value, verbatim (callers re-decode as needed).
                    return (bStart, nodeEnd - bStart);
                }
                if (bIsList || bLen != 32) revert MPTInlineNodeUnsupported();
                expectedHash = RlpCursor.word(bPtr);
            } else {
                // Branch node: exactly 17 items. Walk them once, capturing the target — the
                // child at the key's next nibble, or item 16 (the terminal value) when the
                // key is fully consumed.
                uint256 target = keyIdx >= 64 ? 16 : _nibAt(keyHash, keyIdx);
                // Items 0 and 1 are already parsed above; the helper walks 2..16 (and enforces the
                // 17-item shape), then the target is taken from whichever source holds it.
                (uint256 tStart, uint256 tPtr, uint256 tLen, bool tIsList) = _branchTarget(afterB, nodeEnd, target);
                if (target == 0) (tStart, tPtr, tLen, tIsList) = (payloadPtr, aPtr, aLen, aIsList);
                else if (target == 1) (tStart, tPtr, tLen, tIsList) = (bStart, bPtr, bLen, bIsList);

                if (tIsList) revert MPTInlineNodeUnsupported();
                if (tLen == 0) {
                    // Empty child slot, or an empty terminal value: the key is absent.
                    if (strict) revert MPTKeyAbsent();
                    return (0, 0);
                }
                if (target == 16) {
                    // Full key consumed — the RLP-encoded value at the branch terminal.
                    return (tStart, nodeEnd - tStart);
                }
                if (tLen != 32) revert MPTInlineNodeUnsupported();
                unchecked {
                    keyIdx++;
                }
                expectedHash = RlpCursor.word(tPtr);
            }
        }
        revert MPTProofEndedEarly();
    }

    // ── internal helpers ───────────────────────────────────────────────────────

    /// @dev Walk branch items 2..16 starting at `afterItem1` and capture item `target` when it is
    ///      among them. Reverts unless exactly 17 items fill the node (the caller parsed items 0
    ///      and 1). For `target < 2` the returns stay zero and the caller substitutes its own
    ///      already-parsed item; for `target >= 2` the loop assigns them or reverts.
    function _branchTarget(uint256 afterItem1, uint256 nodeEnd, uint256 target)
        private
        pure
        returns (uint256 tStart, uint256 tPtr, uint256 tLen, bool tIsList)
    {
        uint256 c = afterItem1;
        for (uint256 k = 2; k < 17;) {
            if (c >= nodeEnd) revert MPTInvalidNode();
            (uint256 iPtr, uint256 iLen, bool iIsList) = RlpCursor.head(c, nodeEnd);
            if (k == target) (tStart, tPtr, tLen, tIsList) = (c, iPtr, iLen, iIsList);
            unchecked {
                c = iPtr + iLen;
                k++;
            }
        }
        if (c != nodeEnd) revert MPTInvalidNode();
    }

    /// @dev Returns the nibble at position `i` within a 32-byte hash (0..63).
    function _nibAt(bytes32 keyHash, uint256 i) private pure returns (uint256) {
        unchecked {
            return (uint256(keyHash) >> (252 - 4 * i)) & 0xf;
        }
    }

    /// @dev Decode an MPT compact-encoded path prefix at `[pathPtr, pathPtr + pathLenBytes)`.
    /// @return isLeaf True for leaf nodes (prefix nibble bit-1 set), false for extension.
    /// @return pathNibbles Number of meaningful nibbles in the path payload.
    /// @return shiftBits Bit offset of the first meaningful nibble within the path bytes
    ///         (4 for odd-length paths, 8 for even-length ones — skipping the padding nibble).
    function _decodePathPrefix(uint256 pathPtr, uint256 pathLenBytes)
        private
        pure
        returns (bool isLeaf, uint256 pathNibbles, uint256 shiftBits)
    {
        if (pathLenBytes == 0) revert MPTInvalidPathPrefix();
        uint256 firstByte = RlpCursor.byteAt(pathPtr);
        uint256 prefixNib = firstByte >> 4;
        // prefix nibble: 0x0 ext-even, 0x1 ext-odd, 0x2 leaf-even, 0x3 leaf-odd
        if (prefixNib > 3) revert MPTInvalidPathPrefix();
        isLeaf = (prefixNib & 0x2) != 0;
        unchecked {
            if (prefixNib & 0x1 != 0) {
                // First nibble of payload lives in the low half of byte 0.
                pathNibbles = 2 * pathLenBytes - 1;
                shiftBits = 4;
            } else {
                // Low half of byte 0 is a padding 0x0; payload starts at byte 1.
                // For even-length paths the low half MUST be zero per spec — enforce it.
                if (firstByte & 0x0f != 0) revert MPTInvalidPathPrefix();
                pathNibbles = 2 * pathLenBytes - 2;
                shiftBits = 8;
            }
        }
    }

    /// @dev Bulk-compare the path's payload nibbles against `keyHash[keyIdx .. keyIdx + pathNibbles)`.
    ///      Callers guarantee `keyIdx + pathNibbles <= 64` and `pathNibbles > 0`, so both sides fit
    ///      one 256-bit word. All reads stay inside the path item: {RlpCursor-leftWord} zero-fills
    ///      past `pathLenBytes`, and the 33rd-byte case (a 64-nibble even path) reads exactly one
    ///      extra in-bounds byte.
    function _pathMatches(
        uint256 pathPtr,
        uint256 pathLenBytes,
        uint256 shiftBits,
        uint256 pathNibbles,
        bytes32 keyHash,
        uint256 keyIdx
    ) private pure returns (bool) {
        unchecked {
            uint256 aligned = RlpCursor.leftWord(pathPtr, pathLenBytes) << shiftBits;
            if (4 * pathNibbles > 256 - shiftBits) {
                aligned |= RlpCursor.byteAt(pathPtr + 32);
            }
            uint256 keySegment = uint256(keyHash) << (4 * keyIdx);
            return ((aligned ^ keySegment) >> (256 - 4 * pathNibbles)) == 0;
        }
    }
}
