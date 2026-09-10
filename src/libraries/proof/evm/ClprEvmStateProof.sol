// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MerklePatriciaProof} from "@hiero-ledger/clpr/libraries/proof/evm/MerklePatriciaProof.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprEvmStateProof
/// @notice Helpers for verifying Ethereum-style account + fixed-storage-slot Merkle-Patricia
///         inclusion proofs against a `stateRoot`, and decoding the resulting account leaf
///         into `(storageRoot, codeHash)`
library ClprEvmStateProof {
    error InvalidAccount();
    error InvalidStorageProof();
    error InvalidStorageEntry();
    error SlotNotProven(bytes32 slot);

    /// @dev Walk the account proof from `stateRoot` to the leaf for `keccak256(account)` and
    ///      decode the 4-item account RLP list (`[nonce, balance, storageRoot, codeHash]`) in
    ///      place — no intermediate copies.
    function verifyAccountFields(Memory.Slice accountProofItem, bytes32 stateRoot, address account)
        internal
        pure
        returns (bytes32 storageRoot, bytes32 codeHash)
    {
        (uint256 valuePtr, uint256 valueLen) =
            MerklePatriciaProof.requireValueRange(stateRoot, _accountKey(account), accountProofItem);

        // Strip the leaf's byte-string envelope to reach the inner account list.
        (uint256 accPtr, uint256 accLen, bool envelopeIsList) = RlpCursor.head(valuePtr, valuePtr + valueLen);
        if (envelopeIsList) revert InvalidAccount();
        uint256 accEnd;
        unchecked {
            accEnd = accPtr + accLen;
        }
        (uint256 fieldsPtr, uint256 fieldsLen, bool isList) = RlpCursor.head(accPtr, accEnd);
        uint256 fieldsEnd;
        unchecked {
            fieldsEnd = fieldsPtr + fieldsLen;
        }
        if (!isList || fieldsEnd != accEnd) revert InvalidAccount();

        // [nonce, balance, storageRoot, codeHash] — exactly four fields.
        uint256 cur = _skipItem(fieldsPtr, fieldsEnd); // nonce
        cur = _skipItem(cur, fieldsEnd); // balance
        if (cur >= fieldsEnd) revert InvalidAccount();
        (uint256 srPtr, uint256 srLen, bool srIsList) = RlpCursor.head(cur, fieldsEnd);
        if (srIsList) revert InvalidAccount();
        storageRoot = bytes32(RlpCursor.uintValue(srPtr, srLen));
        unchecked {
            cur = srPtr + srLen;
        }
        if (cur >= fieldsEnd) revert InvalidAccount();
        (uint256 chPtr, uint256 chLen, bool chIsList) = RlpCursor.head(cur, fieldsEnd);
        if (chIsList) revert InvalidAccount();
        codeHash = bytes32(RlpCursor.uintValue(chPtr, chLen));
        unchecked {
            if (chPtr + chLen != fieldsEnd) revert InvalidAccount();
        }
    }

    /// @dev Walk the storage-proof list in place and validate every entry once: a 2-item list
    ///      `[slotNumber, proofNodes]` with a non-list slot of at most 32 bytes and a list proof
    ///      field ending exactly at the entry's end. Every malformed shape reverts
    ///      {InvalidStorageEntry} wherever the entry sits, so a malformed entry can never be
    ///      skipped because it happened not to be looked up. Returns the slot labels and the
    ///      proof-node list items, ready for one or more {verifyIndexedSlots} lookups.
    /// @param storageProofItem The RLP list of entries, each a 2-tuple `[slotNumber, proofNodes]`.
    ///                         No value is carried: the proven value is read from the Merkle proof
    ///                         leaf, so passing it alongside would be redundant (and unverified) data.
    function indexEntries(Memory.Slice storageProofItem)
        internal
        pure
        returns (bytes32[] memory labels, Memory.Slice[] memory proofs)
    {
        (uint256 basePtr, uint256 itemEnd) = RlpCursor.bounds(storageProofItem);
        (uint256 cur, uint256 len, bool isList) = RlpCursor.head(basePtr, itemEnd);
        uint256 end;
        unchecked {
            end = cur + len;
        }
        if (!isList || end != itemEnd) revert InvalidStorageProof();

        uint256 entryCount;
        for (uint256 p = cur; p < end;) {
            (uint256 payloadPtr, uint256 payloadLen,) = RlpCursor.head(p, end);
            unchecked {
                p = payloadPtr + payloadLen;
                entryCount++;
            }
        }
        labels = new bytes32[](entryCount);
        proofs = new Memory.Slice[](entryCount);
        for (uint256 i = 0; i < entryCount;) {
            (labels[i], proofs[i], cur) = _indexEntry(storageProofItem, basePtr, cur, end);
            unchecked {
                i++;
            }
        }
    }

    /// @dev Verify storage slots whose slot numbers are DERIVED BY THE CALLER (never taken from the
    ///      proof) against entries indexed by {indexEntries}. For each `expectedSlots[j]`, find the
    ///      entry whose label equals it, verify its Merkle proof against `storageRoot` at trie path
    ///      `keccak256(slot)`, and return the proven value.
    ///
    ///      The lookup keeps a rotating cursor: each search starts right after the previous match,
    ///      so entries laid out in expected-slot order are found in one probe each. Any order is
    ///      still accepted; a disordered layout only costs the SENDER extra probes. WHICH entry a
    ///      lookup lands on does depend on order when several entries carry the same label (or
    ///      `expectedSlots` repeats a slot): the cursor resolves to whichever same-labelled entry it
    ///      reaches first, so a list mixing a valid and a broken proof for one slot may pass or
    ///      revert depending on layout. That is sound either way — whatever entry is chosen must
    ///      hash-chain from `storageRoot` at the caller-derived key, and two valid proofs under one
    ///      root and key cannot disagree — but callers must not read acceptance of such lists as a
    ///      guarantee about the other duplicates.
    function verifyIndexedSlots(
        bytes32[] memory labels,
        Memory.Slice[] memory proofs,
        bytes32 storageRoot,
        bytes32[] memory expectedSlots
    ) internal pure returns (bytes32[] memory provenValues) {
        uint256 entryCount = labels.length;
        provenValues = new bytes32[](expectedSlots.length);
        uint256 cursor = 0;
        for (uint256 j = 0; j < expectedSlots.length;) {
            bytes32 want = expectedSlots[j];
            uint256 step = 0;
            for (; step < entryCount;) {
                uint256 i;
                unchecked {
                    i = cursor + step;
                    if (i >= entryCount) i -= entryCount;
                }
                if (labels[i] == want) {
                    (uint256 valuePtr, uint256 valueLen) =
                        MerklePatriciaProof.valueRangeOrZero(storageRoot, _slotKey(want), proofs[i]);
                    provenValues[j] = _decodeStorageScalar(valuePtr, valueLen);
                    unchecked {
                        cursor = i + 1;
                        if (cursor >= entryCount) cursor = 0;
                    }
                    break;
                }
                unchecked {
                    step++;
                }
            }
            if (step == entryCount) revert SlotNotProven(want);
            unchecked {
                j++;
            }
        }
    }

    /// @dev {indexEntries} + {verifyIndexedSlots} for callers with a single lookup.
    function verifyProvenSlots(Memory.Slice storageProofItem, bytes32 storageRoot, bytes32[] memory expectedSlots)
        internal
        pure
        returns (bytes32[] memory)
    {
        (bytes32[] memory labels, Memory.Slice[] memory proofs) = indexEntries(storageProofItem);
        return verifyIndexedSlots(labels, proofs, storageRoot, expectedSlots);
    }

    /// @dev Validate the entry at `itemPtr` and return its slot label, its proof-node list item
    ///      (a sub-slice of `storageProofItem`) and the start of the next entry. The entry's end is
    ///      taken from its own header, so trailing bytes after an entry are parsed as the next
    ///      entry and fail there.
    function _indexEntry(Memory.Slice storageProofItem, uint256 basePtr, uint256 itemPtr, uint256 end)
        private
        pure
        returns (bytes32 label, Memory.Slice proof, uint256 next)
    {
        (uint256 payloadPtr, uint256 payloadLen, bool isList) = RlpCursor.head(itemPtr, end);
        if (!isList || payloadLen == 0) revert InvalidStorageEntry();
        unchecked {
            next = payloadPtr + payloadLen;
        }
        (uint256 slotPtr, uint256 slotLen, bool slotIsList) = RlpCursor.head(payloadPtr, next);
        if (slotIsList || slotLen > 32) revert InvalidStorageEntry();
        uint256 nodesStart;
        unchecked {
            nodesStart = slotPtr + slotLen;
        }
        if (nodesStart >= next) revert InvalidStorageEntry();
        (uint256 nodesPtr, uint256 nodesLen, bool nodesIsList) = RlpCursor.head(nodesStart, next);
        unchecked {
            if (!nodesIsList || nodesPtr + nodesLen != next) revert InvalidStorageEntry();
            proof = Memory.slice(storageProofItem, nodesStart - basePtr, next - nodesStart);
        }
        label = bytes32(RlpCursor.uintValue(slotPtr, slotLen));
    }

    /// @dev Storage-trie leaf values are double-wrapped: outer byte-string envelope around
    ///      the RLP-encoded uint256 scalar (leading-zero-stripped). Strip both layers in place.
    ///      Absent (`valuePtr == 0`) or empty at either layer ⇒ zero.
    function _decodeStorageScalar(uint256 valuePtr, uint256 valueLen) private pure returns (bytes32) {
        if (valuePtr == 0 || valueLen == 0) return bytes32(0);
        (uint256 innerPtr, uint256 innerLen, bool envelopeIsList) = RlpCursor.head(valuePtr, valuePtr + valueLen);
        if (envelopeIsList) revert InvalidStorageEntry();
        if (innerLen == 0) return bytes32(0);
        uint256 innerEnd;
        unchecked {
            innerEnd = innerPtr + innerLen;
        }
        (uint256 scalarPtr, uint256 scalarLen, bool scalarIsList) = RlpCursor.head(innerPtr, innerEnd);
        // The scalar must be the whole inner payload — no trailing bytes.
        unchecked {
            if (scalarIsList || scalarPtr + scalarLen != innerEnd) revert InvalidStorageEntry();
        }
        return bytes32(RlpCursor.uintValue(scalarPtr, scalarLen));
    }

    /// @dev Advance past one RLP item, or revert {InvalidAccount} when none remains.
    function _skipItem(uint256 ptr, uint256 end) private pure returns (uint256) {
        if (ptr >= end) revert InvalidAccount();
        (uint256 payloadPtr, uint256 payloadLen,) = RlpCursor.head(ptr, end);
        unchecked {
            return payloadPtr + payloadLen;
        }
    }

    /// @dev `keccak256(abi.encodePacked(slot))` via scratch space — no allocation.
    function _slotKey(bytes32 slot) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, slot)
            h := keccak256(0x00, 0x20)
        }
    }

    /// @dev `keccak256(abi.encodePacked(account))` (20 bytes) via scratch space — no allocation.
    function _accountKey(address account) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, shl(96, account))
            h := keccak256(0x00, 0x14)
        }
    }
}
