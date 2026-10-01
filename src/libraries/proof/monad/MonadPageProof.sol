// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MonadMpt} from "@hiero-ledger/clpr/libraries/proof/monad/MonadMpt.sol";
import {MonadBlake3} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBlake3.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MonadPageProof
/// @notice Storage proofs against a Monad account storage root under MIP-8 page storage.
/// @dev Since MIP-8 (testnet 2026-08-12, mainnet 2026-09-02) a Monad account's storage trie commits to
///      128-slot *pages*, not to slots (monad `category/execution/ethereum/db/util.cpp`
///      `PagedStorageLeafProcessor`, `trie_db.cpp`):
///        - page key   = slot >> 7 (big-endian bytes32), slot offset = slot & 127;
///        - trie path  = keccak256(page key) — branch/extension/leaf nodes are the standard MPT;
///        - leaf value = RLP string of the 32-byte page commitment (`MonadBlake3.pageCommit`);
///        - an all-zero page is not stored (the key is absent from the trie).
///      A page proof carries the page's full contents (bitmap + non-zero values); the verifier
///      recomputes the commitment, so every slot of the page — including the zero ones — is proven.
///
///      Encoding of a batch of page proofs: RLP `[nodePool, pages]` where `nodePool` is the list of trie
///      nodes shared by the batch and each page is `[pageKey(bytes32), nodeIndices(list of uint),
///      bitmap(uint128), values(list of bytes32)]` (see {MonadMpt-getOrEmptyPooled}).
library MonadPageProof {
    error PageKeyMismatch();
    error PageCommitmentMismatch();
    error PageNotProven(bytes32 pageKey);
    error InvalidPageEntry();
    error AccountAbsent();
    error InvalidAccount();

    struct Page {
        bytes32 key;
        uint128 bitmap;
        bytes32[] values;
    }

    /// @notice Account proof against a Monad state root (standard MPT, path keccak256(address), leaf
    ///         `[nonce, balance, storageRoot, codeHash]` — monad `AccountLeafProcessor`).
    function account(Memory.Slice proofList, bytes32 stateRoot, address addr)
        internal
        pure
        returns (bytes32 storageRoot, bytes32 codeHash)
    {
        Memory.Slice leaf = MonadMpt.getOrEmpty(stateRoot, keccak256(abi.encodePacked(addr)), proofList);
        if (Memory.length(leaf) == 0) revert AccountAbsent();
        Memory.Slice[] memory f = RLP.decodeList(RLP.readBytes(leaf));
        if (f.length != 4) revert InvalidAccount();
        storageRoot = RLP.readBytes32(f[2]);
        codeHash = RLP.readBytes32(f[3]);
    }

    /// @notice Verify every page proof in `pagesItem` against `storageRoot`.
    function verifyPages(Memory.Slice pagesItem, bytes32 storageRoot) internal pure returns (Page[] memory pages) {
        Memory.Slice[] memory batch = RLP.readList(pagesItem);
        if (batch.length != 2) revert InvalidPageEntry();
        Memory.Slice[] memory pool = RLP.readList(batch[0]);
        Memory.Slice[] memory entries = RLP.readList(batch[1]);
        pages = new Page[](entries.length);
        for (uint256 i = 0; i < entries.length; ++i) {
            pages[i] = verifyPage(entries[i], pool, storageRoot);
        }
    }

    /// @notice Verify one page proof and return its contents.
    function verifyPage(Memory.Slice entry, Memory.Slice[] memory pool, bytes32 storageRoot)
        internal
        pure
        returns (Page memory page)
    {
        Memory.Slice[] memory f = RLP.readList(entry);
        if (f.length != 4) revert InvalidPageEntry();
        page.key = RLP.readBytes32(f[0]);
        uint256 bm = RLP.readUint256(f[2]);
        if (bm > type(uint128).max) revert InvalidPageEntry();
        // forge-lint: disable-next-line(unsafe-typecast)
        page.bitmap = uint128(bm);
        Memory.Slice[] memory vs = RLP.readList(f[3]);
        page.values = new bytes32[](vs.length);
        for (uint256 j = 0; j < vs.length; ++j) {
            page.values[j] = RLP.readBytes32(vs[j]);
        }

        Memory.Slice leaf = MonadMpt.getOrEmptyPooled(storageRoot, keccak256(abi.encode(page.key)), pool, f[1]);
        if (Memory.length(leaf) == 0) {
            // Absent page ⇒ every slot is zero.
            if (page.bitmap != 0 || page.values.length != 0) revert PageCommitmentMismatch();
            return page;
        }
        bytes memory commitment = RLP.decodeBytes(RLP.readBytes(leaf));
        if (commitment.length != 32) revert PageCommitmentMismatch();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (bytes32(commitment) != MonadBlake3.pageCommit(page.bitmap, page.values)) {
            revert PageCommitmentMismatch();
        }
    }

    /// @notice Value of `slot` from the verified `pages` (zero if its offset is unset in the page).
    ///         Reverts if the slot's page was not supplied.
    function slotValue(Page[] memory pages, bytes32 slot) internal pure returns (bytes32) {
        bytes32 key = bytes32(uint256(slot) >> 7);
        uint256 off = uint256(slot) & 127;
        for (uint256 i = 0; i < pages.length; ++i) {
            if (pages[i].key != key) continue;
            uint256 bm = pages[i].bitmap;
            if ((bm >> off) & 1 == 0) return bytes32(0);
            return pages[i].values[_popcount(bm & ((uint256(1) << off) - 1))];
        }
        revert PageNotProven(key);
    }

    /// @notice Convenience: verify `pagesItem` and read `slots` in one go.
    function readSlots(Memory.Slice pagesItem, bytes32 storageRoot, bytes32[] memory slots)
        internal
        pure
        returns (bytes32[] memory values)
    {
        Page[] memory pages = verifyPages(pagesItem, storageRoot);
        values = new bytes32[](slots.length);
        for (uint256 i = 0; i < slots.length; ++i) {
            values[i] = slotValue(pages, slots[i]);
        }
    }

    function _popcount(uint256 x) private pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            ++c;
        }
    }
}
