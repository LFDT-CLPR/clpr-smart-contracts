// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprMithrilMmr
/// @notice Single-leaf membership in a Mithril `MKTree`: a Merkle mountain range from
///         ckb-merkle-mountain-range 0.6.1 whose merge is `Blake2s-256(lhs ‖ rhs)` and whose leaves
///         are NOT hashed (internal/mithril-merkle-tree `MKTreeNode + MKTreeNode`). The algorithm is
///         `MerkleProof::calculate_root` (BLAKE2s from {ClprBlake2sHasher}) specialised to one leaf: climb to the leaf's peak, take the
///         other peaks from the proof (peaks right of the leaf arrive pre-bagged as one item), then
///         bag right to left with `merge(right, left)`.
/// @dev Leaves are raw byte strings (e.g. `Tx/<hash>/<block hash>/<number>/<slot>`), so proof items
///      are not all 32 bytes: a height-0 sibling is a neighbouring raw leaf. Callers constrain item
///      shapes (see {CardanoMithrilVerifier}) so a forged leaf cannot be spliced across a
///      concatenation boundary.
library ClprMithrilMmr {
    error MmrInvalidPosition();
    error MmrCorruptedProof();

    /// @notice Root of the MMR of size `mmrSize` that holds `leaf` at position `pos`.
    function root(address b2s, bytes memory leaf, uint64 pos, uint64 mmrSize, bytes[] memory items)
        internal
        view
        returns (bytes memory)
    {
        if (pos >= mmrSize || posHeight(pos) != 0) revert MmrInvalidPosition();
        if (mmrSize == 1) {
            if (items.length != 0) revert MmrCorruptedProof();
            return leaf;
        }
        uint64[] memory peaks = getPeaks(mmrSize);
        bytes[] memory peakHashes = new bytes[](peaks.length + 1);
        uint256 np;
        uint256 it;
        bool placed;
        for (uint256 i = 0; i < peaks.length; i++) {
            uint64 peak = peaks[i];
            if (!placed && pos <= peak) {
                placed = true;
                bytes memory item = leaf;
                uint256 p = pos;
                uint256 h;
                while (p != peak) {
                    uint256 nextH = posHeight(uint64(p + 1)); // p < peak < 2^64
                    if (it >= items.length) revert MmrCorruptedProof();
                    uint256 parent;
                    if (nextH > h) {
                        parent = p + 1;
                        item = abi.encodePacked(b2s256(b2s, bytes.concat(items[it++], item)));
                    } else {
                        parent = p + (uint256(2) << h);
                        item = abi.encodePacked(b2s256(b2s, bytes.concat(item, items[it++])));
                    }
                    if (parent > peak) revert MmrCorruptedProof();
                    p = parent;
                    h++;
                }
                peakHashes[np++] = item;
            } else {
                if (it >= items.length) break;
                peakHashes[np++] = items[it++];
            }
        }
        if (!placed) revert MmrInvalidPosition();
        if (it < items.length) peakHashes[np++] = items[it++];
        if (it != items.length) revert MmrCorruptedProof();
        bytes memory acc = peakHashes[np - 1];
        for (uint256 i = np - 1; i > 0; i--) {
            acc = abi.encodePacked(b2s256(b2s, bytes.concat(acc, peakHashes[i - 1])));
        }
        return acc;
    }

    error Blake2sCallFailed();

    /// @notice BLAKE2s-256 of `data` via the {ClprBlake2sHasher} at `b2s`.
    function b2s256(address b2s, bytes memory data) internal view returns (bytes32 h) {
        (bool ok, bytes memory ret) = b2s.staticcall(data);
        if (!ok || ret.length != 32) revert Blake2sCallFailed();
        h = bytes32(ret);
    }

    /// @dev helper.rs `pos_height_in_tree`.
    function posHeight(uint64 pos) internal pure returns (uint8) {
        if (pos == 0) return 0;
        uint64 peakSize = type(uint64).max >> _lz(pos);
        while (peakSize > 0) {
            if (pos >= peakSize) pos -= peakSize;
            peakSize >>= 1;
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(pos); // < 64
    }

    /// @dev helper.rs `get_peaks`.
    function getPeaks(uint64 mmrSize) internal pure returns (uint64[] memory peaks) {
        uint64[] memory tmp = new uint64[](64);
        uint256 n;
        uint64 pos = mmrSize;
        uint64 peakSize = type(uint64).max >> _lz(mmrSize);
        uint64 sum;
        while (peakSize > 0) {
            if (pos >= peakSize) {
                pos -= peakSize;
                tmp[n++] = sum + peakSize - 1;
                sum += peakSize;
            }
            peakSize >>= 1;
        }
        peaks = new uint64[](n);
        for (uint256 i = 0; i < n; i++) {
            peaks[i] = tmp[i];
        }
    }

    function _lz(uint64 x) private pure returns (uint256 n) {
        n = 64;
        while (x != 0) {
            x >>= 1;
            n--;
        }
    }
}
