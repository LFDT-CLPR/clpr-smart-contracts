// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprSignerReplay
/// @notice Header primitives for single-signer PoA / PoSA chains whose blocks carry one ECDSA seal
///         in the last 65 bytes of `extraData` (go-ethereum Clique and its forks: HECO Congress,
///         Bitkub PoSA/PoS, Immutable's Clique).
///
/// Rules, each checked against the chain's own source:
///   - Seal hash: keccak256(RLP(header fields with `extra[:len-65]`)). Clique and Bitkub encode every
///     field the header carries (`encodeSigHeader`); Congress encodes only the first 15 fields (no
///     baseFee). A profile passes `sealFields` (0 = all fields, otherwise the leading field count).
///   - Seal: `r ‖ s ‖ v` with v ∈ {0, 1}; the signer is the ecrecover of the seal hash.
///   - Boundary blocks (Clique checkpoints, Congress epoch blocks, Bitkub span-commit blocks) list
///     the signer set in `extra[32 : len-65]` as `entrySize`-byte entries whose first 20 bytes are an
///     address, optionally followed by a `trailerSize`-byte trailer of system addresses.
library ClprSignerReplay {
    uint256 internal constant EXTRA_VANITY = 32;
    uint256 internal constant EXTRA_SEAL = 65;
    uint256 internal constant MIN_HEADER_FIELDS = 15;
    uint256 internal constant MAX_HEADER_FIELDS = 21;
    uint256 internal constant IDX_PARENT_HASH = 0;
    uint256 internal constant IDX_STATE_ROOT = 3;
    uint256 internal constant IDX_NUMBER = 8;
    uint256 internal constant IDX_EXTRA = 12;
    /// @dev Upper bound on distinct signers a boundary block may introduce.
    uint256 internal constant MAX_SIGNERS = 128;
    /// @dev Marks "no signer in the trailer".
    uint8 internal constant NO_TRAILER_SIGNER = type(uint8).max;

    error InvalidHeader();
    error InvalidExtraData();
    error InvalidSealFields();
    error SealRecoverFailed();
    error HeaderChainBroken(uint256 index);
    error InvalidSignerList();

    struct Header {
        bytes32 hash;
        bytes32 parentHash;
        bytes32 stateRoot;
        uint64 number;
        bytes extra;
        Memory.Slice[] fields;
    }

    /// @dev Decode a raw RLP header. `hash` is keccak256 of the exact encoding (the block hash).
    function decodeHeader(Memory.Slice item) internal pure returns (Header memory h) {
        h.fields = RLP.readList(item);
        uint256 n = h.fields.length;
        if (n < MIN_HEADER_FIELDS || n > MAX_HEADER_FIELDS) revert InvalidHeader();
        h.hash = keccak256(Memory.toBytes(item));
        h.parentHash = RLP.readBytes32(h.fields[IDX_PARENT_HASH]);
        h.stateRoot = RLP.readBytes32(h.fields[IDX_STATE_ROOT]);
        uint256 number = RLP.readUint256(h.fields[IDX_NUMBER]);
        if (number > type(uint64).max) revert InvalidHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        h.number = uint64(number);
        h.extra = RLP.readBytes(h.fields[IDX_EXTRA]);
        if (h.extra.length < EXTRA_VANITY + EXTRA_SEAL) revert InvalidExtraData();
    }

    /// @dev Check that `next` is the direct child of `prev` (parent hash and number).
    function requireChild(Header memory prev, Header memory next, uint256 index) internal pure {
        if (next.parentHash != prev.hash || next.number != uint256(prev.number) + 1) revert HeaderChainBroken(index);
    }

    /// @dev Recover the sealer: ecrecover over keccak256(RLP(first `sealFields` fields, extra unsealed)).
    function sealSigner(Header memory h, uint256 sealFields) internal pure returns (address signer) {
        Memory.Slice[] memory f = h.fields;
        uint256 k = sealFields == 0 ? f.length : sealFields;
        if (k < MIN_HEADER_FIELDS || k > f.length) revert InvalidSealFields();
        bytes[] memory enc = new bytes[](k);
        bytes memory extra = h.extra;
        uint256 unsealedLength = extra.length - EXTRA_SEAL;
        bytes memory unsealed = new bytes(unsealedLength);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            mcopy(add(unsealed, 0x20), add(extra, 0x20), unsealedLength)
            let sig := add(add(extra, 0x20), unsealedLength)
            r := mload(sig)
            s := mload(add(sig, 0x20))
            v := byte(0, mload(add(sig, 0x40)))
        }
        for (uint256 i = 0; i < k; i++) {
            enc[i] = i == IDX_EXTRA ? RLP.encode(unsealed) : Memory.toBytes(f[i]);
        }
        if (v > 1) revert SealRecoverFailed();
        signer = ecrecover(keccak256(RLP.encode(enc)), v + 27, r, s);
        if (signer == address(0)) revert SealRecoverFailed();
    }

    /// @dev Parse the signer list of a boundary block: the distinct entry addresses plus, when
    ///      `trailerSignerOffset != NO_TRAILER_SIGNER`, the address at that offset of the trailer.
    ///      Returned sorted ascending without duplicates (the canonical form the anchor hashes).
    function parseSigners(bytes memory extra, uint256 entrySize, uint256 trailerSize, uint8 trailerSignerOffset)
        internal
        pure
        returns (address[] memory signers)
    {
        if (extra.length < EXTRA_VANITY + EXTRA_SEAL + trailerSize) revert InvalidSignerList();
        uint256 listLength = extra.length - EXTRA_VANITY - EXTRA_SEAL - trailerSize;
        if (entrySize < 20 || listLength == 0 || listLength % entrySize != 0) revert InvalidSignerList();
        uint256 entries = listLength / entrySize;
        uint256 cap = entries + (trailerSignerOffset == NO_TRAILER_SIGNER ? 0 : 1);
        address[] memory buf = new address[](cap);
        uint256 n;
        for (uint256 i = 0; i < cap; i++) {
            uint256 off;
            if (i < entries) {
                off = EXTRA_VANITY + i * entrySize;
            } else {
                if (uint256(trailerSignerOffset) + 20 > trailerSize) revert InvalidSignerList();
                off = EXTRA_VANITY + listLength + trailerSignerOffset;
            }
            address a;
            assembly ("memory-safe") {
                a := shr(96, mload(add(add(extra, 0x20), off)))
            }
            if (a == address(0)) revert InvalidSignerList();
            n = _insertSorted(buf, n, a);
        }
        if (n > MAX_SIGNERS) revert InvalidSignerList();
        signers = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            signers[i] = buf[i];
        }
    }

    /// @dev keccak256 of the packed 20-byte addresses (the anchor's set commitment). Note that
    ///      `abi.encodePacked(address[])` would pad each element to 32 bytes, so pack by hand.
    function hashSigners(address[] memory signers) internal pure returns (bytes32 h) {
        uint256 n = signers.length;
        // 12 spare bytes: each 32-byte store below writes 12 bytes past its 20-byte slot.
        bytes memory packed = new bytes(n * 20 + 12);
        for (uint256 i = 0; i < n; i++) {
            address a = signers[i];
            assembly ("memory-safe") {
                mstore(add(add(packed, 0x20), mul(i, 20)), shl(96, a))
            }
        }
        assembly ("memory-safe") {
            h := keccak256(add(packed, 0x20), mul(n, 20))
        }
    }

    /// @dev Decode the relayer-supplied anchor set: `n × address20`, strictly ascending.
    function decodeSignerBytes(bytes memory packed) internal pure returns (address[] memory signers) {
        if (packed.length == 0 || packed.length % 20 != 0) revert InvalidSignerList();
        uint256 n = packed.length / 20;
        signers = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            address a;
            assembly ("memory-safe") {
                a := shr(96, mload(add(add(packed, 0x20), mul(i, 20))))
            }
            if (i > 0 && uint160(a) <= uint160(signers[i - 1])) revert InvalidSignerList();
            signers[i] = a;
        }
    }

    /// @dev Binary search in an ascending address array; returns the index or `type(uint256).max`.
    function indexOf(address[] memory sorted, address a) internal pure returns (uint256) {
        uint256 lo = 0;
        uint256 hi = sorted.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            address m = sorted[mid];
            if (m == a) return mid;
            if (uint160(m) < uint160(a)) lo = mid + 1;
            else hi = mid;
        }
        return type(uint256).max;
    }

    /// @dev Insert `a` into the ascending prefix `buf[0..n)` unless present; returns the new length.
    function _insertSorted(address[] memory buf, uint256 n, address a) private pure returns (uint256) {
        uint256 i = n;
        while (i > 0 && uint160(buf[i - 1]) > uint160(a)) {
            i--;
        }
        if (i > 0 && buf[i - 1] == a) return n;
        for (uint256 j = n; j > i; j--) {
            buf[j] = buf[j - 1];
        }
        buf[i] = a;
        return n + 1;
    }
}
