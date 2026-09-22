// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprQbftSeal
/// @notice Reads a Besu QBFT block header's `extraData`: the validator list it carries and the
///         committed seals over it. Reconstructs the sealing-header digest (same header with
///         `committedSeals = []` in extraData) and recovers each seal via `ecrecover`.
library ClprQbftSeal {
    error InvalidExtraData();
    error SealLengthMismatch(uint256 got);
    error SealRecoverFailed();

    /// @dev Index of the `extraData` field within an Ethereum block header. QBFT carries
    ///      its consensus metadata here.
    uint8 internal constant HEADER_EXTRA_DATA_INDEX = 12;

    // QBFT extraData layout: [vanity, validators[], vote, round, committedSeals[]]
    uint8 private constant EXTRA_FIELDS = 5;
    uint8 private constant EXTRA_INDEX_VALIDATORS = 1;
    uint8 private constant EXTRA_INDEX_COMMITTED_SEALS = 4;
    uint8 private constant SEAL_LENGTH = 65;

    /// @notice A header's `extraData`, decoded once: the digest the seals signed, the seals, and the
    ///         validator list. A verifier that needs both the list and the seals reads them from one
    ///         of these instead of decoding the header twice.
    struct HeaderExtra {
        bytes32 sealHash;
        Memory.Slice[] seals;
        Memory.Slice validators;
    }

    /// @dev Decode `header[12]` (extraData) exactly once. Reverts `InvalidExtraData` when it is
    ///      empty or not the 5-item QBFT layout.
    function decodeHeader(Memory.Slice[] memory header) internal pure returns (HeaderExtra memory x) {
        Memory.Slice[] memory extra = _decodeExtra(header);
        x.seals = RLP.readList(extra[EXTRA_INDEX_COMMITTED_SEALS]);
        x.validators = extra[EXTRA_INDEX_VALIDATORS];
        x.sealHash = _sealingDigest(header, extra);
    }

    /// @dev The seals and the digest they signed, for a caller that reads no validator list from
    ///      the header.
    function decodeSealsContextFromHeader(Memory.Slice[] memory header)
        internal
        pure
        returns (bytes32 sealHash, Memory.Slice[] memory seals)
    {
        Memory.Slice[] memory extra = _decodeExtra(header);
        seals = RLP.readList(extra[EXTRA_INDEX_COMMITTED_SEALS]);
        sealHash = _sealingDigest(header, extra);
    }

    function _decodeExtra(Memory.Slice[] memory header) private pure returns (Memory.Slice[] memory extra) {
        bytes memory extraDataInner = RLP.readBytes(header[HEADER_EXTRA_DATA_INDEX]);
        // Guard the empty case explicitly: RLP.decodeList would otherwise reject it with the
        // generic RLPInvalidEncoding instead of this library's structural error.
        if (extraDataInner.length == 0) revert InvalidExtraData();
        extra = RLP.decodeList(extraDataInner);
        if (extra.length != EXTRA_FIELDS) revert InvalidExtraData();
    }

    /// @dev Recover the signer of one committed seal over `sealHash`. Reverts on a bad length or a
    ///      failed recovery. QBFT seals carry v in {0,1}; the precompile wants {27,28}, so normalize.
    function recoverSeal(bytes32 sealHash, Memory.Slice sealSlice) internal pure returns (address recovered) {
        bytes memory seal = RLP.readBytes(sealSlice);
        if (seal.length != SEAL_LENGTH) revert SealLengthMismatch(seal.length);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(seal, 0x20))
            s := mload(add(seal, 0x40))
            v := byte(0, mload(add(seal, 0x60)))
        }
        if (v < 27) v += 27;
        recovered = ecrecover(sealHash, v, r, s);
        if (recovered == address(0)) revert SealRecoverFailed();
    }

    /// @dev Reconstruct `keccak256(RLP(header_with_empty_seals))` — the digest the
    ///      validator originally signed before its seal was appended.
    function _sealingDigest(Memory.Slice[] memory header, Memory.Slice[] memory extra) private pure returns (bytes32) {
        bytes[] memory sealingExtraItems = new bytes[](EXTRA_FIELDS);
        for (uint256 i = 0; i < uint256(EXTRA_INDEX_COMMITTED_SEALS);) {
            sealingExtraItems[i] = Memory.toBytes(extra[i]);
            unchecked {
                ++i;
            }
        }
        sealingExtraItems[EXTRA_INDEX_COMMITTED_SEALS] = RLP.encode(new bytes[](0));
        return _hashWithExtra(header, sealingExtraItems);
    }

    /// @dev Hash the header with its extraData replaced by the re-encoded `extraItems`.
    function _hashWithExtra(Memory.Slice[] memory header, bytes[] memory extraItems) private pure returns (bytes32) {
        bytes memory newExtraData = RLP.encode(extraItems);
        bytes[] memory headerItems = new bytes[](header.length);
        for (uint256 i = 0; i < header.length;) {
            headerItems[i] =
                (i == uint256(HEADER_EXTRA_DATA_INDEX)) ? RLP.encode(newExtraData) : Memory.toBytes(header[i]);
            unchecked {
                ++i;
            }
        }
        return keccak256(RLP.encode(headerItems));
    }
}
