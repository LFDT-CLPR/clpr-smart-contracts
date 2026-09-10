// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprQbftSeal
/// @notice Verifies that a Besu QBFT block header's committed-seals list contains at
///         least MIN_COMMITTED_SEALS entries and that the expected validator signed at
///         least one of them.  Reconstructs the sealing-header digest (same header with
///         `committedSeals = []` in extraData) and recovers each seal via `ecrecover`.
library ClprQbftSeal {
    error InvalidExtraData();
    error WrongSealCount(uint256 got, uint256 expected);
    error SealLengthMismatch(uint256 got);
    error SealRecoverFailed();
    error ValidatorSealNotFound(address expected);

    /// @dev Index of the `extraData` field within an Ethereum block header. QBFT carries
    ///      its consensus metadata here.
    uint8 internal constant HEADER_EXTRA_DATA_INDEX = 12;

    // QBFT extraData layout: [vanity, validators[], vote, round, committedSeals[]]
    uint8 private constant EXTRA_FIELDS = 5;
    uint8 private constant EXTRA_INDEX_COMMITTED_SEALS = 4;
    uint8 private constant SEAL_LENGTH = 65;

    /// @dev Verify that `header[12]` (extraData) contains at least minCommittedSeals
    ///      committed seals and that `expectedValidator` signed at least one of them.
    ///      Reverts on any structural mismatch, recovery failure, or missing validator.
    function verify(uint8 minCommittedSeals, Memory.Slice[] memory header, address expectedValidator) internal pure {
        (bytes32 sealHash, Memory.Slice[] memory seals) = decodeSealsContextFromHeader(header);
        if (seals.length < minCommittedSeals) revert WrongSealCount(seals.length, minCommittedSeals);

        for (uint256 i = 0; i < seals.length;) {
            if (recoverSeal(sealHash, seals[i]) == expectedValidator) return;
            unchecked {
                i++;
            }
        }
        revert ValidatorSealNotFound(expectedValidator);
    }

    /// @dev Read the committed seals and the digest they signed from a header.
    function decodeSealsContextFromHeader(Memory.Slice[] memory header)
        internal
        pure
        returns (bytes32 sealHash, Memory.Slice[] memory seals)
    {
        bytes memory extraDataInner = RLP.readBytes(header[HEADER_EXTRA_DATA_INDEX]);
        // Guard the empty case explicitly: RLP.decodeList would otherwise reject it with the
        // generic RLPInvalidEncoding instead of this library's structural error.
        if (extraDataInner.length == 0) revert InvalidExtraData();
        Memory.Slice[] memory extra = RLP.decodeList(extraDataInner);
        if (extra.length != EXTRA_FIELDS) revert InvalidExtraData();

        seals = RLP.readList(extra[EXTRA_INDEX_COMMITTED_SEALS]);
        sealHash = _sealingDigest(header, extra);
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
