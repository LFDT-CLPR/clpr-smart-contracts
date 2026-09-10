// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";

/// @title ClprQbftQuorum
/// @notice Checks the committed seals of a QBFT block header against a validator set.
library ClprQbftQuorum {
    error EmptyValidatorSet();
    error ValidatorSetTooLarge(uint256 size);
    error EmptySeals();
    /// @notice Distinct in-set signers are fewer than the quorum.
    error QuorumNotReached(uint256 got, uint256 required);

    /// @notice Hard upper bound on the validator-set size. {_markSigner} marks each distinct
    ///         signer as one bit of a single uint256 bitmask (bit i = member index i), so the
    ///         word width — 256 — is the structural limit. Besu itself imposes no cap, and QBFT's
    ///         all-to-all messaging keeps real validator sets far below this bound, so the bitmask
    ///         is never the binding constraint in practice. It is deliberately NOT lowered to a
    ///         gas-derived figure: contract mode re-proves the whole set per bundle, so the usable
    ///         size is set by the target chain's block gas limit, not by this contract (see
    ///         `qbft-contract-mode.md` §8 and `GAS_REPORT.md`).
    uint256 internal constant MAX_VALIDATORS = 256;

    /// @param set               A sorted, deduped validator set to check the seals against.
    /// @param header            The RLP-decoded block header (extraData at index 12).
    function verifyQuorum(ValidatorSet memory set, Memory.Slice[] memory header) internal pure {
        uint256 n = set.members.length;
        if (n == 0) revert EmptyValidatorSet();
        if (n > MAX_VALIDATORS) revert ValidatorSetTooLarge(n);

        (bytes32 sealHash, Memory.Slice[] memory seals) = ClprQbftSeal.decodeSealsContextFromHeader(header);
        if (seals.length == 0) revert EmptySeals();
        uint256 required = QbftValidators.quorum(n);
        uint256 counted;
        uint256 distinct;
        for (uint256 i = 0; i < seals.length && distinct < required;) {
            uint256 updated = _markSigner(set, counted, ClprQbftSeal.recoverSeal(sealHash, seals[i]));
            if (updated != counted) {
                counted = updated;
                unchecked {
                    distinct++;
                }
            }
            unchecked {
                i++;
            }
        }
        if (distinct < required) revert QuorumNotReached(distinct, required);
    }

    /// @notice set has to be sorted and deduped for binary search to work correctly
    /// @dev Binary-search `signer` in the set and mark its bit in the `counted` bitmask.
    ///      Returns the updated bitmask; unchanged when `signer` is not a member or already counted.
    function _markSigner(ValidatorSet memory set, uint256 counted, address signer) private pure returns (uint256) {
        uint256 lowerBoundary;
        uint256 higherBoundary = set.members.length;
        while (lowerBoundary < higherBoundary) {
            // Integer division by 2 (shifts every bit one place right, dropping the lowest bit).
            // 11 = 0b1011, shifted right by one -> 0b0101 = 5 (the dropped low bit is the discarded 0.5)
            uint256 middle = (lowerBoundary + higherBoundary) >> 1;
            address member = set.members[middle];
            // `uint256(1) << middle` builds a mask with only bit `middle` set (1 << 3 = 0b1000);
            // `|` copies it into `counted`, leaving every other bit as-is. If the bit was already
            // set (signer counted before) it changes nothing and the caller sees no growth.
            if (member == signer) return counted | (uint256(1) << middle);
            if (uint160(member) < uint160(signer)) {
                unchecked {
                    lowerBoundary = middle + 1;
                }
            } else {
                higherBoundary = middle;
            }
        }
        return counted;
    }
}
