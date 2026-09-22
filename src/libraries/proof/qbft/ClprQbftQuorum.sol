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
    error TrustLinkNotReached(uint256 got, uint256 required);
    error TooManySetChanges(uint256 added, uint256 removed);

    /// @notice Hard upper bound on the validator-set size. {_markSigner} marks each distinct
    ///         signer as one bit of a single uint256 bitmask (bit i = member index i), so the
    ///         word width — 256 — is the structural limit. Besu itself imposes no cap, and QBFT's
    ///         all-to-all messaging keeps real validator sets far below this bound, so the bitmask
    ///         is never the binding constraint in practice. It is deliberately NOT lowered to a
    ///         gas-derived figure: contract mode re-proves the whole set per bundle, so the usable
    ///         size is set by the target chain's block gas limit, not by this contract (see
    ///         `qbft-contract-mode.md` §8 and `GAS_REPORT.md`).
    uint256 internal constant MAX_VALIDATORS = 256;

    struct SealerCounts {
        uint256 listed;
        uint256 trusted;
        bool addedSigned;
    }

    /// @param set     A sorted, deduped validator set to check the seals against.
    /// @param header  The RLP-decoded block header (extraData at index 12).
    function verifyQuorum(ValidatorSet memory set, Memory.Slice[] memory header) internal pure {
        uint256 n = _checkedSize(set);
        (bytes32 sealHash, Memory.Slice[] memory seals) = ClprQbftSeal.decodeSealsContextFromHeader(header);
        _requireQuorum(set, QbftValidators.quorum(n), sealHash, seals);
    }

    /// @param set    A sorted, deduped validator set to check the seals against.
    /// @param extra  The header's `extraData` already decoded.
    function verifyQuorum(ValidatorSet memory set, ClprQbftSeal.HeaderExtra memory extra) internal pure {
        uint256 n = _checkedSize(set);
        _requireQuorum(set, QbftValidators.quorum(n), extra.sealHash, extra.seals);
    }

    /// @dev Recover seals until required distinct members of set have signed; stop early once
    ///      they have. Reverts `EmptySeals` on no seals and `QuorumNotReached` when short.
    function _requireQuorum(ValidatorSet memory set, uint256 required, bytes32 sealHash, Memory.Slice[] memory seals)
        private
        pure
    {
        if (seals.length == 0) revert EmptySeals();
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

    /// @notice What we check:
    ///         1. Is the change legal? The header's set may differ from the trusted set by one
    ///            validator at most (Besu applies one change per block).
    ///         2. Can we trust it? Enough of the trusted set must have sealed the block: a 2/3
    ///            quorum when the sets are equal, quorum - 1 when one validator changed. If the
    ///            new validator did not seal, the full quorum is required again.
    ///         3. Is the block self-consistent? It must be sealed by a 2/3 quorum of the
    ///            validators from its own header.
    /// @param listed  Validator set from the block header.
    /// @param trusted Validator set from the trust anchor.
    /// @param extra   The block header's `extraData`, decoded.
    function verifyRotationStep(
        ValidatorSet memory listed,
        ValidatorSet memory trusted,
        ClprQbftSeal.HeaderExtra memory extra
    ) internal pure {
        uint256 nListed = _checkedSize(listed);
        uint256 nTrusted = _checkedSize(trusted);
        (uint256 added, uint256 removed, address addedMember) = _diff(listed, trusted);
        if (added + removed == 0) {
            verifyQuorum(listed, extra);
            return;
        }
        if (added + removed > 1) revert TooManySetChanges(added, removed);

        SealerCounts memory counts = _countSealers(listed, trusted, extra, addedMember);
        uint256 requiredTrusted = trustLinkRequired(nTrusted, added == 1 && !counts.addedSigned);
        if (counts.trusted < requiredTrusted) revert TrustLinkNotReached(counts.trusted, requiredTrusted);
        uint256 requiredListed = QbftValidators.quorum(nListed);
        if (counts.listed < requiredListed) revert QuorumNotReached(counts.listed, requiredListed);
    }

    /// @notice If a newly added member did not seal the block, the full quorum of trusted
    ///         validators is required. Otherwise one signer fewer is accepted. The result never
    ///         drops below 1: a single trusted validator (quorum 1) must still sign.
    function trustLinkRequired(uint256 n, bool fullQuorum) internal pure returns (uint256) {
        uint256 q = QbftValidators.quorum(n);
        if (fullQuorum) return q;
        return q > 1 ? q - 1 : 1;
    }

    /// @dev Who was added and who was removed, compared with the trusted set. `addedMember` is
    ///      set when exactly one validator was added.
    function _diff(ValidatorSet memory listed, ValidatorSet memory trusted)
        private
        pure
        returns (uint256 added, uint256 removed, address addedMember)
    {
        address[] memory l = listed.members;
        address[] memory t = trusted.members;
        uint256 i;
        uint256 j;
        while (i < l.length && j < t.length) {
            address la = l[i];
            address ta = t[j];
            if (la == ta) {
                unchecked {
                    ++i;
                    ++j;
                }
            } else if (uint160(la) < uint160(ta)) {
                addedMember = la;
                unchecked {
                    ++added;
                    ++i;
                }
            } else {
                unchecked {
                    ++removed;
                    ++j;
                }
            }
        }
        if (i < l.length) {
            addedMember = l[i];
            added += l.length - i;
        }
        removed += t.length - j;
    }

    /// @dev Recover each seal once; count distinct signers in `listed` and in `trusted`, and note
    ///      whether `addedMember` sealed. Stops once both sets have a full quorum of signers.
    function _countSealers(
        ValidatorSet memory listed,
        ValidatorSet memory trusted,
        ClprQbftSeal.HeaderExtra memory extra,
        address addedMember
    ) private pure returns (SealerCounts memory counts) {
        if (extra.seals.length == 0) revert EmptySeals();
        uint256 enoughListed = QbftValidators.quorum(listed.members.length);
        uint256 enoughTrusted = QbftValidators.quorum(trusted.members.length);
        uint256 listedMask;
        uint256 trustedMask;
        for (
            uint256 i = 0; i < extra.seals.length && (counts.listed < enoughListed || counts.trusted < enoughTrusted);) {
            address signer = ClprQbftSeal.recoverSeal(extra.sealHash, extra.seals[i]);
            if (signer == addedMember) counts.addedSigned = true;
            uint256 updated = _markSigner(listed, listedMask, signer);
            if (updated != listedMask) {
                listedMask = updated;
                unchecked {
                    counts.listed++;
                }
            }
            updated = _markSigner(trusted, trustedMask, signer);
            if (updated != trustedMask) {
                trustedMask = updated;
                unchecked {
                    counts.trusted++;
                }
            }
            unchecked {
                i++;
            }
        }
    }

    function _checkedSize(ValidatorSet memory set) private pure returns (uint256 n) {
        n = set.members.length;
        if (n == 0) revert EmptyValidatorSet();
        if (n > MAX_VALIDATORS) revert ValidatorSetTooLarge(n);
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
