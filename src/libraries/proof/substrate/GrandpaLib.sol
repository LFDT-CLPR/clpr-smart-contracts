// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";

/// @title GrandpaLib
/// @notice Verifies a GRANDPA commit (the core of a `GrandpaJustification`) against an authority set.
///
/// Signed message (sp_consensus_grandpa::localized_payload): SCALE((Message::Precommit, round, set_id))
///   = 0x01 ‖ target_hash(32) ‖ target_number(u32 LE) ‖ round(u64 LE) ‖ set_id(u64 LE)   (53 bytes)
/// where 0x01 is the `finality_grandpa::Message::Precommit` variant index, signed with ed25519.
///
/// Threshold (finality_grandpa::VoterSet): total_weight − (total_weight − 1) / 3; a commit is valid
/// once the summed weight of distinct authorities whose precommits target the commit block or a
/// descendant of it reaches the threshold (finality_grandpa::validate_commit).
///
/// Relay format. The relay re-packs the justification's `commit.precommits` into `votes`, one
/// 102-byte entry per precommit, sorted by authority index (no duplicates):
///   authorityIndex(u16 BE) ‖ targetHash(32) ‖ targetNumber(u32 BE) ‖ signature(64)
/// Precommits for a descendant of the commit target come with `votes_ancestries` headers that link
/// them back to it. Every supplied vote is verified; the relay sends just enough to pass threshold.
library GrandpaLib {
    uint256 internal constant VOTE_LENGTH = 102;
    uint256 internal constant AUTHORITY_ENTRY_LENGTH = 40;

    error InvalidAuthorities();
    error InvalidVotesLength();
    error VotesNotSorted();
    error AuthorityIndexOutOfRange();
    error InvalidPrecommitTarget();
    error InvalidGrandpaSignature(uint256 authorityIndex);
    error GrandpaThresholdNotMet(uint256 signedWeight, uint256 threshold);

    struct Commit {
        bytes32 targetHash;
        uint32 targetNumber;
        uint64 round;
        uint64 setId;
        bytes votes;
        bytes[] ancestry;
    }

    /// @notice keccak256 of the packed authority list `(key(32) ‖ weight(u64 LE))*` — the
    ///         commitment the verifiers keep in their trust anchor. Equal to keccak256 of the list
    ///         bytes inside a `ScheduledChange` digest, so a rotation needs no re-encoding.
    function authoritiesHash(bytes memory authorities) internal pure returns (bytes32) {
        return keccak256(authorities);
    }

    /// @notice GRANDPA supermajority threshold for `total` weight.
    function threshold(uint256 total) internal pure returns (uint256) {
        return total - (total - 1) / 3;
    }

    /// @notice Reverts unless `c` is a valid commit of the authority set `authorities`.
    function verifyCommit(Commit memory c, bytes memory authorities, IEd25519Verifier ed) internal view {
        (uint256 signed, uint256 need,) = verifyVotes(c, authorities, ed);
        if (signed < need) revert GrandpaThresholdNotMet(signed, need);
    }

    /// @notice Summed weight of a packed authority list. Reverts on a malformed or zero-weight list.
    function totalWeight(bytes memory authorities) internal pure returns (uint256 total) {
        uint256 n = authorities.length / AUTHORITY_ENTRY_LENGTH;
        if (n == 0 || authorities.length % AUTHORITY_ENTRY_LENGTH != 0 || n > type(uint16).max) {
            revert InvalidAuthorities();
        }
        for (uint256 i; i < n; ++i) {
            total += ScaleCodec.readU64(authorities, i * AUTHORITY_ENTRY_LENGTH + 32);
        }
        if (total == 0) revert InvalidAuthorities();
    }

    /// @notice Verifies every vote in `c.votes` (a subset of a commit is allowed) and returns the
    ///         signed weight, the set's threshold, and a bitmap of the signing authority indices
    ///         (bit `i % 256` of word `i / 256`). Used whole by {verifyCommit} and in batches by
    ///         `GrandpaCommitAccumulator`, which adds the weights of disjoint batches.
    function verifyVotes(Commit memory c, bytes memory authorities, IEd25519Verifier ed)
        internal
        view
        returns (uint256 signed, uint256 need, uint256[] memory signers)
    {
        uint256 n = authorities.length / AUTHORITY_ENTRY_LENGTH;
        need = threshold(totalWeight(authorities));
        signers = new uint256[]((n + 255) / 256);

        bytes memory votes = c.votes;
        if (votes.length == 0 || votes.length % VOTE_LENGTH != 0) revert InvalidVotesLength();
        uint256 count = votes.length / VOTE_LENGTH;

        bytes memory suffix = abi.encodePacked(ScaleCodec.le64(c.round), ScaleCodec.le64(c.setId));
        Ancestry memory anc;
        uint256 next; // smallest index the next vote may use
        for (uint256 v; v < count; ++v) {
            uint256 base = v * VOTE_LENGTH;
            uint256 idx = (uint256(uint8(votes[base])) << 8) | uint8(votes[base + 1]);
            if (idx < next) revert VotesNotSorted();
            if (idx >= n) revert AuthorityIndexOutOfRange();
            next = idx + 1;

            bytes32 tHash = ScaleCodec.readBytes32(votes, base + 2);
            uint32 tNum = uint32(bytes4(ScaleCodec.readBytes32(votes, base + 34)));
            if (tHash == c.targetHash) {
                if (tNum != c.targetNumber) revert InvalidPrecommitTarget();
            } else {
                if (anc.hashes.length == 0) anc = _loadAncestry(c.ancestry);
                if (!_descendsFrom(anc, tHash, tNum, c.targetHash)) revert InvalidPrecommitTarget();
            }

            bytes memory message = abi.encodePacked(uint8(1), tHash, ScaleCodec.le32(tNum), suffix);
            bytes32 key = ScaleCodec.readBytes32(authorities, idx * AUTHORITY_ENTRY_LENGTH);
            if (!ed.verify(key, message, ScaleCodec.slice(votes, base + 38, 64))) {
                revert InvalidGrandpaSignature(idx);
            }
            signed += ScaleCodec.readU64(authorities, idx * AUTHORITY_ENTRY_LENGTH + 32);
            signers[idx >> 8] |= 1 << (idx & 255);
        }
    }

    // ── votes_ancestries ─────────────────────────────────────────────────────

    struct Ancestry {
        bytes32[] hashes;
        bytes32[] parents;
        uint32[] numbers;
    }

    function _loadAncestry(bytes[] memory headers) private view returns (Ancestry memory a) {
        uint256 n = headers.length;
        if (n == 0) revert InvalidPrecommitTarget();
        a.hashes = new bytes32[](n);
        a.parents = new bytes32[](n);
        a.numbers = new uint32[](n);
        for (uint256 i; i < n; ++i) {
            SubstrateHeader.Header memory h = SubstrateHeader.decode(headers[i]);
            a.hashes[i] = SubstrateHeader.hash(headers[i]);
            a.parents[i] = h.parentHash;
            a.numbers[i] = h.number;
        }
    }

    /// @dev True iff `(h, num)` is a strict descendant of `target` along authenticated ancestry
    ///      headers (each step is a header whose blake2_256 is the current hash).
    function _descendsFrom(Ancestry memory a, bytes32 h, uint32 num, bytes32 target) private pure returns (bool) {
        bool first = true;
        for (uint256 steps; steps < a.hashes.length; ++steps) {
            uint256 j = a.hashes.length;
            for (uint256 k; k < a.hashes.length; ++k) {
                if (a.hashes[k] == h) {
                    j = k;
                    break;
                }
            }
            if (j == a.hashes.length) return false;
            if (first) {
                if (a.numbers[j] != num) return false;
                first = false;
            }
            h = a.parents[j];
            if (h == target) return true;
        }
        return false;
    }
}
