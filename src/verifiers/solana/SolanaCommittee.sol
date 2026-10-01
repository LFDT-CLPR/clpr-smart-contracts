// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SolanaCommittee
/// @notice K-of-N secp256k1 attestor committee for the Solana verifier.
///
/// Solana consensus (TowerBFT today, Alpenglow next) never commits to provable account state: the
/// bank hash folds in a 2 KiB lattice hash (SIMD-0215) that admits no inclusion proofs, and no
/// receipt or status root exists (SIMD-0064 is Stagnant). The CLPR program's queue state therefore
/// reaches Hiero as a statement signed by a committee whose members each run a Solana node. This
/// library is that trust root; it is labelled as committee trust in every README and PR.
///
/// Signatures are raw 65-byte secp256k1 over a domain-separated keccak digest (no EIP-191 prefix),
/// recovered with OpenZeppelin `ECDSA.tryRecover` (rejects high-s and malformed signatures). Each
/// signature names its member index; indices must be strictly increasing, so a member counts once.
library SolanaCommittee {
    struct Committee {
        uint64 nonce; // rotation counter; a rotation must increase it by exactly 1
        uint16 threshold; // K
        address[] members; // N, strictly increasing
    }

    struct Signatures {
        uint16[] memberIndex; // strictly increasing
        bytes[] sigs; // 65-byte r‖s‖v
    }

    struct Rotation {
        Committee next;
        Signatures sigs; // by the committee being replaced
    }

    bytes32 internal constant ROTATION_TYPEHASH = keccak256("CLPR_SOLANA_COMMITTEE_ROTATION_V1");

    error CommitteeMalformed();
    error CommitteeHashMismatch(bytes32 got, bytes32 want);
    error SignatureArityMismatch();
    error SignerIndexNotIncreasing();
    error SignerIndexOutOfRange(uint256 index);
    error BadSignature(uint256 index);
    error BelowThreshold(uint256 got, uint256 threshold);
    error RotationNonceNotNext(uint64 got, uint64 want);

    /// @notice keccak256(abi.encode(nonce, threshold, members)).
    function hash(Committee memory c) internal pure returns (bytes32) {
        return keccak256(abi.encode(c.nonce, c.threshold, c.members));
    }

    /// @notice Structural rules: non-empty, members strictly increasing and non-zero, and a strict
    ///         majority threshold (2K > N) so two disjoint quorums cannot both sign.
    function requireWellFormed(Committee memory c) internal pure {
        uint256 n = c.members.length;
        if (n == 0 || n > type(uint16).max || c.threshold == 0 || c.threshold > n || 2 * uint256(c.threshold) <= n) {
            revert CommitteeMalformed();
        }
        address prev = address(0);
        for (uint256 i = 0; i < n; i++) {
            if (c.members[i] <= prev) revert CommitteeMalformed();
            prev = c.members[i];
        }
    }

    /// @notice Revert unless at least `c.threshold` distinct members signed `digest`.
    function requireQuorum(Committee memory c, bytes32 digest, Signatures memory s) internal pure {
        uint256 n = s.sigs.length;
        if (n != s.memberIndex.length) revert SignatureArityMismatch();
        if (n < c.threshold) revert BelowThreshold(n, c.threshold);
        uint256 prev;
        for (uint256 i = 0; i < n; i++) {
            uint256 idx = s.memberIndex[i];
            if (i > 0 && idx <= prev) revert SignerIndexNotIncreasing();
            prev = idx;
            if (idx >= c.members.length) revert SignerIndexOutOfRange(idx);
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, s.sigs[i]);
            if (err != ECDSA.RecoverError.NoError || rec != c.members[idx]) revert BadSignature(idx);
        }
    }

    /// @notice Apply `rotations` in order starting from `current` (whose hash the caller has already
    ///         checked). Each step must be signed by the committee it replaces. Returns the final one.
    function applyRotations(Committee memory current, Rotation[] memory rotations, bytes32 chainHash)
        internal
        pure
        returns (Committee memory)
    {
        for (uint256 i = 0; i < rotations.length; i++) {
            Committee memory next = rotations[i].next;
            requireWellFormed(next);
            if (next.nonce != current.nonce + 1) revert RotationNonceNotNext(next.nonce, current.nonce + 1);
            bytes32 digest = keccak256(abi.encode(ROTATION_TYPEHASH, chainHash, hash(current), hash(next)));
            requireQuorum(current, digest, rotations[i].sigs);
            current = next;
        }
        return current;
    }
}
