// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";

/// @title GrandpaCommitAccumulator
/// @notice Verifies the precommits of one GRANDPA commit over several transactions and records the
///         signed weight, for authority sets too large to check in one 15M-gas transaction (each
///         ed25519 signature costs about 585k gas in pure Solidity). Chainflip's set of 139
///         authorities needs about 92 signatures per commit; at most about 23 fit in one call.
///
///         Permissionless and trust-free: every vote is verified against the supplied authority
///         list, and the record is keyed by the hash of that list, so a record only counts for a
///         verifier whose trust anchor already names the same list. A verifier reads
///         {signedWeight} in its `view` path (see `GrandpaPalletVerifier`).
///
///         Record key: keccak256(abi.encode(setId, authoritiesHash, round, targetHash, targetNumber)).
///         Each authority index is counted at most once per key (bitmap); a batch that repeats an
///         already counted index reverts, so retries must drop the votes that landed.
contract GrandpaCommitAccumulator {
    IEd25519Verifier public immutable ED25519;

    /// @notice Signed weight accumulated for a commit key.
    mapping(bytes32 commitKey => uint256 weight) public signedWeight;
    /// @dev Bitmap of counted authority indices per commit key (word = index / 256).
    mapping(bytes32 commitKey => mapping(uint256 word => uint256 bits)) internal _counted;

    event VotesAccumulated(bytes32 indexed commitKey, uint256 addedWeight, uint256 signedWeight);

    error InvalidProfile();
    error AlreadyCounted(uint256 word, uint256 bits);

    constructor(address ed25519Verifier) {
        if (ed25519Verifier == address(0)) revert InvalidProfile();
        ED25519 = IEd25519Verifier(ed25519Verifier);
    }

    /// @notice The record key of a commit.
    function commitKey(uint64 setId, bytes32 authoritiesHash, uint64 round, bytes32 targetHash, uint32 targetNumber)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(setId, authoritiesHash, round, targetHash, targetNumber));
    }

    /// @notice Verifies a batch of precommits (`c.votes`, GrandpaLib's 102-byte format, sorted by
    ///         index) of the commit `(c.round, c.setId, c.targetHash, c.targetNumber)` under the
    ///         authority list `authorities`, and adds their weight to the commit's record.
    /// @return key    The commit key.
    /// @return weight The record's signed weight after this batch.
    function accumulate(GrandpaLib.Commit calldata c, bytes calldata authorities)
        external
        returns (bytes32 key, uint256 weight)
    {
        (uint256 added,, uint256[] memory signers) = GrandpaLib.verifyVotes(c, authorities, ED25519);
        key = commitKey(c.setId, GrandpaLib.authoritiesHash(authorities), c.round, c.targetHash, c.targetNumber);
        mapping(uint256 => uint256) storage counted = _counted[key];
        for (uint256 w; w < signers.length; ++w) {
            uint256 bits = signers[w];
            if (bits == 0) continue;
            uint256 old = counted[w];
            if (old & bits != 0) revert AlreadyCounted(w, old & bits);
            counted[w] = old | bits;
        }
        weight = signedWeight[key] + added;
        signedWeight[key] = weight;
        emit VotesAccumulated(key, added, weight);
    }

    /// @notice True iff authority `index` has been counted for `key`.
    function isCounted(bytes32 key, uint256 index) external view returns (bool) {
        return (_counted[key][index >> 8] >> (index & 255)) & 1 == 1;
    }
}
