// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateVerifierErrors} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateVerifierErrors.sol";

/// @title GrandpaLightClient
/// @notice The GRANDPA half of the Substrate solo-chain verifiers: a sequential light client that
///         follows `ScheduledChange` set rotations from a trust anchor and returns the state root of
///         the last justified block. The state layer on top differs per verifier: Frontier EVM
///         storage (`GrandpaVerifier`) or a native pallet's storage (`GrandpaPalletVerifier`).
///
/// ## Trust anchor (44 bytes)
///   setId(u64 BE) ‖ authoritiesHash(32) ‖ minHeight(u32 BE)
///   `authoritiesHash` = keccak256 of the packed GRANDPA authority list (key(32) ‖ weight(u64 LE))*;
///   the set `setId` justifies blocks at or above `minHeight`.
///
/// ## Verification chain (_applySteps)
///   For each step (in order, all but the last must change the authority set):
///     1. The supplied authority list must hash to the working anchor.
///     2. headers[0] is the justified block J (number ≥ minHeight); headers[k+1] is the parent of
///        headers[k]; the last header may carry a GRANDPA `ScheduledChange`.
///     3. The GRANDPA commit for (blake2_256(J), J.number) under (round, setId) must reach the
///        2/3+ weight threshold of the working set ({_checkCommit}).
///     4. ScheduledChange{next, delay} signalled at block N (J ≤ N + delay): the working anchor
///        becomes (setId + 1, keccak256(next), N + delay + 1). A `ForcedChange` reverts.
abstract contract GrandpaLightClient is SubstrateVerifierErrors {
    /// @dev One GRANDPA finality step. `votes`/`ancestry` are the re-packed justification (GrandpaLib).
    struct Step {
        bytes[] headers;
        uint64 round;
        bytes votes;
        bytes[] ancestry;
        bytes authorities;
    }

    struct Anchor {
        uint64 setId;
        bytes32 authoritiesHash;
        uint32 minHeight;
    }

    uint256 internal constant ANCHOR_LENGTH = 44;

    IEd25519Verifier public immutable ED25519;
    uint64 public immutable BOOTSTRAP_SET_ID;
    bytes32 public immutable BOOTSTRAP_AUTHORITIES_HASH;
    uint32 public immutable BOOTSTRAP_MIN_HEIGHT;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error AuthoritySetMismatch();
    error BrokenHeaderChain();
    error StepWithoutChange();
    error UnexpectedChange();
    error JustifiedPastChange();

    /// @param ed25519Verifier          Pure-Solidity Ed25519 verifier (no ed25519 precompile on Hedera).
    /// @param bootstrapSetId           Weak-subjectivity checkpoint: GRANDPA set id …
    /// @param bootstrapAuthoritiesHash … keccak256 of its packed authority list …
    /// @param bootstrapMinHeight       … and the first block number it justifies.
    constructor(
        address ed25519Verifier,
        uint64 bootstrapSetId,
        bytes32 bootstrapAuthoritiesHash,
        uint32 bootstrapMinHeight
    ) {
        if (ed25519Verifier == address(0) || bootstrapAuthoritiesHash == bytes32(0)) {
            revert InvalidProfile();
        }
        ED25519 = IEd25519Verifier(ed25519Verifier);
        BOOTSTRAP_SET_ID = bootstrapSetId;
        BOOTSTRAP_AUTHORITIES_HASH = bootstrapAuthoritiesHash;
        BOOTSTRAP_MIN_HEIGHT = bootstrapMinHeight;
    }

    /// @dev Checks one GRANDPA commit against the (anchor-checked) authority list. Default: every
    ///      vote is in the step and verified here.
    function _checkCommit(GrandpaLib.Commit memory c, bytes memory authorities) internal view virtual {
        GrandpaLib.verifyCommit(c, authorities, ED25519);
    }

    /// @dev Applies the finality steps; returns the working anchor and the last justified block's
    ///      state root and number.
    function _applySteps(Step[] memory steps, Anchor memory a)
        internal
        view
        returns (Anchor memory, bytes32 stateRoot, uint32 number)
    {
        if (steps.length == 0) revert InvalidPayloadShape();
        for (uint256 i; i < steps.length; ++i) {
            Step memory s = steps[i];
            if (s.headers.length == 0) revert InvalidPayloadShape();
            if (GrandpaLib.authoritiesHash(s.authorities) != a.authoritiesHash) revert AuthoritySetMismatch();

            SubstrateHeader.Header memory j = SubstrateHeader.decode(s.headers[0]);
            if (j.number < a.minHeight) revert HeightTooOld();

            // Parent-linked chain J → … → signal header; only the last header may signal a change.
            SubstrateHeader.Header memory h = j;
            SubstrateHeader.GrandpaChange memory change;
            uint256 last = s.headers.length - 1;
            for (uint256 k; k <= last; ++k) {
                if (k > 0) {
                    if (SubstrateHeader.hash(s.headers[k]) != h.parentHash) revert BrokenHeaderChain();
                    h = SubstrateHeader.decode(s.headers[k]);
                }
                change = SubstrateHeader.grandpaChange(s.headers[k], h);
                if (change.present && k != last) revert UnexpectedChange();
            }
            if (last > 0 && !change.present) revert StepWithoutChange();

            _checkCommit(
                GrandpaLib.Commit({
                    targetHash: SubstrateHeader.hash(s.headers[0]),
                    targetNumber: j.number,
                    round: s.round,
                    setId: a.setId,
                    votes: s.votes,
                    ancestry: s.ancestry
                }),
                s.authorities
            );

            if (change.present) {
                // h is the signal header N. An honest set never finalizes past N + delay.
                uint256 enactedAt = uint256(h.number) + change.delay;
                if (j.number > enactedAt) revert JustifiedPastChange();
                a = Anchor({
                    setId: a.setId + 1,
                    authoritiesHash: ScaleCodec.keccakRange(
                        s.headers[last], change.authoritiesOffset, change.authoritiesLength
                    ),
                    // forge-lint: disable-next-line(unsafe-typecast)
                    minHeight: uint32(enactedAt + 1)
                });
            } else if (i + 1 != steps.length) {
                revert StepWithoutChange();
            }
            stateRoot = j.stateRoot;
            number = j.number;
        }
        return (a, stateRoot, number);
    }

    function _bootstrapAnchor() internal view returns (Anchor memory) {
        return
            Anchor({
                setId: BOOTSTRAP_SET_ID, authoritiesHash: BOOTSTRAP_AUTHORITIES_HASH, minHeight: BOOTSTRAP_MIN_HEIGHT
            });
    }

    // ── Anchor codec ─────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata t) internal pure returns (Anchor memory a) {
        if (t.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.setId = uint64(bytes8(t[0:8]));
        a.authoritiesHash = bytes32(t[8:40]);
        a.minHeight = uint32(bytes4(t[40:44]));
        if (a.authoritiesHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.setId, a.authoritiesHash, a.minHeight);
    }
}
