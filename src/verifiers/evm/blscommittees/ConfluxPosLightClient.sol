// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBlsCommittee as Bls} from "@hiero-ledger/clpr/libraries/proof/blscommittee/ClprBlsCommittee.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprConfluxPos as Pos} from "@hiero-ledger/clpr/libraries/proof/conflux/ClprConfluxPos.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ConfluxPosLightClient
/// @notice Conflux → Hiero finality half: verifies Conflux PoS ledger infos (aggregated BLS
///         signatures of the PoS committee), follows committee rotations across PoS epochs, and
///         authenticates the PoW pivot block that a ledger info finalizes, returning that block's
///         `deferred_state_root` (the state root of epoch `height − 5`, which equals the eSpace
///         `stateRoot` that `eth_getBlockByNumber(height)` reports).
///
///         This contract is not a CLPR bundle verifier (it does not implement the verifier
///         interface): proving a ClprService storage slot under that
///         root needs Conflux's own state-trie proofs (not Ethereum MPT), and no public Conflux RPC
///         serves them; see the README ("Limits and known gaps").
///
/// @dev Signing (conflux-rust `crates/pos`): each validator signs
///      `SEED ‖ BCS(LedgerInfo)` with BLS12-381 min-pk (keys in G1, signatures in G2), hash-to-G2
///      with DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. A ledger info is valid when the
///      signers' voting power is at least the epoch's `quorum_voting_power` (`2·total/3 + 1`).
///
/// @dev Trust anchor (96 B): `abi.encode(bytes32 committeeHash, uint64 epoch, uint64 pivotHeight)`.
///      `committeeHash` commits to the epoch's committee as the relayer passes it (see
///      {committeeHash}); `pivotHeight` is the highest pivot height accepted so far.
///
/// @dev Proof (RLP list):
///      `[committee, transitions[], ledgerInfoBcs, signerBitmap, aggregateSig(256), pivotHeader]`
///      committee: `[keys(n·128), weights[], quorum]` (EIP-2537 G1 keys, BTreeMap order)
///      transition: `[ledgerInfoBcs, signerBitmap, aggregateSig(256), nextKeys(n·128)]`
contract ConfluxPosLightClient {
    bytes internal constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    uint256 internal constant ANCHOR_LENGTH = 96;

    /// @notice Committee hash this deployment trusts at `BOOTSTRAP_EPOCH` (weak-subjectivity checkpoint).
    bytes32 public immutable BOOTSTRAP_COMMITTEE_HASH;
    uint64 public immutable BOOTSTRAP_EPOCH;

    struct Committee {
        bytes keys;
        uint256[] weights;
        uint64 quorum;
    }

    struct Result {
        uint64 epoch;
        uint64 round;
        uint64 pivotHeight;
        bytes32 pivotBlockHash;
        bytes32 deferredStateRoot;
    }

    error InvalidTrustAnchor();
    error InvalidProofShape();
    error CommitteeMismatch();
    error EpochMismatch(uint64 ledgerInfoEpoch, uint64 committeeEpoch);
    error NotEpochChange();
    error NextEpochMismatch(uint64 nextEpoch, uint64 expected);
    error NextKeyMismatch(uint256 index);
    error BelowQuorum(uint256 signedPower, uint64 quorum);
    error NoPivotDecision();
    error PivotHeaderMismatch();
    error PivotHeightMismatch(uint64 headerHeight, uint64 pivotHeight);
    error PivotNotNewer(uint64 pivotHeight, uint64 anchorHeight);
    error NonZeroBlame();

    constructor(bytes32 bootstrapCommitteeHash, uint64 bootstrapEpoch) {
        BOOTSTRAP_COMMITTEE_HASH = bootstrapCommitteeHash;
        BOOTSTRAP_EPOCH = bootstrapEpoch;
    }

    /// @notice The bootstrap trust anchor.
    function bootstrapAnchor() external view returns (bytes memory) {
        return abi.encode(BOOTSTRAP_COMMITTEE_HASH, BOOTSTRAP_EPOCH, uint64(0));
    }

    /// @notice `keccak256(epoch(8) ‖ quorum(8) ‖ keys ‖ weight_0(8) ‖ … ‖ weight_n-1(8))`.
    function committeeHash(uint64 epoch, Committee memory c) public pure returns (bytes32) {
        bytes memory w = new bytes(8 * c.weights.length);
        for (uint256 i = 0; i < c.weights.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes8 x = bytes8(uint64(c.weights[i]));
            assembly ("memory-safe") {
                mstore(add(add(w, 0x20), mul(i, 8)), x)
            }
        }
        return keccak256(abi.encodePacked(epoch, c.quorum, c.keys, w));
    }

    /// @notice Verify the proof against `trustAnchor`: apply the committee transitions, check the
    ///         final ledger info's quorum signature, and authenticate its pivot block header.
    /// @return r The finalized pivot block and its deferred state root.
    /// @return newTrustAnchor The advanced anchor (epoch and pivot height).
    function verifyPivotStateRoot(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (Result memory r, bytes memory newTrustAnchor)
    {
        (bytes32 cHash, uint64 epoch, uint64 lastPivot) = _decodeAnchor(trustAnchor);
        Memory.Slice[] memory p = RLP.decodeList(proof);
        if (p.length != 6) revert InvalidProofShape();

        Committee memory c = _readCommittee(p[0]);
        if (committeeHash(epoch, c) != cHash) revert CommitteeMismatch();
        (c, epoch) = _applyTransitions(c, epoch, RLP.readList(p[1]));

        Pos.LedgerInfo memory li = _verifyLedgerInfo(c, epoch, RLP.readBytes(p[2]), p[3], p[4]);
        if (!li.hasPivot) revert NoPivotDecision();
        if (li.pivotHeight <= lastPivot) revert PivotNotNewer(li.pivotHeight, lastPivot);

        r.epoch = li.epoch;
        r.round = li.round;
        r.pivotHeight = li.pivotHeight;
        r.pivotBlockHash = li.pivotBlockHash;
        r.deferredStateRoot = _pivotStateRoot(RLP.readBytes(p[5]), li.pivotHeight, li.pivotBlockHash);
        newTrustAnchor = abi.encode(committeeHash(epoch, c), epoch, li.pivotHeight);
    }

    /// @notice Catch-up only: apply committee transitions without a pivot block.
    ///         Proof: `[committee, transitions[]]` (at least one transition).
    function verifyEpochChanges(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (bytes memory newTrustAnchor)
    {
        (bytes32 cHash, uint64 epoch, uint64 lastPivot) = _decodeAnchor(trustAnchor);
        Memory.Slice[] memory p = RLP.decodeList(proof);
        if (p.length != 2) revert InvalidProofShape();
        Committee memory c = _readCommittee(p[0]);
        if (committeeHash(epoch, c) != cHash) revert CommitteeMismatch();
        Memory.Slice[] memory ts = RLP.readList(p[1]);
        if (ts.length == 0) revert InvalidProofShape();
        (c, epoch) = _applyTransitions(c, epoch, ts);
        newTrustAnchor = abi.encode(committeeHash(epoch, c), epoch, lastPivot);
    }

    // ── internals ─────────────────────────────────────────────────────────────────────────

    /// @dev Each transition is the last ledger info of epoch `e` (it carries `next_epoch_state`),
    ///      signed by epoch `e`'s committee. The relayer passes the next committee's keys
    ///      uncompressed; each must compress to the certified 48-byte key and lie in G1.
    function _applyTransitions(Committee memory c, uint64 epoch, Memory.Slice[] memory ts)
        internal
        view
        returns (Committee memory, uint64)
    {
        for (uint256 i = 0; i < ts.length; i++) {
            Memory.Slice[] memory t = RLP.readList(ts[i]);
            if (t.length != 4) revert InvalidProofShape();
            Pos.LedgerInfo memory li = _verifyLedgerInfo(c, epoch, RLP.readBytes(t[0]), t[1], t[2]);
            if (!li.hasNextEpochState) revert NotEpochChange();
            Pos.EpochState memory es = li.nextEpochState;
            if (es.epoch != epoch + 1) revert NextEpochMismatch(es.epoch, epoch + 1);

            bytes memory keys = RLP.readBytes(t[3]);
            uint256 n = es.validators.length;
            if (keys.length != n * Bls.G1_LEN) revert InvalidProofShape();
            Bls.requireSubgroup(keys, Bls.G1_LEN);
            uint256[] memory weights = new uint256[](n);
            for (uint256 j = 0; j < n; j++) {
                bytes memory k = Bls.slice(keys, j * Bls.G1_LEN, Bls.G1_LEN);
                if (keccak256(ClprBls12381.compressG1(k)) != keccak256(es.validators[j].publicKey)) {
                    revert NextKeyMismatch(j);
                }
                weights[j] = es.validators[j].votingPower;
            }
            c = Committee({keys: keys, weights: weights, quorum: es.quorumVotingPower});
            epoch = es.epoch;
        }
        return (c, epoch);
    }

    function _verifyLedgerInfo(
        Committee memory c,
        uint64 epoch,
        bytes memory bcs,
        Memory.Slice bitmapItem,
        Memory.Slice sigItem
    ) internal view returns (Pos.LedgerInfo memory li) {
        li = Pos.decodeLedgerInfo(bcs);
        if (li.epoch != epoch) revert EpochMismatch(li.epoch, epoch);
        (bytes memory aggPk, uint256 power) =
            Bls.aggregateByBitmap(c.keys, Bls.G1_LEN, c.weights, RLP.readBytes(bitmapItem));
        if (power < c.quorum) revert BelowQuorum(power, c.quorum);
        bytes memory h = Bls.hashToG2(abi.encodePacked(Pos.LEDGER_INFO_SEED, bcs), DST);
        Bls.verifyMinPk(aggPk, RLP.readBytes(sigItem), h);
    }

    /// @dev keccak256(header RLP) must be the pivot hash; returns `deferred_state_root` (field 5)
    ///      after checking the height (field 1) and that `blame` (field 8) is zero, so the field is
    ///      the block's own deferred state root and not a blame-vector commitment.
    function _pivotStateRoot(bytes memory header, uint64 height, bytes32 blockHash) internal pure returns (bytes32) {
        if (keccak256(header) != blockHash) revert PivotHeaderMismatch();
        Memory.Slice[] memory h = RLP.decodeList(header);
        if (h.length < 14) revert InvalidProofShape();
        uint256 hh = RLP.readUint256(h[1]);
        // forge-lint: disable-next-line(unsafe-typecast)
        if (hh != height) revert PivotHeightMismatch(uint64(hh), height);
        if (RLP.readUint256(h[8]) != 0) revert NonZeroBlame();
        return RLP.readBytes32(h[5]);
    }

    function _readCommittee(Memory.Slice item) internal pure returns (Committee memory c) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 3) revert InvalidProofShape();
        c.keys = RLP.readBytes(f[0]);
        Memory.Slice[] memory w = RLP.readList(f[1]);
        c.weights = new uint256[](w.length);
        for (uint256 i = 0; i < w.length; i++) {
            c.weights[i] = _readU64(w[i]);
        }
        c.quorum = _readU64(f[2]);
    }

    function _readU64(Memory.Slice item) internal pure returns (uint64) {
        uint256 v = RLP.readUint256(item);
        if (v > type(uint64).max) revert InvalidProofShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v);
    }

    function _decodeAnchor(bytes calldata a) internal pure returns (bytes32, uint64, uint64) {
        if (a.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        return abi.decode(a, (bytes32, uint64, uint64));
    }
}
