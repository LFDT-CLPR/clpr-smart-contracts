// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprAlgorandStateProof as SP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprAlgorandStateProof.sol";
import {ClprFalconDet1024Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprFalconDet1024Engine.sol";

/// @title AlgorandStateProofAccumulator
/// @notice Permissionless, multi-transaction light client of Algorand state proofs (go-algorand
///         crypto/stateproof `Verifier.Verify`). One Algorand state proof attests 256 rounds: its message
///         carries the SHA-256 commitment to their light block headers and the SumHash512 commitment to
///         the voters (top online accounts, with Falcon-1024 Merkle-signature keys) who sign the NEXT
///         interval. A proof of interval i is checked against the voters and proven weight of the
///         message of interval i − 1, so intervals are accumulated one after another from a bootstrap
///         message.
///
///         A mainnet proof has about 60 reveals; each needs a deterministic Falcon-1024 verification and
///         about 200 SumHash512 compressions, roughly 9–11 M gas. That does not fit Hedera's 15 M gas in
///         one transaction, so verification is split:
///
///   1. `submitReveals(header, reveals)` — any number of transactions, each verifying some reveals:
///      Falcon signature of the message hash under the ephemeral key; the key's Merkle path to the
///      participant's key commitment (at round lastAttestedRound − lastAttestedRound mod keyLifetime);
///      the signature-slot leaf to `sigCommit`; the participant leaf to the previous message's voters
///      commitment. A verified reveal is stored as (L, weight) under the session id
///      `keccak256(abi.encode(header))`.
///   2. `finalize(header, positions)` — the weight inequality, the SHAKE256 coins, and for every coin j a
///      verified reveal at `positions[j]` with L ≤ coin < L + weight. On success the message is stored
///      as interval (root, lastAttestedRound).
///
///         `root` names an accumulation lineage: the SHA-256 message hash of its bootstrap message.
///         Bootstrapping is permissionless and trusts nothing by itself; a CLPR channel pins one root in
///         its trust anchor (chosen by the governance that completes the channel), and only intervals
///         chained from that root serve its bundles.
contract AlgorandStateProofAccumulator {
    uint64 public constant INTERVAL = 256; // consensus StateProofInterval (v34+)
    uint256 public constant MAX_TREE_DEPTH = 20; // crypto/stateproof MaxTreeDepth
    uint256 public constant MAX_KEY_DEPTH = 16; // merklearray MaxEncodedTreeDepth

    /// @notice {ClprSumHash512Engine}.
    address public immutable SUMHASH;
    /// @notice {ClprShake256Engine}.
    address public immutable SHAKE;
    /// @notice {ClprFalconDet1024Engine}.
    ClprFalconDet1024Engine public immutable FALCON;

    struct Interval {
        bytes32 blockHeadersCommitment;
        bytes32 votersHi;
        bytes32 votersLo;
        uint64 lnProvenWeight;
        uint64 firstAttestedRound;
        uint64 lastAttestedRound;
    }

    /// @notice Everything a session commits to; its keccak256 is the session id.
    struct SessionHeader {
        bytes32 root;
        uint64 prevLastRound; // interval whose voters sign `message`
        SP.Message message;
        bytes sigCommit; // 64 bytes
        uint64 signedWeight;
        uint8 saltVersion; // MerkleSignatureSaltVersion
        uint8 treeDepth; // depth of the signature and participant trees
    }

    struct Reveal {
        uint64 pos;
        uint64 l; // SigSlot.L
        uint64 weight;
        uint64 keyLifetime;
        bytes commitment; // participant's Merkle-signature key commitment (64)
        bytes sigCT; // Falcon signature, CT form (1538)
        bytes vkey; // Falcon ephemeral public key (1793)
        uint64 vcIdx; // VectorCommitmentIndex of the key
        bytes keyPath; // keyDepth × 64, bottom-up
        bytes sigPath; // treeDepth × 64
        bytes partPath; // treeDepth × 64
    }

    mapping(bytes32 root => mapping(uint64 lastRound => Interval)) internal _intervals;
    /// @dev session id → reveal position → 1 << 255 | L << 64 | weight
    mapping(bytes32 session => mapping(uint64 pos => uint256)) internal _revealed;

    event Bootstrapped(bytes32 indexed root, uint64 lastAttestedRound);
    event RevealsVerified(bytes32 indexed session, uint256 count);
    event IntervalAccumulated(bytes32 indexed root, uint64 indexed lastAttestedRound, bytes32 blockHeadersCommitment);

    error InvalidMessage();
    error IntervalExists(bytes32 root, uint64 lastRound);
    error UnknownInterval(bytes32 root, uint64 lastRound);
    error NotNextInterval();
    error BadTreeDepth();
    error BadReveal(uint64 pos, uint8 reason);
    error InsufficientWeight();
    error CoinNotCovered(uint256 j, uint64 pos, uint64 coin);
    error HashEngineFailed();

    constructor(address sumhash, address shake, ClprFalconDet1024Engine falcon) {
        SUMHASH = sumhash;
        SHAKE = shake;
        FALCON = falcon;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Bootstrap and reads
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Start a lineage from a state-proof message (taken as given). Returns its root.
    function bootstrap(SP.Message calldata m) external returns (bytes32 root) {
        _checkShape(m);
        root = SP.messageHash(m);
        _store(root, m);
        emit Bootstrapped(root, m.lastAttestedRound);
    }

    function interval(bytes32 root, uint64 lastRound) external view returns (Interval memory) {
        return _intervals[root][lastRound];
    }

    function sessionId(SessionHeader calldata h) public pure returns (bytes32) {
        return keccak256(abi.encode(h));
    }

    /// @notice Stored (L, weight) of a verified reveal, `found = false` if not verified yet.
    function revealed(bytes32 session, uint64 pos) external view returns (bool found, uint64 l, uint64 weight) {
        uint256 r = _revealed[session][pos];
        return (r >> 255 == 1, uint64(r >> 64), uint64(r));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Step 1: reveals
    // ─────────────────────────────────────────────────────────────────────────

    function submitReveals(SessionHeader calldata h, Reveal[] calldata rs) external {
        Interval storage prev = _prevOf(h);
        bytes memory voters = abi.encodePacked(prev.votersHi, prev.votersLo);
        bytes32 msgHash = SP.messageHash(h.message);
        bytes32 sid = sessionId(h);

        // one SumHash engine call: key, signature and participant jobs of every reveal
        bytes memory jobs;
        for (uint256 i = 0; i < rs.length; i++) {
            jobs = abi.encodePacked(jobs, _jobs(h, rs[i]));
        }
        (bool ok, bytes memory roots) = SUMHASH.staticcall(jobs);
        if (!ok || roots.length != rs.length * 192) revert HashEngineFailed();

        for (uint256 i = 0; i < rs.length; i++) {
            Reveal calldata r = rs[i];
            if (keccak256(_slice64(roots, 192 * i)) != keccak256(r.commitment)) revert BadReveal(r.pos, 1);
            if (keccak256(_slice64(roots, 192 * i + 64)) != keccak256(h.sigCommit)) revert BadReveal(r.pos, 2);
            if (keccak256(_slice64(roots, 192 * i + 128)) != keccak256(voters)) revert BadReveal(r.pos, 3);
            if (!FALCON.verify(r.vkey, r.sigCT, abi.encodePacked(msgHash))) revert BadReveal(r.pos, 4);
            _revealed[sid][r.pos] = (uint256(1) << 255) | (uint256(r.l) << 64) | r.weight;
        }
        emit RevealsVerified(sid, rs.length);
    }

    /// @dev Engine jobs (key, signature slot, participant) of one reveal; shape checks first.
    function _jobs(SessionHeader calldata h, Reveal calldata r) internal pure returns (bytes memory) {
        uint256 depth = h.treeDepth;
        if (
            r.commitment.length != 64 || r.sigCT.length != 1538 || r.vkey.length != 1793 || r.keyLifetime == 0
                || r.keyPath.length % 64 != 0 || r.keyPath.length / 64 > MAX_KEY_DEPTH || r.sigPath.length != depth * 64
                || r.partPath.length != depth * 64 || r.pos >> depth != 0
        ) revert BadReveal(r.pos, 0);
        if (uint8(r.sigCT[1]) != h.saltVersion) revert BadReveal(r.pos, 5);
        uint256 keyDepth = r.keyPath.length / 64;
        if (r.vcIdx >> keyDepth != 0) revert BadReveal(r.pos, 0);
        uint64 last = h.message.lastAttestedRound;
        uint64 keyRound = last - (last % r.keyLifetime);

        bytes memory keyLeaf = abi.encodePacked("KP", uint16(0), SP.le64(keyRound), r.vkey);
        // SingleLeafProof.GetFixedLengthHashableRepresentation: depth ‖ zero digests ‖ path
        bytes memory proofFixed =
            abi.encodePacked(uint8(keyDepth), new bytes(64 * (MAX_KEY_DEPTH - keyDepth)), r.keyPath);
        bytes memory sigLeaf =
            abi.encodePacked("sps", SP.le64(r.l), uint16(0), r.sigCT, r.vkey, SP.le64(r.vcIdx), proofFixed);
        bytes memory partLeaf = abi.encodePacked("spp", SP.le64(r.weight), SP.le64(r.keyLifetime), r.commitment);
        return abi.encodePacked(
            _job(keyLeaf, r.vcIdx, keyDepth, r.keyPath),
            _job(sigLeaf, r.pos, depth, r.sigPath),
            _job(partLeaf, r.pos, depth, r.partPath)
        );
    }

    function _job(bytes memory leaf, uint64 pos, uint256 depth, bytes calldata path)
        private
        pure
        returns (bytes memory)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(uint32(leaf.length), leaf, pos, uint8(depth), path); // depth ≤ 20
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Step 2: coins
    // ─────────────────────────────────────────────────────────────────────────

    function finalize(SessionHeader calldata h, uint64[] calldata positions) external {
        Interval storage prev = _prevOf(h);
        if (!SP.weightsOk(h.signedWeight, prev.lnProvenWeight, positions.length)) revert InsufficientWeight();
        bytes32 sid = sessionId(h);
        uint64[] memory coins = _coins(
            SP.coinSeed(
                abi.encodePacked(prev.votersHi, prev.votersLo),
                prev.lnProvenWeight,
                h.sigCommit,
                h.signedWeight,
                SP.messageHash(h.message)
            ),
            h.signedWeight,
            positions.length
        );
        for (uint256 j = 0; j < positions.length; j++) {
            uint256 r = _revealed[sid][positions[j]];
            uint256 l = uint64(r >> 64);
            if (r >> 255 != 1 || coins[j] < l || coins[j] >= l + uint64(r)) {
                revert CoinNotCovered(j, positions[j], coins[j]);
            }
        }
        _store(h.root, h.message);
        emit IntervalAccumulated(h.root, h.message.lastAttestedRound, h.message.blockHeadersCommitment);
    }

    /// @dev go-algorand `coinGenerator.getNextCoin`: SHAKE256(seed) read as little-endian u64 samples,
    ///      rejected at or above ⌊2^64 / W⌋·W, reduced mod W.
    function _coins(bytes memory seed, uint64 signedWeight, uint256 n) internal view returns (uint64[] memory out) {
        out = new uint64[](n);
        uint256 threshold = ((uint256(1) << 64) / signedWeight) * signedWeight;
        uint256 len = 8 * n + 64;
        for (;;) {
            // forge-lint: disable-next-line(unsafe-typecast)
            (bool ok, bytes memory s) = SHAKE.staticcall(abi.encodePacked(uint8(1), uint32(len), seed)); // len ≤ 2^20
            if (!ok || s.length != len) revert HashEngineFailed();
            uint256 j;
            for (uint256 off = 0; off + 8 <= len && j < n; off += 8) {
                uint256 sample;
                for (uint256 b = 0; b < 8; b++) {
                    sample |= uint256(uint8(s[off + b])) << (8 * b);
                }
                if (sample < threshold) out[j++] = uint64(sample % signedWeight);
            }
            if (j == n) return out;
            len *= 2; // rejection is rare (probability < W / 2^64 per sample); read further
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internals
    // ─────────────────────────────────────────────────────────────────────────

    function _prevOf(SessionHeader calldata h) internal view returns (Interval storage prev) {
        _checkShape(h.message);
        if (h.sigCommit.length != 64) revert InvalidMessage();
        if (h.treeDepth > MAX_TREE_DEPTH) revert BadTreeDepth();
        prev = _intervals[h.root][h.prevLastRound];
        if (prev.lastAttestedRound == 0) revert UnknownInterval(h.root, h.prevLastRound);
        if (
            uint256(h.message.firstAttestedRound) != uint256(h.prevLastRound) + 1
                || uint256(h.message.lastAttestedRound) != uint256(h.prevLastRound) + INTERVAL
        ) revert NotNextInterval();
        if (_intervals[h.root][h.message.lastAttestedRound].lastAttestedRound != 0) {
            revert IntervalExists(h.root, h.message.lastAttestedRound);
        }
    }

    function _checkShape(SP.Message calldata m) internal pure {
        if (
            m.votersCommitment.length != 64 || m.lastAttestedRound == 0 || m.lastAttestedRound % INTERVAL != 0
                || uint256(m.firstAttestedRound) + INTERVAL - 1 != m.lastAttestedRound || m.lnProvenWeight == 0
        ) revert InvalidMessage();
    }

    function _store(bytes32 root, SP.Message calldata m) internal {
        Interval storage s = _intervals[root][m.lastAttestedRound];
        if (s.lastAttestedRound != 0) revert IntervalExists(root, m.lastAttestedRound);
        s.blockHeadersCommitment = m.blockHeadersCommitment;
        s.votersHi = bytes32(m.votersCommitment[0:32]);
        s.votersLo = bytes32(m.votersCommitment[32:64]);
        s.lnProvenWeight = m.lnProvenWeight;
        s.firstAttestedRound = m.firstAttestedRound;
        s.lastAttestedRound = m.lastAttestedRound;
    }

    function _slice64(bytes memory b, uint256 off) private pure returns (bytes memory out) {
        out = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), off), 64)
        }
    }
}
