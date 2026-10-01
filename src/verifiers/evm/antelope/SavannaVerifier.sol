// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {AntelopeBls} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeBls.sol";
import {AntelopeClprBase} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeClprBase.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title SavannaVerifier
/// @notice Antelope Savanna (Spring 1.x) → Hiero `IClprVerifier`: a finalizer-policy light client
///         that checks strong BLS quorum certificates and proves CLPR action receipts.
///         Serves Vaulta (formerly EOS) and Telos, both on Savanna with 21 finalizers, threshold 15
///         (get_finalizer_info, 2026-10-01).
///
/// @dev Chain of evidence (AntelopeIO/spring v1.2.2):
///      1. QC. A strong QC on block C: finalizers of C's active policy whose weight reaches the
///         threshold all signed C's finality digest (strong votes only; `qc_sig_t::is_strong`).
///         The aggregate G2 signature is checked against the sum of their G1 keys.
///      2. Finality digest (`block_header_state::compute_finality_digest`):
///           sha256(major=1, minor=0, active_gen, last_pending_gen, finality_mroot, l2)
///           l2 = sha256(last_pending_policy_digest, last_pending_start_timestamp, l3_digest)
///         last_pending_policy_digest is the pending policy's digest, or the active one's when none
///         is pending, so l2 also binds the policy the verifier holds. l3 is carried as a digest.
///      3. Finality. C's finality_mroot is the root of the Validation Tree of C's latest QC claim Q
///         (`get_finality_mroot_claim`). A strong QC on C makes Q final: a block that claims that QC
///         strongly sets last_final = link(C).target = Q (`finality_core::get_new_block_numbers`,
///         the two-chain rule). Every leaf of that tree is a final block.
///      4. Finality leaf (`valid_t::finality_leaf_node_t`):
///           sha256(major=1, minor=0, block_num, timestamp, parent_timestamp, finality_digest, action_mroot)
///         Merkle-proven into finality_mroot (`calculate_merkle`: promote-odd SHA-256 tree).
///      5. Action receipt: `digest_savanna` Merkle-proven into the leaf's action_mroot.
///
///      Policy rotation: when C carries a pending policy P' (last_pending_gen != active_gen) its QC
///      must also be strong under P' (`qc_t::verify_basic`), and P' is recorded as pending. A later
///      proof whose active_gen equals P'.generation promotes it; the old policy is then dropped.
///      A pending policy becomes pending only once the block that proposed it is final, so it is
///      canonical even though C itself need not be final.
///
///      Trust anchor: abi.encode(uint32 activeGen, bytes32 activeDigest, uint32 pendingGen,
///      bytes32 pendingDigest); policy digest = sha256(pack(finalizer_policy)). The packed policies
///      ride in the proof.
///
///      Bundle proof: RLP([
///        0 activePolicy   packed finalizer_policy matching the anchor,
///        1 pendingPolicy  packed policy matching anchor.pending, or "" when the anchor has none,
///        2 rotations      [FinalityProof, ...] applied in order,
///        3 finality       FinalityProof whose finality_mroot holds the target block,
///        4 block          BlockProof,
///        5 action         ActionProof of `queuestate`,
///        6 bundleContent  ClprBundleContent protobuf,
///        7 manifest       ClprEndpointManifest protobuf preimage, or ""
///      ])
///      FinalityProof = [activeGen, lastPendingGen, finalityMroot, lastPendingStartTimestamp, l3Digest,
///                       activeQc, pendingPolicy | "", pendingQc | []]   Qc = [bitset, sig192]
///      BlockProof    = [blockNum, timestamp, parentTimestamp, finalityDigest, index, count, siblings]
///      ActionProof   = [actionBase, data, returnValue, receiver, recvSequence, witnessHash,
///                       index, count, siblings]
///      bitset: bit i (byte i/8, bit i%8, LSB first) = finalizer i of the policy voted strong.
contract SavannaVerifier is AntelopeClprBase {
    uint32 internal constant LIGHT_HEADER_MAJOR = 1;
    uint32 internal constant LIGHT_HEADER_MINOR = 0;
    uint256 public constant MAX_FINALIZERS = 128;
    uint256 internal constant TRUST_ANCHOR_LENGTH = 128;
    uint256 internal constant BUNDLE_FIELDS = 8;
    uint256 internal constant FINALITY_FIELDS = 8;

    struct Policy {
        uint32 generation;
        uint64 threshold;
        bytes32 digest;
        bytes pack;
        uint256[] keyOffsets;
        uint64[] weights;
    }

    struct PolicyState {
        Policy active;
        Policy pending;
        bool hasPending;
        bool changed;
    }

    error InvalidTrustAnchor();
    error PolicyMalformed();
    error PolicyMismatch();
    error PolicyThresholdUnsafe(uint64 threshold, uint256 totalWeight);
    error UnknownPolicyGeneration(uint32 generation);
    error PendingPolicyUnexpected();
    error PendingPolicyConflict(uint32 generation);
    error QcBitsetMalformed();
    error QcBelowThreshold(uint256 weight, uint64 threshold);
    error FinalityRootMismatch();
    error ActionRootMismatch();
    error ZeroRoot();

    constructor(string memory chainId) AntelopeClprBase(chainId) {}

    // ── IClprVerifier ─────────────────────────────────────────────────────────

    /// @notice IClprVerifier.verifyBundle.
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS) revert InvalidPayloadShape();

        PolicyState memory st = _loadAnchor(trustAnchor, RLP.readBytes(p[0]), RLP.readBytes(p[1]));

        Memory.Slice[] memory rotations = RLP.readList(p[2]);
        for (uint256 i = 0; i < rotations.length; ++i) {
            _verifyFinality(rotations[i], st);
        }
        bytes32 finalityMroot = _verifyFinality(p[3], st);
        ProvenAction memory a = _verifyActionInFinalBlock(p[4], p[5], finalityMroot);

        bytes32 manifestCommitment;
        (metadata, manifestCommitment) = _queueState(a, ctx);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[6]));

        bytes memory manifestPreimage = RLP.readBytes(p[7]);
        newEndpointManifest = manifestPreimage.length == 0
            ? _absentEndpointManifest()
            : _bindManifest(manifestPreimage, manifestCommitment, ctx.remoteServiceAddress);

        if (st.changed) (newTrustAnchor, newTrustAnchorId) = _encodeAnchor(st);
    }

    /// @notice IClprVerifier.verifyConfig.
    /// @dev configProof = RLP([activePolicy, FinalityProof, BlockProof, ActionProof of `ledgerconfig`]).
    ///      The policy is the channel's weak-subjectivity input; the QC must verify under it.
    ///      endpointManifestProof = RLP([FinalityProof, BlockProof, ActionProof of `manifest`]) or "",
    ///      verified against the same initial policy.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        bytes memory cfgMem = configProofBytes;
        Memory.Slice[] memory c = RLP.decodeList(cfgMem);
        if (c.length != 4) revert InvalidPayloadShape();

        PolicyState memory st;
        st.active = _parsePolicy(RLP.readBytes(c[0]));
        bytes32 root = _verifyFinality(c[1], st);
        ClprTypes.LedgerConfiguration memory lc = _ledgerConfig(_verifyActionInFinalBlock(c[2], c[3], root));
        serviceAddress = lc.serviceAddress;

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            bytes memory mMem = endpointManifestProofBytes;
            Memory.Slice[] memory m = RLP.decodeList(mMem);
            if (m.length != 3) revert InvalidPayloadShape();
            PolicyState memory mst;
            mst.active = st.active;
            bytes32 mRoot = _verifyFinality(m[0], mst);
            endpointManifest = _manifestAction(_verifyActionInFinalBlock(m[1], m[2], mRoot), serviceAddress);
        }

        (initialTrustAnchor, initialTrustAnchorId) = _encodeAnchor(st);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            initialTrustAnchor,
            initialTrustAnchorId,
            endpointManifest
        );
    }

    // ── Finality ──────────────────────────────────────────────────────────────

    /// @dev Verify one FinalityProof against (and update) the policy state; returns finality_mroot.
    function _verifyFinality(Memory.Slice item, PolicyState memory st) internal view returns (bytes32 finalityMroot) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != FINALITY_FIELDS) revert InvalidPayloadShape();
        uint32 activeGen = _u32(f[0]);
        uint32 lastPendingGen = _u32(f[1]);
        finalityMroot = _b32(f[2]);
        if (finalityMroot == bytes32(0)) revert ZeroRoot();

        if (activeGen != st.active.generation) {
            if (!st.hasPending || activeGen != st.pending.generation) revert UnknownPolicyGeneration(activeGen);
            st.active = st.pending;
            st.hasPending = false;
            st.changed = true;
        }

        bytes memory pendingPack = RLP.readBytes(f[6]);
        Memory.Slice[] memory pendingQc = RLP.readList(f[7]);
        Policy memory pend;
        bytes32 lastPendingDigest;
        if (lastPendingGen == activeGen) {
            if (pendingPack.length != 0 || pendingQc.length != 0) revert PendingPolicyUnexpected();
            lastPendingDigest = st.active.digest;
        } else {
            if (lastPendingGen < activeGen) revert UnknownPolicyGeneration(lastPendingGen);
            pend = _parsePolicy(pendingPack);
            if (pend.generation != lastPendingGen) revert PolicyMismatch();
            lastPendingDigest = pend.digest;
        }

        bytes32 l2 = sha256(abi.encodePacked(lastPendingDigest, AntelopeLib.le32(_u32(f[3])), _b32(f[4])));
        bytes32 digest = sha256(
            abi.encodePacked(
                AntelopeLib.le32(LIGHT_HEADER_MAJOR),
                AntelopeLib.le32(LIGHT_HEADER_MINOR),
                AntelopeLib.le32(activeGen),
                AntelopeLib.le32(lastPendingGen),
                finalityMroot,
                l2
            )
        );

        _verifyStrongQc(st.active, RLP.readList(f[5]), digest);
        if (lastPendingGen != activeGen) {
            _verifyStrongQc(pend, pendingQc, digest);
            if (st.hasPending) {
                if (pend.generation < st.pending.generation) revert PendingPolicyConflict(pend.generation);
                if (pend.generation == st.pending.generation) {
                    if (pend.digest != st.pending.digest) revert PendingPolicyConflict(pend.generation);
                    return finalityMroot;
                }
            }
            st.pending = pend;
            st.hasPending = true;
            st.changed = true;
        }
    }

    /// @dev Strong QC: the finalizers marked in `bitset` reach the threshold and their aggregate key
    ///      verifies `sig` over `digest`.
    function _verifyStrongQc(Policy memory pol, Memory.Slice[] memory qc, bytes32 digest) internal view {
        if (qc.length != 2) revert InvalidPayloadShape();
        bytes memory bitset = RLP.readBytes(qc[0]);
        uint256 n = pol.weights.length;
        if (bitset.length != (n + 7) / 8) revert QcBitsetMalformed();
        if (n % 8 != 0 && uint8(bitset[bitset.length - 1]) >> (n % 8) != 0) revert QcBitsetMalformed();

        uint256 weight;
        bytes memory agg;
        for (uint256 i = 0; i < n; ++i) {
            if ((uint8(bitset[i >> 3]) >> (i & 7)) & 1 == 0) continue;
            weight += pol.weights[i];
            bytes memory key = AntelopeBls.g1FromSpring(pol.pack, pol.keyOffsets[i]);
            agg = agg.length == 0 ? key : AntelopeBls.g1Add(agg, key);
        }
        if (weight < pol.threshold) revert QcBelowThreshold(weight, pol.threshold);
        AntelopeBls.verify(agg, abi.encodePacked(digest), AntelopeBls.g2FromSpring(RLP.readBytes(qc[1])));
    }

    // ── Block and action inclusion ────────────────────────────────────────────

    /// @dev Prove an action receipt in a block whose finality leaf is in `finalityMroot`.
    function _verifyActionInFinalBlock(Memory.Slice blockItem, Memory.Slice actionItem, bytes32 finalityMroot)
        internal
        pure
        returns (ProvenAction memory a)
    {
        Memory.Slice[] memory ap = RLP.readList(actionItem);
        if (ap.length != 9) revert InvalidPayloadShape();
        bytes32 actDigest;
        (a, actDigest) = _action(_u64(ap[3]), RLP.readBytes(ap[0]), RLP.readBytes(ap[1]), RLP.readBytes(ap[2]));
        bytes32 receipt =
            AntelopeLib.savannaReceiptDigest(a.receiver, _u64(ap[4]), a.account, a.name, actDigest, _b32(ap[5]));
        bytes32 actionMroot =
            AntelopeLib.savannaMerkleRoot(receipt, RLP.readUint256(ap[6]), RLP.readUint256(ap[7]), _b32s(ap[8]));

        Memory.Slice[] memory bp = RLP.readList(blockItem);
        if (bp.length != 7) revert InvalidPayloadShape();
        bytes32 leaf = sha256(
            abi.encodePacked(
                AntelopeLib.le32(LIGHT_HEADER_MAJOR),
                AntelopeLib.le32(LIGHT_HEADER_MINOR),
                AntelopeLib.le32(_u32(bp[0])),
                AntelopeLib.le32(_u32(bp[1])),
                AntelopeLib.le32(_u32(bp[2])),
                _b32(bp[3]),
                actionMroot
            )
        );
        bytes32 root = AntelopeLib.savannaMerkleRoot(leaf, RLP.readUint256(bp[4]), RLP.readUint256(bp[5]), _b32s(bp[6]));
        if (root != finalityMroot) revert FinalityRootMismatch();
    }

    // ── Policies ──────────────────────────────────────────────────────────────

    /// @dev Parse a packed `finalizer_policy` (generation u32, threshold u64, vector of
    ///      {description string, weight u64, public_key (varint 96 + 96 bytes)}).
    function _parsePolicy(bytes memory pack) internal pure returns (Policy memory pol) {
        pol.pack = pack;
        pol.digest = sha256(pack);
        pol.generation = AntelopeLib.readU32(pack, 0);
        pol.threshold = AntelopeLib.readU64(pack, 4);
        (uint256 n, uint256 off) = AntelopeLib.readVarUint(pack, 12);
        if (n == 0 || n > MAX_FINALIZERS) revert PolicyMalformed();
        pol.keyOffsets = new uint256[](n);
        pol.weights = new uint64[](n);
        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            uint256 len;
            (len, off) = AntelopeLib.readVarUint(pack, off);
            off += len;
            pol.weights[i] = AntelopeLib.readU64(pack, off);
            total += pol.weights[i];
            (len, off) = AntelopeLib.readVarUint(pack, off + 8);
            if (len != 96 || off + 96 > pack.length) revert PolicyMalformed();
            pol.keyOffsets[i] = off;
            off += 96;
        }
        if (off != pack.length) revert PolicyMalformed();
        // BFT safety for this light client needs a > 2/3 threshold (Spring itself only enforces > 1/2).
        if (pol.threshold > total || uint256(pol.threshold) * 3 <= total * 2) {
            revert PolicyThresholdUnsafe(pol.threshold, total);
        }
    }

    function _loadAnchor(bytes calldata anchor, bytes memory activePack, bytes memory pendingPack)
        internal
        pure
        returns (PolicyState memory st)
    {
        if (anchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (uint32 activeGen, bytes32 activeDigest, uint32 pendingGen, bytes32 pendingDigest) =
            abi.decode(anchor, (uint32, bytes32, uint32, bytes32));
        st.active = _parsePolicy(activePack);
        if (st.active.generation != activeGen || st.active.digest != activeDigest) revert PolicyMismatch();
        if (pendingGen != 0) {
            st.pending = _parsePolicy(pendingPack);
            if (st.pending.generation != pendingGen || st.pending.digest != pendingDigest) revert PolicyMismatch();
            st.hasPending = true;
        } else if (pendingPack.length != 0) {
            revert PendingPolicyUnexpected();
        }
    }

    function _encodeAnchor(PolicyState memory st) internal pure returns (bytes memory anchor, bytes memory id) {
        anchor = abi.encode(
            st.active.generation,
            st.active.digest,
            st.hasPending ? st.pending.generation : uint32(0),
            st.hasPending ? st.pending.digest : bytes32(0)
        );
        id = abi.encodePacked(st.active.generation);
    }
}
