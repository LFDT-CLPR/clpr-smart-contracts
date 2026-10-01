// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MonadBlake3} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBlake3.sol";
import {MonadBls} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBls.sol";
import {MonadPageProof} from "@hiero-ledger/clpr/libraries/proof/monad/MonadPageProof.sol";
import {MonadValsetRotation} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadValsetRotation.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MonadVerifier
/// @notice Monad → Hiero CLPR verifier: MonadBFT quorum certificates (BLS12-381 aggregate over the
///         epoch's stake-weighted validator set), the 2-chain commit rule, Monad's delayed execution
///         state root (D = 3), MIP-8 page-storage proofs of the ClprService queue, and validator-set
///         rotation proven from the staking precompile's storage. See README.md in this directory.
contract MonadVerifier is ClprEvmBundleVerifier {
    // ── Protocol constants (verified against monad-bft / monad sources; see README) ─────────────

    /// @dev `EXECUTION_DELAY` in monad-bft `monad-node/src/main.rs`: a block with seq_num n carries the
    ///      Ethereum header (and state root) of block n - 3 in `delayed_execution_results`.
    uint64 public constant EXECUTION_DELAY = 3;
    /// @dev `limits::active_valset_size()` in monad `staking/util/constants.hpp`.
    uint256 public constant MAX_VALIDATORS = 200;
    /// @dev `ConsensusBlockHeader` RLP field count (monad-consensus-types `block.rs`).
    uint256 internal constant HEADER_FIELDS = 13;
    /// @dev Signing-domain prefix of a vote (`signing_domain::Vote`).
    bytes internal constant VOTE_PREFIX = "\x0dmonad/vote/1\n";

    /// @dev One validator in a bundle's validator-set blob: EIP-2537 G1 key (128) || stake (32).
    uint256 internal constant VALSET_ENTRY = 160;

    uint256 internal constant KIND_FINALIZED = 0;
    uint256 internal constant KIND_ROTATION = 1;

    uint256 internal constant ANCHOR_LENGTH = 384;

    error InvalidTrustAnchor();
    error InvalidProofShape();
    error InvalidHeader();
    error BlockIdMismatch();
    error NotCommitted();
    error EpochMismatch();
    error ValidatorSetMismatch();
    error InvalidSignerMap();
    error InsufficientStake();
    error DelayedResultMissing();
    error DelayedResultMismatch();
    error RotationNotPending();
    error InvalidValidatorEntry();

    /// @notice Validator-set rotation logic (separate contract: EIP-170 size budget).
    MonadValsetRotation public immutable ROTATION;

    constructor(MonadValsetRotation rotation) {
        ROTATION = rotation;
    }

    // ── IClprVerifier ─────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes is RLP; its first item selects the kind:
    ///      FINALIZED (0): [0, finality, valsetBlob, serviceAccountProof, channelPages, bundleContent,
    ///                      rotationStart, (manifestPages, manifestPreimage)?]
    ///      ROTATION  (1): [1, channelPages, bundleContent, chunk, finalize]
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
        MonadValsetRotation.Anchor memory a = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length == 0) revert InvalidProofShape();
        uint256 kind = RLP.readUint256(p[0]);
        bool changed;

        if (kind == KIND_FINALIZED) {
            if (p.length != 7 && p.length != 9) revert InvalidProofShape();
            bytes memory valset = RLP.readBytes(p[2]);
            (bytes32 stateRoot, uint64 blockNumber) = _verifyFinality(p[1], valset, a.epoch, a.valsetHash);
            bytes32 serviceRoot = _serviceRoot(p[3], stateRoot, ctx.remoteServiceAddress, a.codeHash);
            metadata = _readChannel(p[4], serviceRoot, ctx.channelId);
            messagePayloads = _decodeBundleContent(RLP.readBytes(p[5]));
            if (RLP.readList(p[6]).length != 0) {
                a = ROTATION.start(Memory.toBytes(p[6]), stateRoot, blockNumber, serviceRoot, a);
                changed = true;
            }
            newEndpointManifest = p.length == 9
                ? _readManifest(p[7], serviceRoot, RLP.readBytes(p[8]), ctx.remoteServiceAddress)
                : _absentEndpointManifest();
        } else if (kind == KIND_ROTATION) {
            if (p.length != 5) revert InvalidProofShape();
            if (a.pendingEpoch == 0) revert RotationNotPending();
            metadata = _readChannel(p[1], a.serviceRoot, ctx.channelId);
            messagePayloads = _decodeBundleContent(RLP.readBytes(p[2]));
            if (RLP.readList(p[3]).length != 0) {
                a = ROTATION.chunk(Memory.toBytes(p[3]), a);
                changed = true;
            }
            if (RLP.readList(p[4]).length != 0) {
                a = ROTATION.finalize(Memory.toBytes(p[4]), a);
                changed = true;
            }
            if (!changed) revert InvalidProofShape();
            newEndpointManifest = _absentEndpointManifest();
        } else {
            revert InvalidProofShape();
        }

        if (changed) {
            newTrustAnchor = abi.encode(a);
            newTrustAnchorId = _anchorId(a);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof: RLP [chainId, serviceAddress, codeHash, peerConfigNanos, throttles(5|7), epoch,
    ///      valsetBlob, finality, (keyRegistry)?]. The initial validator set (and the optional key registry,
    ///      which only makes the first rotation cheaper) is the channel's genesis trust, checked off-chain
    ///      against the staking precompile / validators.toml like any light-client bootstrap; `finality` (a
    ///      QC by that set, of that epoch, over a committed block) shows the set is the live one.
    ///      endpointManifestProof: empty, or RLP [finality, serviceAccountProof, manifestPages, preimage]
    ///      — verified with a QC of the configured epoch's validator set.
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
        Memory.Slice[] memory c = RLP.decodeList(configProofBytes);
        if (c.length != 8 && c.length != 9) revert InvalidProofShape();
        serviceAddress = RLP.readBytes(c[1]);
        _toAddress(serviceAddress); // length check
        MonadValsetRotation.Anchor memory a;
        a.codeHash = RLP.readBytes32(c[2]);
        a.epoch = uint64(RLP.readUint256(c[5]));
        bytes memory valset = RLP.readBytes(c[6]);
        _validatorCount(valset);
        a.valsetHash = keccak256(valset);
        // The configured set must certify a committed block: its keys, stakes and epoch are live.
        _verifyFinality(c[7], valset, a.epoch, a.valsetHash);
        if (c.length == 9) a.keysHash = keccak256(RLP.readBytes(c[8])); // optional key registry

        throttles = _decodeThrottles(c[4]);
        chainId = string(RLP.readBytes(c[0]));
        // forge-lint: disable-next-line(unsafe-typecast)
        peerConfigNanos = uint96(RLP.readUint256(c[3]));
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        initialTrustAnchor = abi.encode(a);
        initialTrustAnchorId = _anchorId(a);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            Memory.Slice[] memory m = RLP.decodeList(endpointManifestProofBytes);
            if (m.length != 4) revert InvalidProofShape();
            (bytes32 stateRoot,) = _verifyFinality(m[0], valset, a.epoch, a.valsetHash);
            bytes32 serviceRoot = _serviceRoot(m[1], stateRoot, serviceAddress, a.codeHash);
            endpointManifest = _readManifest(m[2], serviceRoot, RLP.readBytes(m[3]), serviceAddress);
        }
    }

    // ── Finality: QC + 2-chain commit + delayed execution result ──────────────

    /// @notice Verify that a block P is final and return the Ethereum state root it attests.
    /// @dev `fin` = [headerP, headerB, qcOnB, signature]:
    ///        headerP, headerB  raw RLP `ConsensusBlockHeader`s (as byte strings), B the child of P;
    ///        qcOnB             the RLP `QuorumCertificate` on B (B's child carries it as `header.qc`);
    ///        signature         qcOnB's aggregate signature, uncompressed (256-byte EIP-2537 G2).
    ///      Checks, mirroring monad-bft:
    ///        - BlockId = blake3(rlp(header)); qcOnB.vote.id == id(B); B.qc.vote.id == id(P);
    ///        - commit rule (`QuorumCertificate::get_committable_id`): qcOnB.round == B.qc.round + 1
    ///          ⇒ P is committed;
    ///        - QC signature (`verify_qc`): BLS fast-aggregate-verify of PREFIX || rlp(vote) by the
    ///          signers in the bitmap, whose stake must be ≥ ⌊2·total/3⌋ + 1
    ///          (`has_super_majority_votes`); vote.epoch must be the anchor's epoch;
    ///        - delayed execution: P.delayed_execution_results == [EthHeader(P.seq_num - 3)]; its
    ///          state_root is the post-state of that block. Honest voters only vote for blocks whose
    ///          delayed result equals their own execution (`EthBlockPolicy::check_coherency`).
    function _verifyFinality(Memory.Slice fin, bytes memory valset, uint64 epoch, bytes32 valsetHash)
        internal
        view
        returns (bytes32 stateRoot, uint64 blockNumber)
    {
        if (keccak256(valset) != valsetHash) revert ValidatorSetMismatch();
        Memory.Slice[] memory f = RLP.readList(fin);
        if (f.length != 4) revert InvalidProofShape();
        bytes memory hP = RLP.readBytes(f[0]);
        bytes memory hB = RLP.readBytes(f[1]);

        // B: its QC certifies P.
        uint256 roundOfP;
        {
            Memory.Slice[] memory b = RLP.decodeList(hB);
            if (b.length != HEADER_FIELDS) revert InvalidHeader();
            Memory.Slice[] memory voteOnP = RLP.readList(RLP.readList(b[2])[0]);
            if (voteOnP.length != 3) revert InvalidHeader();
            if (RLP.readBytes32(voteOnP[0]) != MonadBlake3.hash(hP)) revert BlockIdMismatch();
            roundOfP = RLP.readUint256(voteOnP[1]);
        }

        // QC on B.
        Memory.Slice[] memory qc = RLP.readList(f[2]);
        if (qc.length != 2) revert InvalidProofShape();
        {
            Memory.Slice[] memory vote = RLP.readList(qc[0]);
            if (vote.length != 3) revert InvalidProofShape();
            if (RLP.readBytes32(vote[0]) != MonadBlake3.hash(hB)) revert BlockIdMismatch();
            if (RLP.readUint256(vote[1]) != roundOfP + 1) revert NotCommitted();
            if (RLP.readUint256(vote[2]) != epoch) revert EpochMismatch();
        }
        _verifyQcSignature(qc, RLP.readBytes(f[3]), valset);

        // P: delayed execution result.
        Memory.Slice[] memory hdr = RLP.decodeList(hP);
        if (hdr.length != HEADER_FIELDS) revert InvalidHeader();
        Memory.Slice[] memory delayed = RLP.readList(hdr[7]);
        if (delayed.length != 1) revert DelayedResultMissing();
        Memory.Slice[] memory eth = RLP.readList(delayed[0]);
        if (eth.length < 15) revert InvalidHeader();
        stateRoot = RLP.readBytes32(eth[3]);
        blockNumber = uint64(RLP.readUint256(eth[8]));
        if (uint256(blockNumber) + EXECUTION_DELAY != RLP.readUint256(hdr[4])) revert DelayedResultMismatch();
    }

    /// @notice Verify a QC's aggregate BLS signature and stake supermajority against `valset`.
    /// @param qc       decoded `QuorumCertificate` items [vote, signatures].
    /// @param sig      uncompressed (256-byte) form of the aggregate signature.
    /// @param valset   bundle validator-set blob (n × (G1 key 128 || stake 32)) in BTreeMap order.
    function _verifyQcSignature(Memory.Slice[] memory qc, bytes memory sig, bytes memory valset) internal view {
        Memory.Slice[] memory sc = RLP.readList(qc[1]);
        if (sc.length != 2) revert InvalidSignerMap();
        MonadBls.requireCompressedG2(sig, RLP.readBytes(sc[1]));
        Memory.Slice[] memory sm = RLP.readList(sc[0]);
        if (sm.length != 2) revert InvalidSignerMap();
        uint256 n = _validatorCount(valset);
        if (RLP.readUint256(sm[0]) != n) revert InvalidSignerMap();
        bytes memory bitmap = RLP.readBytes(sm[1]);
        if (bitmap.length != (n + 7) / 8) revert InvalidSignerMap();

        // Aggregate signer keys with BLS12_G1ADD into buf[0..128); tally stake.
        bytes memory buf = new bytes(256);
        uint256 total;
        uint256 signed;
        uint256 nb = bitmap.length;
        for (uint256 i = 0; i < n; ++i) {
            uint256 stake;
            uint256 entry;
            assembly ("memory-safe") {
                entry := add(add(valset, 0x20), mul(i, 160))
                stake := mload(add(entry, 128))
            }
            total += stake;
            uint256 pos = n - 1 - i; // validator 0 is the most significant bit (SignerMap encoding)
            if ((uint8(bitmap[nb - 1 - pos / 8]) >> (pos % 8)) & 1 == 0) continue;
            signed += stake;
            bool ok;
            assembly ("memory-safe") {
                let d := add(buf, 0x20)
                mcopy(add(d, 128), entry, 128)
                ok := staticcall(gas(), 0x0b, d, 256, d, 128)
            }
            if (!ok) revert MonadBls.BlsPrecompileFailed();
        }
        if (signed < (total * 2) / 3 + 1) revert InsufficientStake();
        bytes memory apk = new bytes(128);
        assembly ("memory-safe") {
            mcopy(add(apk, 0x20), add(buf, 0x20), 128)
        }
        MonadBls.verify(apk, sig, abi.encodePacked(VOTE_PREFIX, Memory.toBytes(qc[0])));
    }

    // ── Storage reads (MIP-8 pages) ───────────────────────────────────────────

    function _readChannel(Memory.Slice pagesItem, bytes32 serviceRoot, bytes32 channelId)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory)
    {
        return _buildQueueMetadata(MonadPageProof.readSlots(pagesItem, serviceRoot, _channelMetadataSlots(channelId)));
    }

    /// @dev Endpoint-manifest commitment (slot 18) from page proofs, bound to `preimage`.
    function _readManifest(
        Memory.Slice pagesItem,
        bytes32 serviceRoot,
        bytes memory preimage,
        bytes memory expectedServiceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory manifest) {
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT);
        if (keccak256(preimage) != MonadPageProof.readSlots(pagesItem, serviceRoot, slots)[0]) {
            revert ManifestCommitmentMismatch();
        }
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev ClprService storage root from its account proof, pinning the code hash.
    function _serviceRoot(Memory.Slice proofList, bytes32 stateRoot, bytes memory service, bytes32 codeHash)
        internal
        pure
        returns (bytes32 storageRoot)
    {
        bytes32 actual;
        (storageRoot, actual) = MonadPageProof.account(proofList, stateRoot, _toAddress(service));
        if (actual != codeHash) revert CodeHashMismatch();
    }

    function _validatorCount(bytes memory valset) internal pure returns (uint256 n) {
        if (valset.length == 0 || valset.length % VALSET_ENTRY != 0) revert InvalidValidatorEntry();
        n = valset.length / VALSET_ENTRY;
        if (n > MAX_VALIDATORS) revert InvalidValidatorEntry();
    }

    function _decodeAnchor(bytes calldata t) internal pure returns (MonadValsetRotation.Anchor memory a) {
        if (t.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a = abi.decode(t, (MonadValsetRotation.Anchor));
        if (a.valsetHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _anchorId(MonadValsetRotation.Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.epoch, a.pendingEpoch, a.pendingProven);
    }

    function _decodeThrottles(Memory.Slice item) internal pure returns (ClprTypes.Throttles memory t) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 5 && f.length != 7) revert InvalidProofShape();
        // forge-lint: disable-start(unsafe-typecast)
        t.maxMessagesPerBundle = uint32(RLP.readUint256(f[0]));
        t.maxMessagePayloadBytes = uint64(RLP.readUint256(f[1]));
        t.maxGasPerMessage = uint64(RLP.readUint256(f[2]));
        t.maxQueueDepth = uint32(RLP.readUint256(f[3]));
        t.maxSyncBytes = uint64(RLP.readUint256(f[4]));
        if (f.length == 7) {
            t.maxLocalEndpoints = uint32(RLP.readUint256(f[5]));
            t.maxPeerEndpoints = uint32(RLP.readUint256(f[6]));
        }
        // forge-lint: disable-end(unsafe-typecast)
    }

    /// @notice Stand-alone QC check against a validator-set blob (used by the live-data fixture and
    ///         tooling). Same code path as bundle verification.
    /// @param qcRlp raw RLP `QuorumCertificate`.
    function verifyQuorumCertificate(bytes calldata qcRlp, bytes calldata signature, bytes calldata valset)
        external
        view
        returns (bytes32 blockId, uint64 round, uint64 epoch)
    {
        Memory.Slice[] memory qc = RLP.decodeList(qcRlp);
        if (qc.length != 2) revert InvalidProofShape();
        Memory.Slice[] memory vote = RLP.readList(qc[0]);
        if (vote.length != 3) revert InvalidProofShape();
        _verifyQcSignature(qc, signature, valset);
        blockId = RLP.readBytes32(vote[0]);
        round = uint64(RLP.readUint256(vote[1]));
        epoch = uint64(RLP.readUint256(vote[2]));
    }

    /// @notice BlockId of a raw RLP consensus header (blake3), for tooling.
    function consensusBlockId(bytes calldata headerRlp) external pure returns (bytes32) {
        return MonadBlake3.hash(headerRlp);
    }
}
