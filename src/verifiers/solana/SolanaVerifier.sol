// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {SolanaCommittee} from "@hiero-ledger/clpr/verifiers/solana/SolanaCommittee.sol";
import {AlpenglowCert} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowCert.sol";
import {AlpenglowFinalityVerifier} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowFinalityVerifier.sol";

/// @title SolanaVerifier
/// @notice Solana → Hiero `IClprVerifier`. See README.md in this directory.
///
/// Two modes, chosen by the trust anchor:
///   - ATTESTED (1): the CLPR Solana program's queue state at a rooted slot is signed by K of N
///     committee members. Consensus-agnostic, so it keeps working unchanged across the TowerBFT →
///     Alpenglow migration. Trust: the committee (labelled; bonded and slashable on Solana).
///   - ALPENGLOW (2): as ATTESTED, and the attested `(slot, block_id)` must also carry an Alpenglow
///     finality certificate (BLS12-381 aggregate, EIP-2537) under the epoch's ranked validator set.
///     The committee can then no longer attest to a block that Solana did not finalize. The ranked
///     set itself is committee-signed, because vote-account state is not provable either.
///
/// Neither mode proves account state from Solana consensus; nothing on Solana can (README §1).
contract SolanaVerifier is ClprEvmBundleVerifier {
    uint8 public constant MODE_ATTESTED = 1;
    uint8 public constant MODE_ALPENGLOW = 2;

    bytes32 internal constant QUEUE_TYPEHASH = keccak256("CLPR_SOLANA_QUEUE_ATTESTATION_V1");
    bytes32 internal constant CONFIG_TYPEHASH = keccak256("CLPR_SOLANA_CONFIG_ATTESTATION_V1");
    bytes32 internal constant EPOCH_SET_TYPEHASH = keccak256("CLPR_SOLANA_EPOCH_SET_V1");

    /// @notice Queue state of one CLPR Channel in the Solana CLPR program, at a rooted/finalized slot.
    struct QueueAttestation {
        bytes32 programId; // CLPR program id (the Channel's remoteServiceAddress)
        bytes32 channelId;
        uint64 slot;
        bytes32 blockRef; // ATTESTED: the slot's blockhash; ALPENGLOW: the slot's block_id
        uint8 status;
        uint64 nextMessageId;
        bytes32 sentRunningHash;
        uint64 receivedMessageId;
        bytes32 receivedRunningHash;
        uint64 endpointManifestVersion;
        bytes32 manifestCommitment; // keccak256(encodeEndpointManifest(m)), 0 if none
    }

    struct EpochSetUpdate {
        AlpenglowCert.EpochSet set;
        SolanaCommittee.Signatures sigs;
    }

    struct BundleProof {
        SolanaCommittee.Committee committee; // must hash to the anchor's committee
        SolanaCommittee.Rotation[] rotations;
        EpochSetUpdate[] setUpdates; // ALPENGLOW only
        QueueAttestation attestation;
        SolanaCommittee.Signatures sigs;
        bytes finality; // ALPENGLOW: abi.encode(FinalityProof, EpochSet); ATTESTED: empty
        bytes bundleContent; // ClprBundleContent protobuf
        bytes manifestPreimage; // empty ⇒ no manifest update
    }

    struct ConfigAttestation {
        bytes32 programId;
        uint64 slot;
        uint96 peerConfigNanos;
        ClprTypes.Throttles throttles;
        bytes32 manifestCommitment;
    }

    struct ConfigProof {
        SolanaCommittee.Committee committee; // must hash to GENESIS_COMMITTEE_HASH
        ConfigAttestation attestation;
        SolanaCommittee.Signatures sigs;
        uint8 mode;
        AlpenglowCert.EpochSet[] initialSet; // ALPENGLOW: exactly one; ATTESTED: none
        SolanaCommittee.Signatures setSigs;
    }

    /// @dev abi.encode of this is the trust anchor.
    struct Anchor {
        uint8 mode;
        bytes32 committeeHash;
        uint64 committeeNonce;
        bytes32 prevSetHash; // ALPENGLOW: previous epoch (certificates for its slots still verify)
        bytes32 curSetHash;
        uint64 curEpoch;
    }

    bytes32 public immutable CHAIN_HASH;
    bytes32 public immutable GENESIS_COMMITTEE_HASH;
    /// @notice Finality checker for ALPENGLOW mode; zero for an ATTESTED-only deployment.
    AlpenglowFinalityVerifier public immutable ALPENGLOW;
    string public chainId; // CAIP-2, e.g. solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp

    error UnknownMode(uint8 mode);
    error ProgramIdMismatch();
    error ChannelIdMismatch();
    error InvalidStatus(uint8 status);
    error SetUpdatesNotAllowed();
    error EpochNotIncreasing(uint64 got, uint64 current);
    error UnknownEpochSet(bytes32 setHash);
    error FinalityTargetMismatch();
    error UnexpectedFinalityProof();
    error InitialSetShape();
    error AlpenglowUnavailable();

    constructor(string memory chainId_, bytes32 genesisCommitteeHash, AlpenglowFinalityVerifier alpenglow) {
        chainId = chainId_;
        CHAIN_HASH = keccak256(bytes(chainId_));
        GENESIS_COMMITTEE_HASH = genesisCommitteeHash;
        ALPENGLOW = alpenglow;
    }

    // ── Digests (signed off-chain by committee members) ─────────────────────────

    function queueDigest(bytes32 committeeHash, QueueAttestation memory a) public view returns (bytes32) {
        return keccak256(abi.encode(QUEUE_TYPEHASH, CHAIN_HASH, committeeHash, a));
    }

    function configDigest(bytes32 committeeHash, ConfigAttestation memory a) public view returns (bytes32) {
        return keccak256(abi.encode(CONFIG_TYPEHASH, CHAIN_HASH, committeeHash, a));
    }

    function epochSetDigest(bytes32 committeeHash, AlpenglowCert.EpochSet memory s) public view returns (bytes32) {
        return keccak256(abi.encode(EPOCH_SET_TYPEHASH, CHAIN_HASH, committeeHash, AlpenglowCert.setHash(s)));
    }

    function rotationDigest(bytes32 currentHash, bytes32 nextHash) external view returns (bytes32) {
        return keccak256(abi.encode(SolanaCommittee.ROTATION_TYPEHASH, CHAIN_HASH, currentHash, nextHash));
    }

    // ── IClprVerifier ─────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
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
        Anchor memory anchor = abi.decode(trustAnchor, (Anchor));
        if (anchor.mode != MODE_ATTESTED && anchor.mode != MODE_ALPENGLOW) revert UnknownMode(anchor.mode);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        // 1. Committee: the anchored one, then any rotations it signed.
        bytes32 h = SolanaCommittee.hash(p.committee);
        if (h != anchor.committeeHash) revert SolanaCommittee.CommitteeHashMismatch(h, anchor.committeeHash);
        SolanaCommittee.Committee memory committee =
            SolanaCommittee.applyRotations(p.committee, p.rotations, CHAIN_HASH);
        bytes32 committeeHash = SolanaCommittee.hash(committee);
        bool changed = p.rotations.length > 0;

        // 2. Epoch-set updates (ALPENGLOW), each signed by the current committee.
        if (p.setUpdates.length > 0) {
            if (anchor.mode != MODE_ALPENGLOW) revert SetUpdatesNotAllowed();
            for (uint256 i = 0; i < p.setUpdates.length; i++) {
                AlpenglowCert.EpochSet memory s = p.setUpdates[i].set;
                AlpenglowCert.requireWellFormed(s);
                if (s.epoch <= anchor.curEpoch) revert EpochNotIncreasing(s.epoch, anchor.curEpoch);
                SolanaCommittee.requireQuorum(committee, epochSetDigest(committeeHash, s), p.setUpdates[i].sigs);
                anchor.prevSetHash = anchor.curSetHash;
                anchor.curSetHash = AlpenglowCert.setHash(s);
                anchor.curEpoch = s.epoch;
            }
            changed = true;
        }

        // 3. The queue attestation.
        QueueAttestation memory a = p.attestation;
        if (ctx.remoteServiceAddress.length != 32 || bytes32(ctx.remoteServiceAddress) != a.programId) {
            revert ProgramIdMismatch();
        }
        if (a.channelId != ctx.channelId) revert ChannelIdMismatch();
        if (a.status > uint8(ClprTypes.ChannelStatus.CLOSED)) revert InvalidStatus(a.status);
        SolanaCommittee.requireQuorum(committee, queueDigest(committeeHash, a), p.sigs);

        // 4. Alpenglow finality of the attested block.
        if (anchor.mode == MODE_ALPENGLOW) {
            (AlpenglowCert.FinalityProof memory fp, AlpenglowCert.EpochSet memory set) =
                abi.decode(p.finality, (AlpenglowCert.FinalityProof, AlpenglowCert.EpochSet));
            bytes32 sh = AlpenglowCert.setHash(set);
            if (sh != anchor.curSetHash && sh != anchor.prevSetHash) revert UnknownEpochSet(sh);
            if (fp.slot != a.slot || fp.blockId != a.blockRef) revert FinalityTargetMismatch();
            if (address(ALPENGLOW) == address(0)) revert AlpenglowUnavailable();
            ALPENGLOW.verifyFinality(fp, set);
        } else if (p.finality.length != 0) {
            revert UnexpectedFinalityProof();
        }

        // 5. Outputs. The CLPR Service binds the payloads to `sentRunningHash` and rejects replays.
        metadata = ClprTypes.QueueMetadata({
            nextMessageId: a.nextMessageId,
            sentRunningHash: a.sentRunningHash,
            receivedMessageId: a.receivedMessageId,
            receivedRunningHash: a.receivedRunningHash,
            state: ClprTypes.ChannelStatus(a.status),
            endpointManifestVersion: a.endpointManifestVersion
        });
        messagePayloads = _decodeBundleContent(p.bundleContent);
        newEndpointManifest = p.manifestPreimage.length == 0
            ? _absentEndpointManifest()
            : _bindManifest(p.manifestPreimage, a.manifestCommitment, ctx.remoteServiceAddress);

        if (changed) {
            anchor.committeeHash = committeeHash;
            anchor.committeeNonce = committee.nonce;
            newTrustAnchor = abi.encode(anchor);
            newTrustAnchorId = abi.encodePacked(anchor.committeeNonce, anchor.curEpoch);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof); endpointManifestProofBytes = the manifest
    ///      protobuf preimage of `attestation.manifestCommitment`, or empty for bring-up.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId_,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        SolanaCommittee.requireWellFormed(p.committee);
        bytes32 committeeHash = SolanaCommittee.hash(p.committee);
        if (committeeHash != GENESIS_COMMITTEE_HASH) {
            revert SolanaCommittee.CommitteeHashMismatch(committeeHash, GENESIS_COMMITTEE_HASH);
        }
        SolanaCommittee.requireQuorum(p.committee, configDigest(committeeHash, p.attestation), p.sigs);

        Anchor memory anchor;
        anchor.mode = p.mode;
        anchor.committeeHash = committeeHash;
        anchor.committeeNonce = p.committee.nonce;
        if (p.mode == MODE_ALPENGLOW) {
            if (address(ALPENGLOW) == address(0)) revert AlpenglowUnavailable();
            if (p.initialSet.length != 1) revert InitialSetShape();
            AlpenglowCert.requireWellFormed(p.initialSet[0]);
            SolanaCommittee.requireQuorum(p.committee, epochSetDigest(committeeHash, p.initialSet[0]), p.setSigs);
            anchor.curSetHash = AlpenglowCert.setHash(p.initialSet[0]);
            anchor.curEpoch = p.initialSet[0].epoch;
        } else if (p.mode == MODE_ATTESTED) {
            if (p.initialSet.length != 0) revert InitialSetShape();
        } else {
            revert UnknownMode(p.mode);
        }

        serviceAddress = abi.encodePacked(p.attestation.programId);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _bindManifest(endpointManifestProofBytes, p.attestation.manifestCommitment, serviceAddress);
        chainId_ = chainId;
        peerConfigNanos = p.attestation.peerConfigNanos;
        throttles = p.attestation.throttles;
        initialTrustAnchor = abi.encode(anchor);
        initialTrustAnchorId = abi.encodePacked(anchor.committeeNonce, anchor.curEpoch);
    }

    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedService)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        m = ClprProtobuf.decodeEndpointManifest(preimage);
        if (m.version == 0) revert ManifestVersionZero();
        if (keccak256(m.serviceAddress) != keccak256(expectedService)) revert ManifestServiceAddressMismatch();
    }
}
