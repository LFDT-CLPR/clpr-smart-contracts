// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {StellarXdr} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarXdr.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title StellarScpVerifier
/// @notice Stellar → Hiero `IClprVerifier`: an SCP light client over a trusted quorum set (the
///         tier-1 organizations) plus proofs of Soroban contract events in closed ledgers.
///
/// @dev Finality. An SCP EXTERNALIZE statement for slot S signed by a validator means that
///      validator externalized (finalized) the StellarValue V of ledger S. A slot is accepted when the
///      distinct signers of valid EXTERNALIZE envelopes for (S, V) satisfy the trusted quorum set,
///      evaluated as stellar-core's LocalNode::isQuorumSlice. On pubnet that set is the tier-1 quorum:
///      10 organizations x 3 validators, top threshold 7, each organization 2 of 3, so 14 Ed25519
///      signatures. Signatures cover networkID || ENVELOPE_TYPE_SCP || XDR(SCPStatement)
///      (HerderImpl::signEnvelope) and are checked by the pure-Solidity {IEd25519Verifier}.
///
///      From value to header. SCP signs the input of a ledger (tx set hash, close time, upgrades),
///      not its output, so ledger S's own header is not signed. Header S-1 is: V.txSetHash commits to
///      the GeneralizedTransactionSet of S, whose first field is previousLedgerHash, which
///      stellar-core checks against the last closed ledger before voting (TxSetFrame checkValid,
///      PREVIOUS_LEDGER_HASH_MISMATCH). The proof therefore carries the whole tx set of S. Older
///      headers follow by previousLedgerHash (header hash = SHA-256 of its XDR). The header's
///      skipList holds bucket-list hashes (BucketManager::calculateSkipValues), not ledger hashes,
///      so it cannot shorten the chain.
///
///      State. LedgerHeader.bucketListHash commits to the whole bucket list: each bucket is hashed
///      as a flat file (SHA-256 over every entry), not as a Merkle tree, so a single Soroban
///      ContractData entry cannot be proven without the full bucket that holds it (megabytes to
///      gigabytes below level 0). The verifier proves a contract event instead:
///      header.txSetResultHash = SHA-256(TransactionResultSet); the transaction's pair is located
///      by its hash (SHA-256 of networkID || ENVELOPE_TYPE_TX || Transaction, supplied by the relayer);
///      a successful InvokeHostFunction result holds sha256(InvokeHostFunctionSuccessPreImage
///      { returnValue, events }); the first event's contractID is set by the Soroban host, so only
///      the CLPR service contract can emit it. The service's `attest_queue` publishes its queue
///      metadata as that event (see README for the format).
///
///      Two-step bundles. A pubnet tx set is 100-430 KB and a result set 37-125 KB, so a full proof
///      rarely fits Hedera's 128 KB. The trust anchor keeps a checkpoint (a proven ledger hash): a
///      bundle may carry only the SCP proof (it then advances the checkpoint and re-returns the last
///      proven metadata, which the CLPR Service accepts as a trust-anchor-only update), and a later
///      bundle walks headers back from that checkpoint to the attestation's ledger.
///
///      Quorum-set rotation. Every EXTERNALIZE statement carries D, the hash of its signer's own
///      quorum set. The trusted set moves to a new set Q' when the signers whose D = SHA-256(Q')
///      satisfy the current set, i.e. the current tier-1 quorum itself declares Q' as its quorum.
///
///      Trust anchor: abi.encode(bytes32 qsetHash, uint64 lastSlot, uint32 checkpointSeq,
///      bytes32 checkpointHash, bytes32 lastMetadataHash). A bundle returns a new anchor only when one
///      of these changed; an attestation that re-proves the last metadata from the same checkpoint
///      returns none. Replays of older queue states are rejected by the CLPR Service (replay, ack and
///      progress checks), as for every other verifier.
///
///      Bundle proof: RLP([
///        0 qset            SCPQuorumSet XDR; SHA-256 must equal anchor.qsetHash
///        1 scp             [] or [[[statement, sig64], ...], txSetXdr, newQsetXdr | ""]
///        2 headers         [headerXdr, ...] from the trusted ledger backwards ([] for checkpoint only)
///        3 attestation     [] or [txPayload, resultSetXdr, pairOffset, successPreimage]
///        4 lastMetadata    abi.encode(QueueMetadata) of the last proven attestation, when 3 is empty
///        5 bundleContent   ClprBundleContent protobuf
///        6 manifest        ClprEndpointManifest protobuf preimage, or empty
///      ])
contract StellarScpVerifier is ClprEvmBundleVerifier {
    /// @notice Ed25519 signature checker (pure Solidity; Hedera has no Ed25519 precompile).
    IEd25519Verifier public immutable ED25519;
    /// @notice SHA-256 of the network passphrase, e.g. "Public Global Stellar Network ; September 2015".
    bytes32 public immutable NETWORK_ID;
    /// @notice keccak256 of the CAIP-2 id this verifier serves ("stellar:pubnet", "stellar:testnet").
    bytes32 public immutable CHAIN_ID_HASH;

    uint256 internal constant TRUST_ANCHOR_LENGTH = 160;
    uint256 internal constant BUNDLE_FIELDS = 7;
    uint256 internal constant SCP_FIELDS = 3;
    uint256 internal constant ATTESTATION_FIELDS = 4;
    uint256 internal constant CONFIG_FIELDS = 3;
    uint256 internal constant MANIFEST_PROOF_FIELDS = 3;

    /// @dev Queue event: topics [Symbol("clpr_queue"), Bytes(channelId)], data Bytes(124).
    bytes10 internal constant QUEUE_SYMBOL = "clpr_queue";
    uint32 internal constant QUEUE_DATA_LENGTH = 124;
    uint256 internal constant QUEUE_EVENT_PREFIX = 72;
    /// @dev Manifest event: topics [Symbol("clpr_manifest")], data Bytes(32).
    bytes13 internal constant MANIFEST_SYMBOL = "clpr_manifest";
    uint256 internal constant MANIFEST_EVENT_PREFIX = 36;

    struct Anchor {
        bytes32 qsetHash;
        uint64 lastSlot;
        uint32 checkpointSeq;
        bytes32 checkpointHash;
        bytes32 lastMetadataHash;
    }

    /// @notice What an SCP proof established.
    struct ScpResult {
        uint64 slot;
        bytes32 previousLedgerHash; // hash of ledger slot - 1
        uint256 signers;
        bytes32 newQsetHash; // 0 unless the proof rotated the quorum set
    }

    error InvalidConstructorParams();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error QuorumSetMismatch();
    error NoEnvelopes();
    error SignersNotSorted(uint256 index);
    error UnknownSigner(bytes32 nodeId);
    error BadSignature(uint256 index);
    error SlotMismatch(uint256 index);
    error ValueMismatch(uint256 index);
    error UnsupportedStellarValue(uint32 extArm);
    error QuorumNotSatisfied();
    error RotationNotEndorsed();
    error TxSetMismatch();
    error StaleSlot(uint64 slot, uint64 lastSlot);
    error NoCheckpoint();
    error HeaderChainBroken(uint256 index);
    error EmptyHeaderChain();
    error ResultSetMismatch();
    error BadTransactionPayload();
    error TransactionNotInResultSet();
    error SuccessPreimageMismatch();
    error WrongEmitter(bytes32 contractId);
    error WrongAttestationEvent();
    error InvalidChannelStatus(uint32 status);
    error LastMetadataMismatch();
    error NothingProven();
    error WrongChain(string chainId);

    constructor(IEd25519Verifier ed25519, bytes32 networkId, string memory chainId) {
        if (address(ed25519) == address(0) || networkId == bytes32(0) || bytes(chainId).length == 0) {
            revert InvalidConstructorParams();
        }
        ED25519 = ed25519;
        NETWORK_ID = networkId;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
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
        Anchor memory a = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 serviceContract = _contractId(ctx.remoteServiceAddress);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS) revert InvalidPayloadShape();

        StellarXdr.QuorumSet memory q = _trustedQuorumSet(RLP.readBytes(p[0]), a.qsetHash);

        // 1. Optional SCP proof: finality of a new slot, a new checkpoint, maybe a rotation.
        Memory.Slice[] memory scp = RLP.readList(p[1]);
        bool proved;
        if (scp.length != 0) {
            ScpResult memory r = _verifyScp(scp, q, true);
            if (r.slot <= a.lastSlot) revert StaleSlot(r.slot, a.lastSlot);
            a.lastSlot = r.slot;
            a.checkpointSeq = uint32(r.slot - 1);
            a.checkpointHash = r.previousLedgerHash;
            if (r.newQsetHash != bytes32(0)) a.qsetHash = r.newQsetHash;
            proved = true;
        }

        // 2. Optional attestation, in a ledger reached from the checkpoint by previousLedgerHash.
        Memory.Slice[] memory att = RLP.readList(p[3]);
        bytes32 manifestCommitment;
        if (att.length != 0) {
            StellarXdr.Header memory h = _walkHeaders(p[2], a);
            (metadata, manifestCommitment) = _verifyQueueEvent(att, h, serviceContract, ctx.channelId);
            a.lastMetadataHash = keccak256(abi.encode(metadata));
            proved = true;
        } else {
            if (RLP.readList(p[2]).length != 0) revert InvalidPayloadShape();
            metadata = _lastMetadata(RLP.readBytes(p[4]), a.lastMetadataHash);
        }
        if (!proved) revert NothingProven();

        // 3. Message payloads. BundleLib binds them to metadata.sentRunningHash.
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[5]));

        // 4. Optional endpoint-manifest update, bound to the attested commitment.
        bytes memory manifestPreimage = RLP.readBytes(p[6]);
        if (manifestPreimage.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            if (att.length == 0) revert InvalidPayloadShape();
            newEndpointManifest = _bindManifest(manifestPreimage, manifestCommitment, ctx.remoteServiceAddress);
        }

        bytes memory encoded = _encodeTrustAnchor(a);
        if (keccak256(encoded) != keccak256(trustAnchor)) {
            newTrustAnchor = encoded;
            newTrustAnchorId = _anchorId(a);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof = RLP([qsetXdr, scpProof, ledgerConfigControlMessage]). The quorum set is the
    ///      channel's weak-subjectivity input (as for every light client); the SCP proof must show it
    ///      externalizing a real slot, which also fixes the first checkpoint.
    ///      endpointManifestProof = RLP([headers, attestation, manifestPreimage]) walking back from that
    ///      checkpoint to a `clpr_manifest` event, or empty.
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
        Memory.Slice[] memory cfg = RLP.decodeList(cfgMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidPayloadShape();

        bytes memory qsetXdr = RLP.readBytes(cfg[0]);
        StellarXdr.QuorumSet memory q = StellarXdr.parseQuorumSet(qsetXdr, true);
        Memory.Slice[] memory scp = RLP.readList(cfg[1]);
        if (scp.length == 0) revert InvalidPayloadShape();
        ScpResult memory r = _verifyScp(scp, q, false);

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[2])).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChain(lc.chainId);
        serviceAddress = lc.serviceAddress;
        bytes32 serviceContract = _contractId(serviceAddress);

        Anchor memory a = Anchor({
            qsetHash: sha256(qsetXdr),
            lastSlot: r.slot,
            checkpointSeq: uint32(r.slot - 1),
            checkpointHash: r.previousLedgerHash,
            lastMetadataHash: bytes32(0)
        });
        initialTrustAnchor = _encodeTrustAnchor(a);
        initialTrustAnchorId = _anchorId(a);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _verifyConfigManifest(endpointManifestProofBytes, a, serviceContract, serviceAddress);
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

    // ── SCP finality ──────────────────────────────────────────────────────────

    /// @dev Check the quorum-set preimage against the anchor and decode it.
    function _trustedQuorumSet(bytes memory qsetXdr, bytes32 expected)
        internal
        pure
        returns (StellarXdr.QuorumSet memory q)
    {
        if (sha256(qsetXdr) != expected) revert QuorumSetMismatch();
        q = StellarXdr.parseQuorumSet(qsetXdr, false);
    }

    /// @dev Verify [[statement, sig], ...], txSet, newQset. Envelopes are sorted by node id (so
    ///      every signer counts once), signed by members of `q`, all EXTERNALIZE for the same slot and
    ///      value, and their signers satisfy `q`. Returns the slot and the hash of ledger slot - 1.
    function _verifyScp(Memory.Slice[] memory scp, StellarXdr.QuorumSet memory q, bool allowRotation)
        internal
        view
        returns (ScpResult memory r)
    {
        if (scp.length != SCP_FIELDS) revert InvalidPayloadShape();
        Memory.Slice[] memory envs = RLP.readList(scp[0]);
        uint256 n = envs.length;
        if (n == 0) revert NoEnvelopes();
        if (n > StellarXdr.MAX_QSET_VALIDATORS) revert InvalidPayloadShape();

        bytes memory newQset = RLP.readBytes(scp[2]);
        if (newQset.length != 0) {
            if (!allowRotation) revert InvalidPayloadShape();
            StellarXdr.parseQuorumSet(newQset, true);
            r.newQsetHash = sha256(newQset);
        }

        bytes32[] memory signers = new bytes32[](n);
        bytes32[] memory endorsers = new bytes32[](n);
        uint256 endorsed;
        bytes32 valueHash;
        bytes memory value;
        for (uint256 i = 0; i < n; ++i) {
            Memory.Slice[] memory env = RLP.readList(envs[i]);
            if (env.length != 2) revert InvalidPayloadShape();
            bytes memory stmt = RLP.readBytes(env[0]);
            StellarXdr.Externalize memory e = StellarXdr.parseExternalize(stmt);
            if (i > 0 && e.nodeId <= signers[i - 1]) revert SignersNotSorted(i);
            if (!StellarXdr.isMember(q, e.nodeId)) revert UnknownSigner(e.nodeId);
            if (i == 0) {
                r.slot = e.slotIndex;
                value = e.value;
                valueHash = keccak256(e.value);
            } else {
                if (e.slotIndex != r.slot) revert SlotMismatch(i);
                if (keccak256(e.value) != valueHash) revert ValueMismatch(i);
            }
            if (!ED25519.verify(e.nodeId, StellarXdr.scpSignedMessage(NETWORK_ID, stmt), RLP.readBytes(env[1]))) {
                revert BadSignature(i);
            }
            signers[i] = e.nodeId;
            if (r.newQsetHash != bytes32(0) && e.commitQuorumSetHash == r.newQsetHash) {
                endorsers[endorsed++] = e.nodeId;
            }
        }
        if (!StellarXdr.isSatisfied(q, signers)) revert QuorumNotSatisfied();
        if (r.newQsetHash != bytes32(0)) {
            assembly ("memory-safe") {
                mstore(endorsers, endorsed)
            }
            if (!StellarXdr.isSatisfied(q, endorsers)) revert RotationNotEndorsed();
        }
        r.signers = n;
        // Ledger sequence numbers are uint32; slot - 1 becomes the checkpoint's ledgerSeq.
        if (r.slot == 0 || r.slot > type(uint32).max) revert SlotMismatch(0);

        // The externalized StellarValue: BASIC or SIGNED only. EMPTY_TX_SET marks a skipped ledger
        // whose applied tx set differs from txSetHash, so it is rejected (fail closed).
        (uint256 end, uint32 extArm) = StellarXdr.stellarValueEnd(value, 0);
        if (end != value.length) revert StellarXdr.XdrTrailingBytes();
        if (extArm > StellarXdr.STELLAR_VALUE_SIGNED) revert UnsupportedStellarValue(extArm);

        // GeneralizedTransactionSet v1 { previousLedgerHash; phases<> }, hashed as a whole.
        bytes memory txSet = RLP.readBytes(scp[1]);
        if (StellarXdr.u32(txSet, 0) != 1 || sha256(txSet) != StellarXdr.b32(value, 0)) revert TxSetMismatch();
        r.previousLedgerHash = StellarXdr.b32(txSet, 4);
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// @dev Walk [header, ...] back from the anchor's checkpoint; returns the last header.
    function _walkHeaders(Memory.Slice item, Anchor memory a) internal pure returns (StellarXdr.Header memory h) {
        if (a.checkpointHash == bytes32(0)) revert NoCheckpoint();
        Memory.Slice[] memory list = RLP.readList(item);
        if (list.length == 0) revert EmptyHeaderChain();
        bytes32 expectHash = a.checkpointHash;
        uint256 expectSeq = a.checkpointSeq;
        for (uint256 i = 0; i < list.length; ++i) {
            h = StellarXdr.parseHeader(RLP.readBytes(list[i]));
            if (h.hash != expectHash || h.ledgerSeq != expectSeq) revert HeaderChainBroken(i);
            expectHash = h.previousLedgerHash;
            expectSeq = expectSeq - 1;
        }
    }

    // ── Soroban event attestations ────────────────────────────────────────────

    /// @dev Prove that a successful Soroban transaction in ledger `h` emitted, as its first event, an
    ///      event from `serviceContract`. Returns the success preimage and the offset of that event's
    ///      topics vector.
    function _provenEvent(Memory.Slice[] memory att, StellarXdr.Header memory h, bytes32 serviceContract)
        internal
        view
        returns (bytes memory preimage, uint256 topicsStart)
    {
        if (att.length != ATTESTATION_FIELDS) revert InvalidPayloadShape();
        bytes memory payload = RLP.readBytes(att[0]);
        bytes memory resultSet = RLP.readBytes(att[1]);
        uint256 o = RLP.readUint256(att[2]);
        preimage = RLP.readBytes(att[3]);

        if (sha256(resultSet) != h.txSetResultHash) revert ResultSetMismatch();

        // A transaction hash is SHA-256(networkID || ENVELOPE_TYPE_TX || Transaction). No other value in
        // a result set is a SHA-256 over a networkID-prefixed preimage, so a matching 32-byte window is
        // the transaction's own TransactionResultPair (or the InnerTransactionResultPair of a fee bump).
        if (payload.length < 36 || StellarXdr.b32(payload, 0) != NETWORK_ID) revert BadTransactionPayload();
        if (StellarXdr.u32(payload, 32) != StellarXdr.ENVELOPE_TYPE_TX) revert BadTransactionPayload();
        if (StellarXdr.b32(resultSet, o) != sha256(payload)) revert TransactionNotInResultSet();

        bytes32 successHash = StellarXdr.invokeSuccessHash(resultSet, o + 32);
        if (sha256(preimage) != successHash) revert SuccessPreimageMismatch();
        bytes32 emitter;
        (emitter, topicsStart,) = StellarXdr.firstContractEvent(preimage);
        if (emitter != serviceContract) revert WrongEmitter(emitter);
    }

    /// @dev The `clpr_queue` event. Data layout (124 bytes, big-endian): nextMessageId u64,
    ///      sentRunningHash 32, receivedMessageId u64, receivedRunningHash 32, status u32,
    ///      endpointManifestVersion u64, manifestCommitment 32.
    function _verifyQueueEvent(
        Memory.Slice[] memory att,
        StellarXdr.Header memory h,
        bytes32 serviceContract,
        bytes32 channelId
    ) internal view returns (ClprTypes.QueueMetadata memory m, bytes32 manifestCommitment) {
        (bytes memory pre, uint256 o) = _provenEvent(att, h, serviceContract);
        bytes memory expected = abi.encodePacked(
            uint32(2),
            StellarXdr.SCV_SYMBOL,
            uint32(10),
            QUEUE_SYMBOL,
            bytes2(0),
            StellarXdr.SCV_BYTES,
            uint32(32),
            channelId,
            StellarXdr.SCV_BYTES,
            QUEUE_DATA_LENGTH
        );
        if (o + QUEUE_EVENT_PREFIX + QUEUE_DATA_LENGTH > pre.length) revert WrongAttestationEvent();
        if (StellarXdr.sha256Range(pre, o, QUEUE_EVENT_PREFIX) != sha256(expected)) revert WrongAttestationEvent();
        uint256 d = o + QUEUE_EVENT_PREFIX;
        uint32 status = StellarXdr.u32(pre, d + 80);
        if (status > uint32(type(ClprTypes.ChannelStatus).max)) revert InvalidChannelStatus(status);
        m = ClprTypes.QueueMetadata({
            nextMessageId: StellarXdr.u64(pre, d),
            sentRunningHash: StellarXdr.b32(pre, d + 8),
            receivedMessageId: StellarXdr.u64(pre, d + 40),
            receivedRunningHash: StellarXdr.b32(pre, d + 48),
            state: ClprTypes.ChannelStatus(status),
            endpointManifestVersion: StellarXdr.u64(pre, d + 84)
        });
        manifestCommitment = StellarXdr.b32(pre, d + 92);
    }

    /// @dev The `clpr_manifest` event: topics [Symbol("clpr_manifest")], data Bytes(32) commitment.
    function _verifyManifestEvent(Memory.Slice[] memory att, StellarXdr.Header memory h, bytes32 serviceContract)
        internal
        view
        returns (bytes32 commitment)
    {
        (bytes memory pre, uint256 o) = _provenEvent(att, h, serviceContract);
        bytes memory expected = abi.encodePacked(
            uint32(1), StellarXdr.SCV_SYMBOL, uint32(13), MANIFEST_SYMBOL, bytes3(0), StellarXdr.SCV_BYTES, uint32(32)
        );
        if (o + MANIFEST_EVENT_PREFIX + 32 > pre.length) revert WrongAttestationEvent();
        if (StellarXdr.sha256Range(pre, o, MANIFEST_EVENT_PREFIX) != sha256(expected)) {
            revert WrongAttestationEvent();
        }
        commitment = StellarXdr.b32(pre, o + MANIFEST_EVENT_PREFIX);
    }

    function _verifyConfigManifest(
        bytes calldata proofBytes,
        Anchor memory a,
        bytes32 serviceContract,
        bytes memory serviceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        bytes memory mem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(mem);
        if (p.length != MANIFEST_PROOF_FIELDS) revert InvalidPayloadShape();
        StellarXdr.Header memory h = _walkHeaders(p[0], a);
        bytes32 commitment = _verifyManifestEvent(RLP.readList(p[1]), h, serviceContract);
        return _bindManifest(RLP.readBytes(p[2]), commitment, serviceAddress);
    }

    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ── Metadata of checkpoint-only bundles ───────────────────────────────────

    /// @dev A bundle without an attestation re-returns the last proven metadata (bound by its hash in
    ///      the anchor), which BundleLib accepts as a zero-message, trust-anchor-only update. Before
    ///      the first attestation it returns the empty queue (nothing sent, nothing received, PENDING).
    function _lastMetadata(bytes memory preimage, bytes32 expected)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory m)
    {
        if (expected == bytes32(0)) {
            if (preimage.length != 0) revert LastMetadataMismatch();
            m.nextMessageId = 1;
            m.state = ClprTypes.ChannelStatus.PENDING;
            return m;
        }
        if (keccak256(preimage) != expected) revert LastMetadataMismatch();
        m = abi.decode(preimage, (ClprTypes.QueueMetadata));
    }

    // ── Encoding helpers ──────────────────────────────────────────────────────

    /// @dev A Soroban contract is addressed by its 32-byte contract id.
    function _contractId(bytes memory serviceAddress) internal pure returns (bytes32 id) {
        if (serviceAddress.length != 32) revert InvalidServiceAddressLength();
        // forge-lint: disable-next-line(unsafe-typecast)
        id = bytes32(serviceAddress); // exactly 32 bytes, checked above
    }

    function _encodeTrustAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encode(a.qsetHash, a.lastSlot, a.checkpointSeq, a.checkpointHash, a.lastMetadataHash);
    }

    /// @dev Identifies the anchor: the last finalized slot and the metadata it re-returns.
    function _anchorId(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.lastSlot, a.lastMetadataHash);
    }

    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (Anchor memory a) {
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (a.qsetHash, a.lastSlot, a.checkpointSeq, a.checkpointHash, a.lastMetadataHash) =
            abi.decode(trustAnchor, (bytes32, uint64, uint32, bytes32, bytes32));
    }
}
