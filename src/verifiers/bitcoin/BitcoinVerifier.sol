// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";

/// @title BitcoinVerifier
/// @notice CLPR verifier for the one-way connector Bitcoin L1 → Hiero (or any EVM ledger). It runs
///         a stateless proof-of-work (SPV) light client and reads CLPR messages from Bitcoin
///         transactions. See `src/verifiers/bitcoin/README.md` for the design, trust assumptions
///         and limits.
///
/// Bitcoin has no smart contracts, so there is no CLPR Service and no queue state on Bitcoin:
///   - The QUEUE is a UTXO chain. Every message tx spends the previous message's "cursor" output
///     (vout 1) as its input 0 and creates a new cursor at its own vout 1. Bitcoin's double-spend
///     rule makes the chain linear, which yields total order and exactly-once delivery.
///   - A MESSAGE is committed by a 55-byte OP_RETURN script at vout 0:
///       OP_RETURN PUSH(53) "CLPR" ‖ version(1)=0x01 ‖ channelTag(8) ‖ sha256(payload)(32) ‖ id(8, BE)
///     The payload preimage (a protobuf `ClprMessage` DATA) is supplied in the bundle.
///   - The QUEUE METADATA is synthesized by this verifier: it keeps the running hash in the trust
///     anchor and folds it exactly like `BundleLib` (`h = sha256(h ‖ sha256(payload))`).
///
/// Trust anchor (ABI-encoded {TrustAnchor}): a PoW checkpoint that is at least `k` confirmations
/// deep, the queue cursor, the last delivered message id and running hash, and `k` itself.
contract BitcoinVerifier is IClprVerifier {
    // ── Wire / protocol constants ────────────────────────────────────────────

    bytes4 internal constant MAGIC = "CLPR";
    uint8 internal constant MESSAGE_VERSION = 1;
    /// @dev OP_RETURN (0x6a) followed by a direct 53-byte push (0x35).
    uint256 internal constant OP_RETURN_SCRIPT_LENGTH = 55;
    uint256 internal constant OP_RETURN_DATA_LENGTH = 53;
    /// @dev Output index of the queue cursor in every CLPR tx (genesis and messages).
    uint32 internal constant CURSOR_VOUT = 1;
    /// @dev Upper bound on the sender scriptPubKey length (P2TR is 34 bytes; bare multisig is larger).
    uint256 internal constant MAX_SENDER_SCRIPT_LENGTH = 128;

    // ── Types ────────────────────────────────────────────────────────────────

    /// @notice A verified header-chain position plus the state needed to validate its successors.
    struct Checkpoint {
        bytes32 blockHash; // internal byte order
        uint32 height;
        uint256 chainWork; // cumulative work up to and including this block
        uint32 bits; // nBits of this block (the "regular" difficulty on min-difficulty networks)
        uint32 time; // timestamp of this block
        uint32 periodStartTime; // timestamp of the first block of this block's 2016-block period
    }

    /// @notice Channel.trustAnchor, ABI-encoded.
    struct TrustAnchor {
        Checkpoint checkpoint;
        bytes32 cursorTxid; // outpoint the next message tx must spend as input 0
        uint32 cursorVout;
        uint64 lastMessageId; // id of the last delivered message (0 = none yet)
        bytes32 runningHash; // BundleLib-style running hash after lastMessageId (0 = none yet)
        uint8 confirmations; // k
    }

    /// @notice One CLPR transaction with its inclusion proof.
    struct TxProof {
        uint32 headerIndex; // index into the proof's header list of the block containing the tx
        uint32 txIndex; // position of the tx in the block
        bytes32[] merkleBranch; // siblings, leaf-first, internal byte order
        bytes rawTx; // legacy or segwit serialization
        bytes payload; // message payload preimage (empty for the genesis tx)
    }

    /// @notice `proofBytes` of {verifyBundle}, ABI-encoded.
    /// @dev `headers` is a concatenation of 80-byte headers at heights startHeight, startHeight+1, …
    ///      It must connect to the anchor checkpoint: either start at checkpoint.height+1 (linking to
    ///      checkpoint.blockHash), or start at or below checkpoint.height and contain the checkpoint
    ///      header itself. Headers at or below the checkpoint are bound by hash linkage only (their
    ///      work was already accepted); headers above it get full PoW/difficulty validation.
    struct BundleProof {
        uint32 startHeight;
        bytes headers;
        TxProof[] messages;
    }

    /// @notice `configProofBytes` of {verifyConfig}, ABI-encoded. Headers connect to the deployment
    ///         checkpoint exactly as {BundleProof.headers} connect to an anchor checkpoint.
    struct ConfigProof {
        uint32 startHeight;
        bytes headers;
        TxProof genesis;
    }

    /// @dev Per-header data kept after chain validation.
    struct VerifiedChain {
        bytes32[] merkleRoots; // indexed like the proof's header list
        uint32[] times;
        uint32 finalHeight; // highest height with ≥ k confirmations (never below the old checkpoint)
        Checkpoint newCheckpoint;
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    error InvalidNetworkParams();
    error InvalidTrustAnchor();
    error InvalidHeadersLength();
    error HeadersDoNotConnect();
    error BrokenLinkage(uint256 index);
    error CheckpointMismatch();
    error WrongDifficultyBits(uint256 height, uint32 expected, uint32 actual);
    error TargetAbovePowLimit(uint256 height);
    error InsufficientProofOfWork(uint256 height);
    error HeaderIndexOutOfRange();
    error InsufficientConfirmations(uint256 blockHeight, uint256 finalHeight);
    error MerkleProofInvalid();
    error NotACursorSpend();
    error MalformedCommitment();
    error WrongChannelTag();
    error UnexpectedMessageId(uint64 expected, uint64 actual);
    error CursorNotHeldBySender();
    error PayloadHashMismatch();
    error InvalidSenderScript();
    error ManifestProofUnsupported();

    // ── Deployment parameters ────────────────────────────────────────────────

    /// @notice Maximum target (minimum difficulty) of the network.
    uint256 public immutable POW_LIMIT;
    /// @notice Regtest: difficulty never retargets.
    bool public immutable NO_RETARGETING;
    /// @notice Regtest/testnet: a block more than 20 minutes after its parent may use powLimit.
    bool public immutable ALLOW_MIN_DIFFICULTY;
    /// @notice Confirmation depth k written into every trust anchor this verifier creates.
    uint8 public immutable CONFIRMATIONS;
    /// @notice Payloads larger than this are delivered as REDACTED rather than halting the channel.
    uint256 public immutable MAX_PAYLOAD_BYTES;

    // Deployment checkpoint (trusted root for verifyConfig), stored as immutables.
    bytes32 internal immutable CP_HASH;
    uint32 internal immutable CP_HEIGHT;
    uint256 internal immutable CP_CHAINWORK;
    uint32 internal immutable CP_BITS;
    uint32 internal immutable CP_TIME;
    uint32 internal immutable CP_PERIOD_START_TIME;

    /// @notice CAIP-2 chain id of the Bitcoin network, e.g. `bip122:000000000019d6689c085ae165831e93`.
    string public chainId;

    /// @param powLimit Network maximum target (mainnet 0x00000000ffff << 208; regtest 0x7fffff << 232).
    /// @param noRetargeting True for regtest.
    /// @param allowMinDifficulty True for regtest. Only supported together with `noRetargeting`:
    ///        testnet3/testnet4 retarget semantics (walk-back, BIP94) are not implemented.
    /// @param confirmations k (≥ 1); 6 is the conventional value for mainnet.
    /// @param maxPayloadBytes Oversized-payload threshold (keep ≤ the local maxMessagePayloadBytes).
    /// @param caip2ChainId CAIP-2 id returned by verifyConfig as the peer chain id.
    /// @param checkpoint A block the deployer trusts to be on the canonical chain.
    constructor(
        uint256 powLimit,
        bool noRetargeting,
        bool allowMinDifficulty,
        uint8 confirmations,
        uint256 maxPayloadBytes,
        string memory caip2ChainId,
        Checkpoint memory checkpoint
    ) {
        if (powLimit == 0 || confirmations == 0 || maxPayloadBytes == 0 || bytes(caip2ChainId).length == 0) {
            revert InvalidNetworkParams();
        }
        if (allowMinDifficulty && !noRetargeting) revert InvalidNetworkParams();
        POW_LIMIT = powLimit;
        NO_RETARGETING = noRetargeting;
        ALLOW_MIN_DIFFICULTY = allowMinDifficulty;
        CONFIRMATIONS = confirmations;
        MAX_PAYLOAD_BYTES = maxPayloadBytes;
        chainId = caip2ChainId;
        CP_HASH = checkpoint.blockHash;
        CP_HEIGHT = checkpoint.height;
        CP_CHAINWORK = checkpoint.chainWork;
        CP_BITS = checkpoint.bits;
        CP_TIME = checkpoint.time;
        CP_PERIOD_START_TIME = checkpoint.periodStartTime;
    }

    /// @notice The deployment checkpoint that roots every channel's config proof.
    function deploymentCheckpoint() public view returns (Checkpoint memory) {
        return Checkpoint({
            blockHash: CP_HASH,
            height: CP_HEIGHT,
            chainWork: CP_CHAINWORK,
            bits: CP_BITS,
            time: CP_TIME,
            periodStartTime: CP_PERIOD_START_TIME
        });
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof). The genesis tx fixes the channel's sender
    ///      (the scriptPubKey of its cursor output) and the first cursor outpoint. Its OP_RETURN must
    ///      commit to this channel's tag with message id 0 and a zero payload hash. Endpoint-manifest
    ///      proofs are not supported (Bitcoin has no endpoints): the manifest is always version 0.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory peerChainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (endpointManifestProofBytes.length != 0) {
            revert ManifestProofUnsupported();
        }
        if (configProofBytes.length == 0) revert InvalidHeadersLength();
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));

        uint8 k = CONFIRMATIONS;
        VerifiedChain memory chain = _verifyChain(deploymentCheckpoint(), p.startHeight, p.headers, k);

        (BitcoinLib.Tx memory t, uint64 id, bytes32 payloadHash) =
            _verifyClprTx(chain, p.startHeight, p.genesis, bytes8(channelId));
        if (id != 0 || payloadHash != bytes32(0)) revert MalformedCommitment();
        serviceAddress = t.out1Script;
        if (serviceAddress.length == 0 || serviceAddress.length > MAX_SENDER_SCRIPT_LENGTH) {
            revert InvalidSenderScript();
        }

        TrustAnchor memory anchor = TrustAnchor({
            checkpoint: chain.newCheckpoint,
            cursorTxid: t.txid,
            cursorVout: CURSOR_VOUT,
            lastMessageId: 0,
            runningHash: bytes32(0),
            confirmations: k
        });

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        peerChainId = chainId;
        peerConfigNanos = uint96(chain.times[p.genesis.headerIndex]) * 1_000_000_000;
        throttles = _peerThrottles();
        initialTrustAnchor = abi.encode(anchor);
        initialTrustAnchorId = _anchorId(anchor);
        // No manifest proof exists for Bitcoin: version 0 (UNINITIALIZED), bound to the sender.
        endpointManifest.serviceAddress = serviceAddress;
        endpointManifest.endpoints = new ClprTypes.Endpoint[](0);
    }

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof). Messages must be listed in queue order starting at
    ///      lastMessageId+1; each must be in a block with ≥ k confirmations relative to the proof's
    ///      tip (or at/below the anchor checkpoint, which already has them).
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
        TrustAnchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (proofBytes.length == 0) revert InvalidHeadersLength();
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        VerifiedChain memory chain = _verifyChain(anchor.checkpoint, p.startHeight, p.headers, anchor.confirmations);

        uint256 n = p.messages.length;
        messagePayloads = new bytes[](n);
        bytes8 tag = bytes8(ctx.channelId);
        bytes32 senderScriptHash = keccak256(ctx.remoteServiceAddress);
        for (uint256 i = 0; i < n; ++i) {
            TxProof memory m = p.messages[i];
            (BitcoinLib.Tx memory t, uint64 id, bytes32 payloadHash) = _verifyClprTx(chain, p.startHeight, m, tag);

            // Queue order: input 0 spends the current cursor, the id is the next one, and the new
            // cursor stays with the channel's single sender.
            if (t.in0PrevTxid != anchor.cursorTxid || t.in0PrevVout != anchor.cursorVout) revert NotACursorSpend();
            if (id != anchor.lastMessageId + 1) revert UnexpectedMessageId(anchor.lastMessageId + 1, id);
            if (keccak256(t.out1Script) != senderScriptHash) revert CursorNotHeldBySender();

            if (sha256(m.payload) != payloadHash) revert PayloadHashMismatch();
            bytes memory delivered = _deliverable(m.payload, payloadHash, ctx.remoteServiceAddress);
            messagePayloads[i] = delivered;

            anchor.cursorTxid = t.txid;
            anchor.cursorVout = CURSOR_VOUT;
            anchor.lastMessageId = id;
            anchor.runningHash = sha256(abi.encodePacked(anchor.runningHash, sha256(delivered)));
        }

        metadata = ClprTypes.QueueMetadata({
            nextMessageId: anchor.lastMessageId + 1,
            sentRunningHash: anchor.runningHash,
            receivedMessageId: 0, // Bitcoin never receives
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });

        bool checkpointMoved = chain.newCheckpoint.height != anchor.checkpoint.height;
        if (checkpointMoved || n > 0) {
            anchor.checkpoint = chain.newCheckpoint;
            newTrustAnchor = abi.encode(anchor);
            newTrustAnchorId = _anchorId(anchor);
        }
        newEndpointManifest.endpoints = new ClprTypes.Endpoint[](0); // version 0 = no update
    }

    /// @notice Whether `payload` is a well-formed DATA message whose sender field is `senderScript`.
    /// @dev External so {verifyBundle} can call it under try/catch: any decode revert → false.
    function isDeliverableData(bytes calldata payload, bytes calldata senderScript) external pure returns (bool) {
        (bool known, ClprTypes.MessageType t) = ClprProtobuf.tryGetMessageType(payload);
        if (!known || t != ClprTypes.MessageType.DATA) return false;
        ClprTypes.DecodedDataMessage memory d = ClprProtobuf.decodeDataMessage(payload);
        return keccak256(d.sender) == keccak256(senderScript) && d.targetApplication.length == 20;
    }

    // ── Header chain ─────────────────────────────────────────────────────────

    /// @dev Validate `headers` against checkpoint `cp` and compute the new checkpoint: the highest
    ///      block with ≥ k confirmations (tip - k + 1), never moving backwards.
    function _verifyChain(Checkpoint memory cp, uint32 startHeight, bytes memory headers, uint8 k)
        internal
        view
        returns (VerifiedChain memory chain)
    {
        uint256 count = headers.length / BitcoinLib.HEADER_LENGTH;
        if (count == 0 || headers.length % BitcoinLib.HEADER_LENGTH != 0) revert InvalidHeadersLength();
        if (k == 0) revert InvalidTrustAnchor();
        uint256 tipHeight = uint256(startHeight) + count - 1;
        // Must connect: start at most one above the checkpoint and reach at least the checkpoint.
        if (uint256(startHeight) > uint256(cp.height) + 1 || tipHeight < cp.height) revert HeadersDoNotConnect();

        uint256 finalHeight = cp.height;
        if (tipHeight + 1 >= uint256(k) && tipHeight + 1 - k > finalHeight) finalHeight = tipHeight + 1 - k;
        // casting to 'uint32' is safe: finalHeight ≤ tipHeight = startHeight + count - 1 and heights fit 32 bits
        // for the lifetime of Bitcoin; a larger value would fail the connect check on the next bundle.
        // forge-lint: disable-next-line(unsafe-typecast)
        chain.finalHeight = uint32(finalHeight);
        chain.merkleRoots = new bytes32[](count);
        chain.times = new uint32[](count);
        chain.newCheckpoint = cp;

        Checkpoint memory s = Checkpoint({
            blockHash: cp.blockHash,
            height: cp.height,
            chainWork: cp.chainWork,
            bits: cp.bits,
            time: cp.time,
            periodStartTime: cp.periodStartTime
        });
        bytes32 prev = cp.blockHash;
        bool linkFirst = uint256(startHeight) == uint256(cp.height) + 1;

        for (uint256 i = 0; i < count; ++i) {
            bytes memory h = BitcoinLib.headerAt(headers, i);
            bytes32 hash = BitcoinLib.hash256(h);
            uint256 height = uint256(startHeight) + i;
            if ((i > 0 || linkFirst) && BitcoinLib.prevHash(h) != prev) revert BrokenLinkage(i);

            if (height == cp.height) {
                if (hash != cp.blockHash) revert CheckpointMismatch();
            } else if (height > cp.height) {
                _checkWork(h, hash, height, s);
                s.blockHash = hash;
                // casting to 'uint32' is safe: height ≤ tipHeight, bounded as above.
                // forge-lint: disable-next-line(unsafe-typecast)
                s.height = uint32(height);
                if (height == finalHeight) chain.newCheckpoint = _copy(s);
            }
            chain.merkleRoots[i] = BitcoinLib.merkleRoot(h);
            chain.times[i] = BitcoinLib.timestamp(h);
            prev = hash;
        }
    }

    /// @dev Difficulty and proof-of-work checks for the block at `height` whose parent state is `s`;
    ///      advances `s` (bits, time, period start, chainwork) to this block.
    ///      Not checked (documented in the README): median-time-past and the 2-hour future-time rule.
    function _checkWork(bytes memory header, bytes32 hash, uint256 height, Checkpoint memory s) internal view {
        uint32 bits = BitcoinLib.nBits(header);
        uint32 time = BitcoinLib.timestamp(header);
        bool boundary = height % BitcoinLib.RETARGET_INTERVAL == 0;

        if (boundary && !NO_RETARGETING) {
            uint32 expected = BitcoinLib.retarget(s.bits, s.periodStartTime, s.time, POW_LIMIT);
            if (bits != expected) revert WrongDifficultyBits(height, expected, bits);
            s.bits = bits;
        } else if (ALLOW_MIN_DIFFICULTY && uint256(time) > uint256(s.time) + 2 * BitcoinLib.TARGET_SPACING) {
            uint32 minBits = BitcoinLib.targetToBits(POW_LIMIT);
            if (bits != minBits) revert WrongDifficultyBits(height, minBits, bits);
            // s.bits keeps the regular difficulty (only reachable with NO_RETARGETING, see constructor).
        } else if (bits != s.bits) {
            revert WrongDifficultyBits(height, s.bits, bits);
        }
        if (boundary) s.periodStartTime = time;

        uint256 target = BitcoinLib.bitsToTarget(bits);
        if (target > POW_LIMIT) revert TargetAbovePowLimit(height);
        if (BitcoinLib.reverse256(uint256(hash)) > target) revert InsufficientProofOfWork(height);
        s.chainWork += BitcoinLib.work(target);
        s.time = time;
    }

    // ── Transactions ─────────────────────────────────────────────────────────

    /// @dev Prove `m.rawTx` is in a final block of `chain`, then parse its CLPR commitment.
    /// @return t The parsed tx (txid, input-0 outpoint, vout 0/1 scripts).
    /// @return id The committed message id.
    /// @return payloadHash The committed sha256(payload).
    function _verifyClprTx(VerifiedChain memory chain, uint32 startHeight, TxProof memory m, bytes8 tag)
        internal
        pure
        returns (BitcoinLib.Tx memory t, uint64 id, bytes32 payloadHash)
    {
        if (m.headerIndex >= chain.merkleRoots.length) revert HeaderIndexOutOfRange();
        uint256 blockHeight = uint256(startHeight) + m.headerIndex;
        if (blockHeight > chain.finalHeight) revert InsufficientConfirmations(blockHeight, chain.finalHeight);

        t = BitcoinLib.parseTx(m.rawTx);
        if (BitcoinLib.computeMerkleRoot(t.txid, m.txIndex, m.merkleBranch) != chain.merkleRoots[m.headerIndex]) {
            revert MerkleProofInvalid();
        }
        // The coinbase (index 0) can never be a CLPR tx: its input spends nothing.
        if (m.txIndex == 0) revert NotACursorSpend();

        (id, payloadHash) = _parseCommitment(t.out0Script, tag);
    }

    /// @dev Parse `OP_RETURN PUSH53 "CLPR" ‖ 0x01 ‖ tag(8) ‖ hash(32) ‖ id(8, BE)`.
    function _parseCommitment(bytes memory script, bytes8 tag) internal pure returns (uint64 id, bytes32 payloadHash) {
        if (script.length != OP_RETURN_SCRIPT_LENGTH || script[0] != 0x6a || uint8(script[1]) != OP_RETURN_DATA_LENGTH)
        {
            revert MalformedCommitment();
        }
        bytes32 w0;
        bytes32 w1;
        assembly ("memory-safe") {
            w0 := mload(add(script, 0x22)) // data[0..32)
            w1 := mload(add(script, 0x42)) // data[32..53) + padding
        }
        if (bytes4(w0) != MAGIC || uint8(w0[4]) != MESSAGE_VERSION) revert MalformedCommitment();
        if (bytes8(w0 << 40) != tag) revert WrongChannelTag();
        // payload hash occupies data[13..45): 19 bytes from w0, 13 bytes from w1.
        payloadHash = (w0 << 104) | (w1 >> 152);
        // id occupies data[45..53): w1 bytes [13..21).
        id = uint64(bytes8(w1 << 104));
    }

    /// @dev The committed payload is final on Bitcoin, so a bad one cannot be rejected without
    ///      halting the channel forever. Instead, anything the CLPR Service would choke on (not a
    ///      DATA message, spoofed sender, bad target, unknown wire field, oversized) is delivered
    ///      as a REDACTED message carrying the committed hash — deterministic, so a relay gains no
    ///      discretion (it must still supply the exact preimage).
    function _deliverable(bytes memory payload, bytes32 payloadHash, bytes memory senderScript)
        internal
        view
        returns (bytes memory)
    {
        if (payload.length > 0 && payload.length <= MAX_PAYLOAD_BYTES) {
            try this.isDeliverableData(payload, senderScript) returns (bool ok) {
                if (ok) return payload;
            } catch {}
        }
        return ClprProtobuf.encodeRedactedMessage(payloadHash);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (TrustAnchor memory a) {
        // 11 static words: checkpoint(6) + cursorTxid, cursorVout, lastMessageId, runningHash, k.
        if (trustAnchor.length != 11 * 32) revert InvalidTrustAnchor();
        a = abi.decode(trustAnchor, (TrustAnchor));
        if (a.confirmations == 0) revert InvalidTrustAnchor();
    }

    function _anchorId(TrustAnchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.checkpoint.blockHash, a.lastMessageId);
    }

    function _copy(Checkpoint memory s) internal pure returns (Checkpoint memory) {
        return Checkpoint({
            blockHash: s.blockHash,
            height: s.height,
            chainWork: s.chainWork,
            bits: s.bits,
            time: s.time,
            periodStartTime: s.periodStartTime
        });
    }

    /// @dev Bitcoin enforces no CLPR throttles; these are placeholders that pass
    ///      `ClprTypes.validateThrottles`. Outbound traffic to Bitcoin is undeliverable regardless
    ///      (see README "receive-only peer").
    function _peerThrottles() internal view returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 1,
            // casting to 'uint64' is safe: constructor-supplied payload cap.
            // forge-lint: disable-next-line(unsafe-typecast)
            maxMessagePayloadBytes: uint64(MAX_PAYLOAD_BYTES),
            maxGasPerMessage: 1,
            maxQueueDepth: 1,
            maxSyncBytes: 1,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }
}
