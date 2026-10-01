// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RskHeader} from "@hiero-ledger/clpr/libraries/proof/rootstock/RskHeader.sol";
import {RskUnitrie} from "@hiero-ledger/clpr/libraries/proof/rootstock/RskUnitrie.sol";

/// @title RootstockVerifier
/// @notice Rootstock (RSK) → Hiero CLPR verifier. A merged-mining proof-of-work light client: it
///         follows RSK headers whose work is proven by a Bitcoin header + coinbase commitment, waits
///         for `k` confirmations, then proves the CLPR Service's storage (the unmodified Solidity
///         `ClprService`, deployed on RSK) through RSK's Unitrie — not the Ethereum MPT.
///         See README.md in this directory for design, trust assumptions and limits.
///
/// Trust anchor: ABI-encoded {Anchor} (a final RSK block plus the service's code hash).
contract RootstockVerifier is ClprEvmBundleVerifier {
    // ── Types ────────────────────────────────────────────────────────────────

    struct Params {
        string chainId; // CAIP-2, e.g. "eip155:30"
        uint64 confirmations; // k ≥ 1: a block is final when tip − number + 1 ≥ k
        uint256 minDifficulty; // Constants.minimumDifficulty (mainnet 7e15)
        uint256 difficultyDivisor; // 400 after RSKIP156 (mainnet); 2048 on regtest
        uint256 durationLimit; // seconds per block target (mainnet 14, regtest 10)
        uint256 forkDetectionFrom; // RSKIP110 activation height (mainnet 1,591,000)
        uint256 maxBtcTimestampDiff; // RSKIP179 bound (300 s); 0 disables the timestamp rules (regtest)
    }

    /// @notice A final (k-confirmed) RSK block: everything needed to validate its successor.
    struct Checkpoint {
        bytes32 blockHash;
        uint256 number;
        uint256 difficulty;
        uint256 timestamp;
        uint256 work; // Σ header difficulty from the deployment checkpoint (uncles not counted)
    }

    struct Anchor {
        Checkpoint checkpoint;
        bytes32 codeHash; // pinned CLPR Service runtime code hash
    }

    /// @notice One RSK header and its merged-mining proof.
    struct MinedHeader {
        bytes header; // exact hash preimage (rsk_getRawBlockHeaderByNumber)
        bytes coinbase; // bitcoinMergedMiningCoinbaseTransaction
        bytes merkleProof; // bitcoinMergedMiningMerkleProof
    }

    /// @notice `proofBytes` of {verifyBundle}.
    struct BundleProof {
        MinedHeader[] headers; // anchor.number + 1, + 2, …
        uint256 stateIndex; // header whose stateRoot is proven; needs ≥ k confirmations
        bytes[] codeProof; // Unitrie nodes for the service's code key (proves account + code hash)
        bytes[][] slotProofs; // 5 channel slots (+ last-message running hash when messages are sent)
        bytes bundleContent; // ClprBundleContent protobuf
        bytes manifestPreimage; // optional endpoint-manifest update ...
        bytes[] manifestProof; // ... and the Unitrie proof of its commitment slot
        Checkpoint start; // where `headers` begin: zero blockHash = the anchor, else a checkpoint
        //                   recorded by {extend} that descends from the anchor
    }

    /// @notice `configProofBytes` of {verifyConfig}.
    struct ConfigProof {
        MinedHeader[] headers; // deployment checkpoint + 1, …
        uint256 stateIndex;
        address service;
        bytes[] codeProof;
        uint96 peerConfigNanos;
        ClprTypes.Throttles throttles;
    }

    /// @notice `endpointManifestProofBytes` of {verifyConfig}: proven against the config's state root.
    struct ConfigManifestProof {
        bytes manifestPreimage;
        bytes[] manifestProof;
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    error RskBadParams();
    error RskNoHeaders();
    error RskParentMismatch();
    error RskNumberMismatch();
    error RskDifficultyMismatch();
    error RskTimestampNotIncreasing();
    error RskBtcTimestampSkew();
    error RskNotFinal();
    error RskServiceNotDeployed();
    error RskBadSlotProofCount();
    error RskStartNotRecorded();

    event CheckpointExtended(bytes32 indexed fromId, bytes32 indexed toId, uint256 number, bytes32 blockHash);

    // ── Immutable configuration ──────────────────────────────────────────────

    bytes32 internal immutable CHAIN_ID_HASH;
    string internal chainIdString;
    uint256 public immutable CONFIRMATIONS;
    uint256 public immutable MIN_DIFFICULTY;
    uint256 public immutable DIFFICULTY_DIVISOR;
    uint256 public immutable DURATION_LIMIT;
    uint256 public immutable FORK_DETECTION_FROM;
    uint256 public immutable MAX_BTC_TIMESTAMP_DIFF;

    /// @notice How many {extend} records a bundle may walk back to reach its anchor.
    uint256 public constant MAX_EXTENSIONS = 256;

    /// @notice checkpointId(to) → checkpointId(from) for every header run proven by {extend}.
    mapping(bytes32 => bytes32) public extendedFrom;

    bytes32 public immutable GENESIS_HASH;
    uint256 public immutable GENESIS_NUMBER;
    uint256 public immutable GENESIS_DIFFICULTY;
    uint256 public immutable GENESIS_TIMESTAMP;

    /// @param p network parameters
    /// @param genesis the deployment checkpoint: a deep, canonical RSK block chosen by the deployer
    constructor(Params memory p, Checkpoint memory genesis) {
        if (p.confirmations == 0 || p.difficultyDivisor == 0 || p.durationLimit == 0) revert RskBadParams();
        chainIdString = p.chainId;
        CHAIN_ID_HASH = keccak256(bytes(p.chainId));
        CONFIRMATIONS = p.confirmations;
        MIN_DIFFICULTY = p.minDifficulty;
        DIFFICULTY_DIVISOR = p.difficultyDivisor;
        DURATION_LIMIT = p.durationLimit;
        FORK_DETECTION_FROM = p.forkDetectionFrom;
        MAX_BTC_TIMESTAMP_DIFF = p.maxBtcTimestampDiff;
        GENESIS_HASH = genesis.blockHash;
        GENESIS_NUMBER = genesis.number;
        GENESIS_DIFFICULTY = genesis.difficulty;
        GENESIS_TIMESTAMP = genesis.timestamp;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

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
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));
        address service = _toAddress(ctx.remoteServiceAddress);

        Checkpoint memory from = anchor.checkpoint;
        if (p.start.blockHash != bytes32(0)) {
            requireDescends(anchor.checkpoint, p.start);
            from = p.start;
        }
        (Checkpoint memory finalCp, bytes32 stateRoot) = _followChain(from, p.headers, p.stateIndex);
        _verifyCode(stateRoot, service, p.codeProof, anchor.codeHash);

        metadata = _verifyChannelSlots(stateRoot, service, ctx.channelId, p.slotProofs);
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (p.manifestPreimage.length != 0) {
            newEndpointManifest =
                _verifyRskManifest(stateRoot, service, p.manifestPreimage, p.manifestProof, ctx.remoteServiceAddress);
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }

        anchor.checkpoint = finalCp;
        newTrustAnchor = abi.encode(anchor);
        newTrustAnchorId = abi.encodePacked(finalCp.blockHash);
    }

    /// @inheritdoc IClprVerifier
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
        ConfigProof memory c = abi.decode(configProofBytes, (ConfigProof));
        Checkpoint memory genesis = Checkpoint({
            blockHash: GENESIS_HASH,
            number: GENESIS_NUMBER,
            difficulty: GENESIS_DIFFICULTY,
            timestamp: GENESIS_TIMESTAMP,
            work: 0
        });
        (Checkpoint memory finalCp, bytes32 stateRoot) = _followChain(genesis, c.headers, c.stateIndex);

        // The code hash is read from the proven state, never taken from the operator.
        RskUnitrie.Value memory code = RskUnitrie.get(stateRoot, RskUnitrie.codeKey(c.service), c.codeProof);
        if (!code.found) revert RskServiceNotDeployed();

        serviceAddress = abi.encodePacked(c.service);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            ConfigManifestProof memory m = abi.decode(endpointManifestProofBytes, (ConfigManifestProof));
            endpointManifest =
                _verifyRskManifest(stateRoot, c.service, m.manifestPreimage, m.manifestProof, serviceAddress);
        }
        chainId = chainIdString;
        peerConfigNanos = c.peerConfigNanos;
        throttles = c.throttles;
        initialTrustAnchor = abi.encode(Anchor({checkpoint: finalCp, codeHash: code.valueHash}));
        initialTrustAnchorId = abi.encodePacked(finalCp.blockHash);
    }

    // ── Catch-up: header runs proven ahead of a bundle ───────────────────────

    /// @notice Prove `headers` on top of `from` (same checks as a bundle) and record the k-final
    ///         checkpoint they reach. Permissionless: a record only says "this checkpoint follows from
    ///         that one with valid merged-mining work"; a bundle uses it only when the chain of records
    ///         leads back to its own anchor. Lets a channel catch up after more RSK blocks than one
    ///         transaction can carry.
    function extend(Checkpoint calldata from, MinedHeader[] calldata headers) external returns (Checkpoint memory to) {
        (to,) = _followChain(from, headers, 0);
        bytes32 toId = checkpointId(to);
        if (extendedFrom[toId] == bytes32(0)) {
            bytes32 fromId = checkpointId(from);
            extendedFrom[toId] = fromId;
            emit CheckpointExtended(fromId, toId, to.number, to.blockHash);
        }
    }

    function checkpointId(Checkpoint memory c) public pure returns (bytes32) {
        return keccak256(abi.encode(c));
    }

    /// @notice Reverts unless `start` is `anchor` or reachable from it through {extendedFrom} records.
    function requireDescends(Checkpoint memory anchor, Checkpoint memory start) public view {
        bytes32 target = checkpointId(anchor);
        bytes32 cur = checkpointId(start);
        if (cur == target) return;
        for (uint256 i = 0; i < MAX_EXTENSIONS; ++i) {
            cur = extendedFrom[cur];
            if (cur == target) return;
            if (cur == bytes32(0)) break;
        }
        revert RskStartNotRecorded();
    }

    // ── Header chain ─────────────────────────────────────────────────────────

    /// @dev Validate `headers` on top of `cp` (parent link, number, difficulty rule, timestamps,
    ///      merged-mining PoW). Returns the new final checkpoint (tip − k + 1, never behind `cp`) and the
    ///      state root of `headers[stateIndex]`, which must itself be final.
    function _followChain(Checkpoint memory cp, MinedHeader[] memory headers, uint256 stateIndex)
        internal
        view
        returns (Checkpoint memory finalCp, bytes32 stateRoot)
    {
        uint256 n = headers.length;
        if (n == 0) revert RskNoHeaders();
        // Final iff confirmations = n − i ≥ k  ⇔  i ≤ n − k.
        if (n < CONFIRMATIONS || stateIndex > n - CONFIRMATIONS) revert RskNotFinal();
        uint256 finalIndex = n - CONFIRMATIONS;

        Checkpoint memory parent = cp;
        for (uint256 i = 0; i < n; ++i) {
            RskHeader.Header memory h = RskHeader.parse(headers[i].header, headers[i].coinbase, FORK_DETECTION_FROM);
            if (h.parentHash != parent.blockHash) revert RskParentMismatch();
            if (h.number != parent.number + 1) revert RskNumberMismatch();
            if (MAX_BTC_TIMESTAMP_DIFF != 0) {
                if (h.timestamp <= parent.timestamp) revert RskTimestampNotIncreasing();
                uint256 btcTime = _btcTime(h.btcHeader);
                uint256 diff = btcTime > h.timestamp ? btcTime - h.timestamp : h.timestamp - btcTime;
                if (diff >= MAX_BTC_TIMESTAMP_DIFF) revert RskBtcTimestampSkew();
            }
            uint256 expected = RskHeader.expectedDifficulty(
                parent.difficulty,
                parent.timestamp,
                h.timestamp,
                h.uncleCount,
                DURATION_LIMIT,
                DIFFICULTY_DIVISOR,
                MIN_DIFFICULTY
            );
            if (h.difficulty != expected) revert RskDifficultyMismatch();
            RskHeader.verifyMergedMining(h, headers[i].coinbase, headers[i].merkleProof);

            parent = Checkpoint({
                blockHash: h.hash,
                number: h.number,
                difficulty: h.difficulty,
                timestamp: h.timestamp,
                work: parent.work + h.difficulty
            });
            if (i == stateIndex) stateRoot = h.stateRoot;
            if (i == finalIndex) finalCp = parent;
        }
    }

    function _btcTime(bytes memory btcHeader) private pure returns (uint256 t) {
        for (uint256 i = 0; i < 4; ++i) {
            t |= uint256(uint8(btcHeader[68 + i])) << (8 * i);
        }
    }

    // ── Unitrie state ────────────────────────────────────────────────────────

    function _verifyCode(bytes32 stateRoot, address service, bytes[] memory codeProof, bytes32 codeHash) internal pure {
        RskUnitrie.Value memory code = RskUnitrie.get(stateRoot, RskUnitrie.codeKey(service), codeProof);
        if (!code.found) revert RskServiceNotDeployed();
        if (codeHash != bytes32(0) && code.valueHash != codeHash) revert CodeHashMismatch();
    }

    /// @dev The five Channel slots (+ the last sent message's running-hash slot when present), keys
    ///      derived from the CLPR storage layout, values proven (inclusion or exclusion) in the Unitrie.
    function _verifyChannelSlots(bytes32 stateRoot, address service, bytes32 channelId, bytes[][] memory proofs)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        if (proofs.length != 5 && proofs.length != 6) revert RskBadSlotProofCount();
        bytes32[] memory slots = _channelMetadataSlots(channelId);
        bytes32[] memory values = new bytes32[](5);
        for (uint256 i = 0; i < 5; ++i) {
            values[i] =
                RskUnitrie.storageWord(RskUnitrie.get(stateRoot, RskUnitrie.storageKey(service, slots[i]), proofs[i]));
        }
        metadata = _buildQueueMetadata(values);
        if (proofs.length == 6) {
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            // Proven only for shape parity with the MPT verifiers (the service checks the running hash).
            RskUnitrie.get(
                stateRoot,
                RskUnitrie.storageKey(service, _lastMessageRunningHashSlot(channelId, metadata.nextMessageId - 1)),
                proofs[5]
            );
        }
    }

    function _verifyRskManifest(
        bytes32 stateRoot,
        address service,
        bytes memory preimage,
        bytes[] memory proof,
        bytes memory expectedServiceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory manifest) {
        bytes32 commitment = RskUnitrie.storageWord(
            RskUnitrie.get(stateRoot, RskUnitrie.storageKey(service, bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT)), proof)
        );
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ── Generic entry point (live tests, tooling) ────────────────────────────

    /// @notice Follow `headers` from `trustAnchor` and read one storage slot of `account` at
    ///         `headers[stateIndex]`. Runs the same header and Unitrie checks as {verifyBundle}
    ///         without the CLPR record checks.
    function verifyStorage(
        bytes calldata trustAnchor,
        MinedHeader[] calldata headers,
        uint256 stateIndex,
        address account,
        bytes32 slot,
        bytes[] calldata proof
    ) external view returns (bytes32 value, Checkpoint memory finalCp) {
        Anchor memory anchor = abi.decode(trustAnchor, (Anchor));
        bytes32 stateRoot;
        (finalCp, stateRoot) = _followChain(anchor.checkpoint, headers, stateIndex);
        value = RskUnitrie.storageWord(RskUnitrie.get(stateRoot, RskUnitrie.storageKey(account, slot), proof));
    }

    /// @notice Header-chain only: the checkpoint `headers` reach from `checkpoint`.
    function verifyHeaders(Checkpoint calldata checkpoint, MinedHeader[] calldata headers)
        external
        view
        returns (Checkpoint memory finalCp)
    {
        (finalCp,) = _followChain(checkpoint, headers, 0);
    }
}
