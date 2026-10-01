// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {TonCells} from "@hiero-ledger/clpr/libraries/proof/ton/TonCells.sol";
import {TonBlocks} from "@hiero-ledger/clpr/libraries/proof/ton/TonBlocks.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";

/// @title TonVerifier
/// @notice TON → Hiero CLPR verifier: a TON masterchain light client (Ed25519 signatures of the
///         masterchain validators, key block by key block) plus BoC Merkle proofs from a signed
///         masterchain block to a contract account's persistent data.
///
/// Light-client rule (ton-blockchain/ton `crypto/block/check-proof.cpp`, `BlockProofLink::validate`):
/// a masterchain block B is signed by the masterchain validators — the first `main` entries of
/// ConfigParam 34 — of the config in B's previous key block (`BlockInfo.prev_key_block_seqno`), with
/// signed weight * 3 > total * 2 (`signature-set.cpp`). The trust anchor is that key block:
/// `keyBlockSeqno (u32 BE) ‖ keccak256(validators)`, validators packed as `pubkey ‖ uint64 weight`.
/// A key block signed by the anchor's set moves the anchor to its own config (rotation).
///
/// Signed message (`signature-set.cpp`), both modes supported:
///  - catchain (ordinary): TL `ton.blockId root_cell_hash file_hash` = 706e0bc5 ‖ root ‖ file;
///  - Simplex (TON mainnet and testnet today): TL `consensus.dataToSign session_id
///    data:(consensus.simplex.finalizeVote (consensus.candidateId slot sha256(candidate)))`, where the
///    candidate (`consensus.candidateHashData…`) names the block by `tonNode.blockIdExt` — checked
///    against the proven root hash and seqno.
///
/// Account proof: B.state_update → masterchain state → (basechain: McStateExtra.shard_hashes →
/// ShardDescr.root_hash → shard block.state_update → shard state) → ShardAccounts → Account →
/// StateInit.data. Each hop is a separate BoC whose level-0 root hash must equal the hash before it.
///
/// TON CLPR Service data layout (root data cell; trailing bits/refs are free for the service):
///   `config_commitment:bits256 manifest_commitment:bits256 channels:(HashmapE 256 ^ChannelQueue)`
///   `ChannelQueue = status:uint8 next_message_id:uint64 received_message_id:uint64
///                   sent_running_hash:bits256 received_running_hash:bits256 endpoint_manifest_version:uint64`
///   (712 bits, no refs). Service address = `workchain:int8 ‖ account_id:bits256` (33 bytes).
contract TonVerifier is ClprNearTonBundleVerifier {
    using TonCells for TonCells.Boc;

    struct BlockSignatures {
        uint8 mode; // 0 = catchain (ton.blockId), 1 = Simplex finalize vote
        bytes32 fileHash; // mode 0
        bytes32 sessionId; // mode 1
        uint32 slot; // mode 1
        bytes candidate; // mode 1: TL consensus.CandidateHashData (boxed)
        uint256[] signers; // strictly increasing indices into the validator list
        bytes[] signatures; // 64 bytes, or empty = pre-verified in the signature cache
    }

    struct McBlock {
        bytes boc; // Merkle proof of the block: header, plus state_update / config as needed
        BlockSignatures sigs;
    }

    struct StateChain {
        bytes mcState; // Merkle proof of the masterchain state (state_update new hash of the block)
        bytes shardBlock; // basechain only: shard block proof (root hash from ShardDescr)
        bytes shardState; // basechain only: shard state proof
        bytes account; // the Account cell tree (code may be pruned)
    }

    struct BundleProof {
        bytes validators; // the anchor's validator list
        McBlock[] keyBlocks; // key blocks moving the anchor forward, in order
        McBlock block; // the block whose state is proven
        StateChain state;
        bytes bundleContent;
        bytes manifestPreimage; // empty = no manifest in this bundle
    }

    struct ConfigProof {
        bytes validators; // the checkpoint's validator list
        McBlock[] keyBlocks;
        McBlock block;
        StateChain state;
        bytes controlMessage; // keccak256 == config_commitment
    }

    uint256 internal constant ANCHOR_LENGTH = 36;
    uint256 internal constant QUEUE_BITS = 712;
    uint256 internal constant MC_SHARD = 0x8000000000000000;

    IEd25519Verifier public immutable ED25519;
    ClprEd25519SignatureCache public immutable SIGNATURE_CACHE;
    bytes32 public immutable CHAIN_ID_HASH;
    uint32 public immutable CHECKPOINT_KEY_BLOCK;
    bytes32 public immutable CHECKPOINT_SET_HASH;

    error InvalidAnchor();
    error ValidatorsMismatch();
    error NotMasterchain();
    error WrongKeyBlock(uint32 expected, uint32 got);
    error NotKeyBlock();
    error BadCandidate();
    error BadSignatureMode();
    error SignersNotAscending();
    error SignerOutOfRange();
    error InsufficientWeight(uint256 signed, uint256 total);
    error ZeroAddress();

    constructor(
        string memory chainId,
        uint32 checkpointKeyBlock,
        bytes32 checkpointSetHash,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache signatureCache
    ) {
        if (address(ed25519) == address(0)) revert ZeroAddress();
        ED25519 = ed25519;
        SIGNATURE_CACHE = signatureCache;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
        CHECKPOINT_KEY_BLOCK = checkpointKeyBlock;
        CHECKPOINT_SET_HASH = checkpointSetHash;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof).
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
        (uint32 keySeq, bytes32 setHash) = decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        (int8 wc, bytes32 addr) = _serviceAddress(ctx.remoteServiceAddress);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (TonCells.Boc memory data, uint32 endSeq, bytes32 endHash,) =
            _verifyToData(keySeq, setHash, p.validators, p.keyBlocks, p.block, p.state, wc, addr);

        (, bytes32 manC, uint256 channels) = _serviceData(data);
        metadata = _channelQueue(data, channels, ctx.channelId);
        messagePayloads = _decodeBundleContent(p.bundleContent);
        newEndpointManifest = p.manifestPreimage.length == 0
            ? _absentEndpointManifest()
            : _bindManifest(p.manifestPreimage, manC, ctx.remoteServiceAddress);
        if (endSeq != keySeq) {
            newTrustAnchor = abi.encodePacked(endSeq, endHash);
            newTrustAnchorId = abi.encodePacked(endSeq);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof) from the deploy-time checkpoint; the
    ///      ControlMessage is bound by the service's `config_commitment`. A non-empty
    ///      `endpointManifestProofBytes` is the manifest preimage, bound by `manifest_commitment`
    ///      of the same proven data cell.
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
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        ClprTypes.LedgerConfiguration memory lc =
            _bindConfig(p.controlMessage, keccak256(p.controlMessage), CHAIN_ID_HASH);
        serviceAddress = lc.serviceAddress;
        (int8 wc, bytes32 addr) = _serviceAddress(serviceAddress);

        (TonCells.Boc memory data, uint32 endSeq, bytes32 endHash,) = _verifyToData(
            CHECKPOINT_KEY_BLOCK, CHECKPOINT_SET_HASH, p.validators, p.keyBlocks, p.block, p.state, wc, addr
        );
        (bytes32 cfgC, bytes32 manC,) = _serviceData(data);
        if (cfgC != keccak256(p.controlMessage)) revert ConfigCommitmentMismatch();

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = abi.encodePacked(endSeq, endHash);
        initialTrustAnchorId = abi.encodePacked(endSeq);
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _bindManifest(endpointManifestProofBytes, manC, serviceAddress);
    }

    // ── Generic entry point ──────────────────────────────────────────────────

    /// @notice Verify key blocks and a signed masterchain block from `trustAnchor`, then an account's
    ///         state. Returns the account's data-cell hash, the block's seqno and the new anchor
    ///         (empty if no key block was crossed). Used by the live tests (no CLPR Service on TON yet).
    function verifyAccountData(
        bytes calldata validators,
        bytes calldata keyBlocks,
        bytes calldata blockProof,
        bytes calldata stateChain,
        bytes calldata serviceAddress,
        bytes calldata trustAnchor
    ) external view returns (bytes32 dataHash, uint32 seqno, bytes memory newTrustAnchor) {
        (uint32 keySeq, bytes32 setHash) = decodeAnchor(trustAnchor);
        (int8 wc, bytes32 addr) = _serviceAddress(serviceAddress);
        McBlock[] memory kb = keyBlocks.length == 0 ? new McBlock[](0) : abi.decode(keyBlocks, (McBlock[]));
        McBlock memory blk = abi.decode(blockProof, (McBlock));
        StateChain memory st = abi.decode(stateChain, (StateChain));
        TonCells.Boc memory data;
        uint32 endSeq;
        bytes32 endHash;
        (data, endSeq, endHash, seqno) = _verifyToData(keySeq, setHash, validators, kb, blk, st, wc, addr);
        dataHash = data.cells[data.root].hashes[0];
        if (endSeq != keySeq) newTrustAnchor = abi.encodePacked(endSeq, endHash);
    }

    function decodeAnchor(bytes calldata a) public pure returns (uint32 keySeq, bytes32 setHash) {
        if (a.length != ANCHOR_LENGTH) revert InvalidAnchor();
        keySeq = uint32(bytes4(a[0:4]));
        setHash = bytes32(a[4:36]);
    }

    // ── internals ────────────────────────────────────────────────────────────

    function _verifyToData(
        uint32 keySeq,
        bytes32 setHash,
        bytes memory validators,
        McBlock[] memory keyBlocks,
        McBlock memory blk,
        StateChain memory st,
        int8 wc,
        bytes32 addr
    ) internal view returns (TonCells.Boc memory data, uint32 endSeq, bytes32 endHash, uint32 seqno) {
        if (keccak256(validators) != setHash) revert ValidatorsMismatch();
        for (uint256 i = 0; i < keyBlocks.length; i++) {
            (TonCells.Boc memory kb, TonBlocks.BlockInfo memory ki) = _verifyMcBlock(keySeq, validators, keyBlocks[i]);
            if (!ki.keyBlock) revert NotKeyBlock();
            (validators,) = TonBlocks.keyBlockValidators(kb, kb.root);
            keySeq = ki.seqno;
        }
        endSeq = keySeq;
        endHash = keccak256(validators);

        (TonCells.Boc memory b, TonBlocks.BlockInfo memory bi) = _verifyMcBlock(keySeq, validators, blk);
        seqno = bi.seqno;
        bytes32 stateHash = TonBlocks.newStateHash(b, b.root);
        TonCells.Boc memory mcState = TonCells.parseExpect(st.mcState, stateHash);
        TonCells.Boc memory accountState = mcState;
        if (wc != -1) {
            bytes32 shardRoot = TonBlocks.shardBlockRoot(mcState, int32(wc), addr);
            TonCells.Boc memory sb = TonCells.parseExpect(st.shardBlock, shardRoot);
            TonBlocks.BlockInfo memory si = TonBlocks.blockInfo(sb, sb.root);
            if (!si.notMaster || si.workchain != int32(wc)) revert NotMasterchain();
            accountState = TonCells.parseExpect(st.shardState, TonBlocks.newStateHash(sb, sb.root));
        }
        TonCells.Boc memory acc = TonCells.parseExpect(st.account, TonBlocks.accountHash(accountState, addr));
        uint256 dataCell = TonBlocks.accountData(acc, wc, addr);
        // Re-root the account tree at its data cell so callers read it through `data.root`.
        acc.root = dataCell;
        data = acc;
    }

    /// @dev Check one masterchain block: header, previous key block = the anchor, and > 2/3 weight.
    function _verifyMcBlock(uint32 keySeq, bytes memory validators, McBlock memory m)
        internal
        view
        returns (TonCells.Boc memory b, TonBlocks.BlockInfo memory info)
    {
        b = TonCells.parse(m.boc);
        bytes32 rootHash = b.cells[b.root].hashes[0];
        info = TonBlocks.blockInfo(b, b.root);
        if (info.notMaster || info.workchain != -1) revert NotMasterchain();
        if (info.prevKeyBlockSeqno != keySeq) revert WrongKeyBlock(keySeq, info.prevKeyBlockSeqno);
        bytes memory message = _signedMessage(m.sigs, rootHash, info.seqno);
        _checkSignatures(validators, m.sigs, message);
    }

    function _signedMessage(BlockSignatures memory s, bytes32 rootHash, uint32 seqno)
        internal
        pure
        returns (bytes memory)
    {
        if (s.mode == 0) {
            return abi.encodePacked(bytes4(0x706e0bc5), rootHash, s.fileHash); // ton.blockId
        }
        if (s.mode != 1) revert BadSignatureMode();
        bytes memory c = s.candidate;
        // consensus.candidateHashDataOrdinary#e8f9bcdc | consensus.candidateHashDataEmpty#72b4d933,
        // then block:tonNode.blockIdExt = workchain:int shard:long seqno:int root_hash file_hash
        if (c.length < 84) revert BadCandidate();
        bytes4 ctor = bytes4(_bytes32At(c, 0));
        if (ctor != bytes4(0xdcbcf9e8) && ctor != bytes4(0x33d9b472)) revert BadCandidate();
        if (bytes4(_bytes32At(c, 4)) != bytes4(0xffffffff)) revert BadCandidate(); // workchain -1 (LE)
        if (bytes8(_bytes32At(c, 8)) != bytes8(0x0000000000000080)) revert BadCandidate(); // mc shard (LE)
        if (bytes4(_bytes32At(c, 16)) != _le32(seqno) || _bytes32At(c, 20) != rootHash) revert BadCandidate();
        bytes memory vote = abi.encodePacked(
            bytes4(0x05e1a740), // consensus.simplex.finalizeVote
            bytes4(0x3fcd91b6), // consensus.candidateId
            _le32(s.slot),
            sha256(c)
        );
        // TL bytes: 1-byte length (44) + payload + 3 bytes padding
        return abi.encodePacked(bytes4(0xf83de3a8), s.sessionId, uint8(44), vote, bytes3(0));
    }

    function _checkSignatures(bytes memory validators, BlockSignatures memory s, bytes memory message) internal view {
        uint256 n = validators.length / 40;
        uint256 total;
        for (uint256 i = 0; i < n; i++) {
            total += _weight(validators, i);
        }
        if (s.signatures.length != s.signers.length) revert SignerOutOfRange();
        bytes32 mh = keccak256(message);
        uint256 signed;
        for (uint256 i = 0; i < s.signers.length; i++) {
            uint256 idx = s.signers[i];
            if (i > 0 && idx <= s.signers[i - 1]) revert SignersNotAscending();
            if (idx >= n) revert SignerOutOfRange();
            ClprEd25519Check.check(
                ED25519, SIGNATURE_CACHE, _bytes32At(validators, idx * 40), message, mh, s.signatures[i], idx
            );
            signed += _weight(validators, idx);
        }
        if (signed * 3 <= total * 2) revert InsufficientWeight(signed, total);
    }

    function _weight(bytes memory v, uint256 i) private pure returns (uint256) {
        return uint64(bytes8(_bytes32At(v, i * 40 + 32)));
    }

    /// @dev Service data root: config_commitment, manifest_commitment, channels dict root (or 0).
    function _serviceData(TonCells.Boc memory b) internal pure returns (bytes32 cfgC, bytes32 manC, uint256 channels) {
        TonCells.Slice memory s = b.open(b.root);
        cfgC = bytes32(b.loadUint(s, 256));
        manC = bytes32(b.loadUint(s, 256));
        channels = b.loadBit(s) ? b.loadRef(s) : type(uint256).max;
    }

    function _channelQueue(TonCells.Boc memory b, uint256 channels, bytes32 channelId)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory)
    {
        if (channels == type(uint256).max) revert TonCells.KeyNotFound();
        TonCells.Slice memory leaf = b.lookup(channels, uint256(channelId), 256);
        uint256 q = b.loadRef(leaf);
        TonCells.Slice memory s = b.open(q);
        if (b.cells[q].bits != QUEUE_BITS || b.cells[q].refCount != 0) revert InvalidQueueRecord();
        uint8 status = uint8(b.loadUint(s, 8));
        uint64 nextId = uint64(b.loadUint(s, 64));
        uint64 recvId = uint64(b.loadUint(s, 64));
        bytes32 sent = bytes32(b.loadUint(s, 256));
        bytes32 recv = bytes32(b.loadUint(s, 256));
        uint64 ver = uint64(b.loadUint(s, 64));
        return _queueMetadata(status, nextId, recvId, sent, recv, ver);
    }

    function _serviceAddress(bytes memory a) internal pure returns (int8 wc, bytes32 addr) {
        if (a.length != 33) revert InvalidServiceAddress();
        wc = int8(uint8(a[0]));
        if (wc != 0 && wc != -1) revert InvalidServiceAddress();
        addr = _bytes32At(a, 1);
    }

    function _le32(uint32 v) private pure returns (bytes4) {
        return bytes4(uint32((v & 0xff) << 24 | ((v >> 8) & 0xff) << 16 | ((v >> 16) & 0xff) << 8 | (v >> 24)));
    }
}
