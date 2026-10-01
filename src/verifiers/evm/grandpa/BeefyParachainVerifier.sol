// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {BeefyLib} from "@hiero-ledger/clpr/libraries/proof/substrate/BeefyLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {SubstrateEvmVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateEvmVerifierBase.sol";

/// @title BeefyParachainVerifier
/// @notice "Polkadot parachain → Hiero" verifier: relay-chain finality from BEEFY (secp256k1,
///         `ecrecover`), the parachain head from relay-chain state, and Frontier EVM storage from
///         the parachain's state trie. Built for Hydration (para 2034); any Frontier parachain of
///         the same relay chain is a deploy-time profile. See README.md in this directory.
///
/// Why not the BEEFY leaf's para-heads root: Polkadot's `leaf_extra` merkelizes only lifecycle
/// `Parachain`s (+ a whitelist). Since agile coretime, Hydration's lifecycle is `Parathread`, so its
/// head is not in that root; it is proven in relay state (`Paras::Heads`) instead.
///
/// ## Trust anchor (92 bytes)
///   current{id u64, len u32, root 32} ‖ next{id u64, len u32, root 32} ‖ minRelayBlock u32 (all BE)
///   — the BEEFY authority sets (as in the MMR leaf's BeefyAuthoritySet) and the oldest relay block a
///   commitment may be for.
///
/// ## Verification chain (verifyBundle)
///   For each commit (all but the last must rotate the set):
///     1. Decode the signed commitment; block_number ≥ minRelayBlock.
///     2. validator_set_id is current.id, or next.id (⇒ rotation).
///     3. The supplied authority addresses must re-merkelize to that set's root; >2/3 (n − (n−1)/3)
///        signatures over keccak256(commitment) by those addresses.
///     4. The MMR leaf of the commitment block (parent_number + 1 == block_number) is in the
///        commitment's "mh" MMR root; its beefy_next_authority_set.id must be validator_set_id + 1.
///     5. Rotation: anchor := (next, leaf.next, block_number).
///   Then, from the last leaf: relay header with blake2_256 = leaf.parent_hash → relay state_root →
///   `Paras::Heads(paraId)` (trie proof) → parachain header → para state_root → `AccountStorages`.
contract BeefyParachainVerifier is SubstrateEvmVerifierBase {
    struct Commit {
        bytes commitment;
        bytes signers;
        bytes signatures;
        bytes authorities;
        bytes mmrLeaf;
        bytes32[] mmrPath;
        uint256 mmrPathSides;
    }

    struct BundleProof {
        Commit[] commits;
        bytes relayHeader;
        bytes[] relayStateProof;
        bytes[] paraStateProof;
        bool lastMessageSlot;
        bytes bundleContent;
        bytes manifestPreimage;
    }

    struct ConfigProof {
        Commit[] commits;
        bytes relayHeader;
        bytes[] relayStateProof;
        bytes[] paraStateProof;
        bytes ledgerConfig;
    }

    struct Anchor {
        BeefyLib.AuthoritySet current;
        BeefyLib.AuthoritySet next;
        uint32 minRelayBlock;
    }

    /// @dev Relay-chain result of the commits: the anchor after them and the parachain state root.
    struct RelayResult {
        Anchor anchor;
        bytes32 paraStateRoot;
        uint32 paraNumber;
    }

    uint256 internal constant ANCHOR_LENGTH = 92;

    /// @notice Parachain id (Hydration: 2034).
    uint32 public immutable PARA_ID;
    /// @notice Relay storage key of `Paras::Heads(PARA_ID)`:
    ///         twox128("Paras") ‖ twox128("Heads") ‖ twox64(paraId LE) ‖ paraId LE (44 bytes),
    ///         stored as its first 32 bytes and last 12 bytes.
    bytes32 public immutable PARA_HEAD_KEY_HI;
    bytes12 public immutable PARA_HEAD_KEY_LO;

    bytes32 internal immutable BOOT_CURRENT_ROOT;
    bytes32 internal immutable BOOT_NEXT_ROOT;
    uint64 internal immutable BOOT_CURRENT_ID;
    uint32 internal immutable BOOT_CURRENT_LEN;
    uint32 internal immutable BOOT_NEXT_LEN;
    uint32 internal immutable BOOT_MIN_RELAY_BLOCK;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error UnknownValidatorSet(uint64 id);
    error CommitWithoutRotation();
    error LeafNotForCommitmentBlock();
    error LeafNextSetMismatch();
    error RelayHeaderMismatch();
    error ParaHeadNotFound();
    error InvalidParaHead();

    /// @param paraHeadKey 44-byte relay storage key of Paras::Heads(paraId) (computed off-chain;
    ///                    its last 4 bytes must be paraId LE).
    /// @param bootstrap   Weak-subjectivity checkpoint: the BEEFY current and next authority sets
    ///                    (pallet_beefy_mmr BeefyAuthorities / BeefyNextAuthorities) and the first
    ///                    relay block a commitment may be for.
    constructor(
        bytes16 evmPalletPrefix,
        string memory chainId,
        uint32 paraId,
        bytes memory paraHeadKey,
        Anchor memory bootstrap
    ) SubstrateEvmVerifierBase(evmPalletPrefix, chainId) {
        if (paraHeadKey.length != 44 || bytes4(ScaleCodec.le32(paraId)) != _last4(paraHeadKey)) {
            revert InvalidProfile();
        }
        if (
            bootstrap.current.root == bytes32(0) || bootstrap.next.root == bytes32(0) || bootstrap.current.len == 0
                || bootstrap.next.len == 0 || bootstrap.next.id != bootstrap.current.id + 1
        ) revert InvalidProfile();
        PARA_ID = paraId;
        PARA_HEAD_KEY_HI = ScaleCodec.readBytes32(paraHeadKey, 0);
        PARA_HEAD_KEY_LO = bytes12(ScaleCodec.readBytes32(paraHeadKey, 12) << 160);
        BOOT_CURRENT_ROOT = bootstrap.current.root;
        BOOT_NEXT_ROOT = bootstrap.next.root;
        BOOT_CURRENT_ID = bootstrap.current.id;
        BOOT_CURRENT_LEN = bootstrap.current.len;
        BOOT_NEXT_LEN = bootstrap.next.len;
        BOOT_MIN_RELAY_BLOCK = bootstrap.minRelayBlock;
    }

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof); trustAnchor = 92-byte {Anchor}.
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
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (proofBytes.length == 0) revert InvalidPayloadShape();
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        RelayResult memory r = _verifyRelay(p.commits, anchor, p.relayHeader, p.relayStateProof);
        (metadata, newEndpointManifest) = _verifyChannelState(
            p.paraStateProof,
            r.paraStateRoot,
            ctx.remoteServiceAddress,
            ctx.channelId,
            p.lastMessageSlot,
            p.manifestPreimage
        );
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (r.anchor.current.id != anchor.current.id) {
            newTrustAnchor = _encodeAnchor(r.anchor);
            newTrustAnchorId = abi.encodePacked(r.anchor.current.id);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), followed from the deploy-time bootstrap
    ///      checkpoint; endpointManifestProofBytes = manifest preimage (or empty), proven against the
    ///      same parachain state root.
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
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        RelayResult memory r = _verifyRelay(p.commits, bootstrapAnchor(), p.relayHeader, p.relayStateProof);

        ClprTypes.LedgerConfiguration memory lc;
        (lc, endpointManifest) =
            _verifyConfigState(p.paraStateProof, r.paraStateRoot, p.ledgerConfig, endpointManifestProofBytes);
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = _encodeAnchor(r.anchor);
        initialTrustAnchorId = abi.encodePacked(r.anchor.current.id);
    }

    /// @notice The deploy-time bootstrap anchor.
    function bootstrapAnchor() public view returns (Anchor memory a) {
        a.current = BeefyLib.AuthoritySet({id: BOOT_CURRENT_ID, len: BOOT_CURRENT_LEN, root: BOOT_CURRENT_ROOT});
        a.next = BeefyLib.AuthoritySet({id: BOOT_CURRENT_ID + 1, len: BOOT_NEXT_LEN, root: BOOT_NEXT_ROOT});
        a.minRelayBlock = BOOT_MIN_RELAY_BLOCK;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Relay chain
    // ─────────────────────────────────────────────────────────────────────────

    function _verifyRelay(
        Commit[] memory commits,
        Anchor memory a,
        bytes memory relayHeader,
        bytes[] memory relayStateProof
    ) internal view returns (RelayResult memory r) {
        if (commits.length == 0) revert InvalidPayloadShape();
        BeefyLib.MmrLeaf memory leaf;
        for (uint256 i; i < commits.length; ++i) {
            bool rotated;
            (a, leaf, rotated) = _applyCommit(commits[i], a);
            if (!rotated && i + 1 != commits.length) revert CommitWithoutRotation();
        }
        r.anchor = a;

        // Relay block leaf.parent_number: header → state root → Paras::Heads(PARA_ID).
        if (SubstrateHeader.hash(relayHeader) != leaf.parentHash) revert RelayHeaderMismatch();
        SubstrateHeader.Header memory rh = SubstrateHeader.decode(relayHeader);
        if (rh.number != leaf.parentNumber) revert RelayHeaderMismatch();
        (bool exists, bytes memory headData) = SubstrateTrie.get(
            SubstrateTrie.load(relayStateProof), rh.stateRoot, abi.encodePacked(PARA_HEAD_KEY_HI, PARA_HEAD_KEY_LO)
        );
        if (!exists) revert ParaHeadNotFound();

        // HeadData(Vec<u8>) = Compact(len) ‖ SCALE(parachain header).
        (uint256 len, uint256 off) = ScaleCodec.readCompact(headData, 0);
        if (off + len != headData.length) revert InvalidParaHead();
        SubstrateHeader.Header memory ph = SubstrateHeader.decode(ScaleCodec.slice(headData, off, len));
        r.paraStateRoot = ph.stateRoot;
        r.paraNumber = ph.number;
    }

    function _applyCommit(Commit memory c, Anchor memory a)
        internal
        pure
        returns (Anchor memory, BeefyLib.MmrLeaf memory leaf, bool rotated)
    {
        BeefyLib.Commitment memory cm = BeefyLib.decodeCommitment(c.commitment);
        if (cm.blockNumber < a.minRelayBlock) revert HeightTooOld();

        BeefyLib.AuthoritySet memory set;
        if (cm.validatorSetId == a.current.id) {
            set = a.current;
        } else if (cm.validatorSetId == a.next.id) {
            set = a.next;
            rotated = true;
        } else {
            revert UnknownValidatorSet(cm.validatorSetId);
        }
        BeefyLib.verifySignatures(c.commitment, set, c.authorities, c.signers, c.signatures);

        BeefyLib.verifyMmrLeaf(cm.mmrRoot, c.mmrLeaf, c.mmrPath, c.mmrPathSides);
        leaf = BeefyLib.decodeLeaf(c.mmrLeaf);
        if (uint256(leaf.parentNumber) + 1 != cm.blockNumber) revert LeafNotForCommitmentBlock();
        if (leaf.nextAuthoritySet.id != cm.validatorSetId + 1) revert LeafNextSetMismatch();

        if (rotated) {
            a = Anchor({current: a.next, next: leaf.nextAuthoritySet, minRelayBlock: cm.blockNumber});
        }
        return (a, leaf, rotated);
    }

    // ── Anchor codec ─────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata t) internal pure returns (Anchor memory a) {
        if (t.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.current =
            BeefyLib.AuthoritySet({id: uint64(bytes8(t[0:8])), len: uint32(bytes4(t[8:12])), root: bytes32(t[12:44])});
        a.next = BeefyLib.AuthoritySet({
            id: uint64(bytes8(t[44:52])), len: uint32(bytes4(t[52:56])), root: bytes32(t[56:88])
        });
        a.minRelayBlock = uint32(bytes4(t[88:92]));
        if (a.current.len == 0 || a.next.len == 0 || a.next.id != a.current.id + 1) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            a.current.id, a.current.len, a.current.root, a.next.id, a.next.len, a.next.root, a.minRelayBlock
        );
    }

    function _last4(bytes memory b) private pure returns (bytes4 out) {
        assembly ("memory-safe") {
            out := mload(add(add(b, 32), sub(mload(b), 4)))
        }
    }
}
