// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {EvmMptBuilder} from "@test/helpers/EvmMptBuilder.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title EthBundleProofFactory
/// @notice Builds **complete, self-consistent** `EthMainnetVerifier` bundle proofs: real EIP-2537
///         BLS aggregate signatures, real SSZ Merkle folds, and real Merkle-Patricia account and
///         storage proofs at a caller-chosen trie depth.
///
/// @dev The two deliberate simplifications are documented and are *conservative or neutral* for gas:
///
///      1. **Self-consistent committee (`sk = 1`).** Every member's pubkey is the G1 generator, so
///         the aggregate of `n` members is `n·G1` and a valid aggregate signature is `n·H(root)`
///         (see {EthCommitteeFixtures}).
///
///      2. **Identical committee keys ⇒ one shared non-signer Merkle proof.** Because all 512 leaves
///         are equal, every internal node at a given level is equal, so a single 288-byte sibling
///         path authenticates any index. The verifier still runs the full per-entry fold
///         ({ClprCommitteeMerkle.verifyAndExtractKey}, 9 keccaks + a 128-byte copy each), so the
///         measured cost per non-signer is exact.
///
///      Trie depth is explicit rather than incidental: {EvmMptBuilder} pads the trie so the account
///      and storage proofs cross a chosen number of branch nodes. A trie holding only the keys under
///      test would produce a 1-node proof and understate MPT gas several-fold.
abstract contract EthBundleProofFactory is EthCommitteeFixtures {
    // ── Beacon / chain constants for the synthetic chain ─────────────────────
    // FORK_VERSION, GVR and SLOTS_PER_SYNC_COMMITTEE_PERIOD come from {EthCommitteeFixtures}.
    uint64 internal constant ATTESTED_PERIOD = 5;
    uint64 internal constant ATTESTED_SLOT = ATTESTED_PERIOD * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 17;
    uint64 internal constant SIGNATURE_SLOT = ATTESTED_SLOT + 1;
    uint64 internal constant PROPOSER_INDEX = 7;
    uint256 internal constant SIGNER_SK = 1;
    uint256 internal constant PEER_SK = 2;
    uint256 internal constant PROVEN_SK = 3;

    uint256 internal constant GINDEX_EXEC = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY; // 802
    uint256 internal constant GINDEX_NEXT_COMMITTEE = ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE; // 87
    uint256 internal constant EXEC_BRANCH_DEPTH = 9;

    /// @dev CLPR service storage layout
    uint256 internal constant CHANNELS_BASE_SLOT = 15;
    uint256 internal constant MESSAGE_QUEUES_BASE_SLOT = 1;
    uint256 internal constant MANIFEST_COMMITMENT_SLOT = 18;

    /// @dev Which of the verifier's rotation paths the bundle exercises (README §"Rotation").
    enum Rotation {
        None,
        Widen,
        Shift
    }

    /// @dev What the relay is asked to prove for one bundle.
    struct BundleSpec {
        uint256 messageCount; // N outbound DATA messages carried by the bundle
        uint256 signers; // sync-committee participation (342..512)
        uint256 accountDepth; // branch nodes crossed by the account proof before its leaf
        uint256 storageDepth; // branch nodes crossed by each storage-slot proof
        /// @dev Fill every branch node on the proven paths (16 children, ~529 bytes) instead of the
        ///      minimum 2 (~81 bytes). Mainnet's upper trie levels are dense, and the walker keccaks
        ///      and copies every node it visits, so this is the realistic setting.
        bool denseBranches;
        Rotation rotation; // which next-sync-committee rotation path to carry, if any
        bool manifest; // carry an endpoint-manifest update (13-field shape)
        /// @dev The peer's `receivedMessageId` — how far it has acked *our* outbound queue. Non-zero
        ///      makes the bundle carry an acknowledgement, which is what lets a zero-message
        ///      (ACK-only) bundle make protocol progress at all; `BundleLib` rejects a bundle that
        ///      neither delivers a new message nor advances the ack cursor.
        uint64 ackedByPeer;
        bytes32 channelId;
        address peerService;
        bytes32 codeHash;
        bytes32 connectorId;
        address targetApp;
    }

    /// @dev Everything the caller needs to submit and to cross-check the proof.
    struct BuiltBundle {
        bytes proof;
        bytes trustAnchor;
        bytes channelContext;
        bytes[] payloads;
        bytes32 sentRunningHash;
        uint64 nextMessageId;
        bytes32 beaconBlockRoot;
        bytes32 signingRoot;
        bytes32 committeeRoot;
        bytes aggregatePubkey;
        bytes signature;
        bytes bits;
        uint256 accountProofDepth; // achieved, asserted by callers
        uint256 storageProofDepth; // achieved, for the present slot
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Top-level builder
    // ─────────────────────────────────────────────────────────────────────────

    function _buildBundle(BundleSpec memory s) internal returns (BuiltBundle memory b) {
        // 1 ── payloads and the running hash the peer's storage must commit to.
        b.payloads = _payloads(s);
        b.nextMessageId = uint64(s.messageCount + 1);
        b.sentRunningHash = _runningHash(b.payloads);

        // 2 ── storage trie: the two non-zero Channel slots plus proofs of absence for the rest.
        (
            bytes32 storageRoot,
            bytes memory storageProofRlp,
            bytes memory manifestProofRlp,
            bytes memory manifestPreimage
        ) = _buildStorageProof(s, b.sentRunningHash, b.nextMessageId);
        b.storageProofDepth = s.storageDepth + 1;

        // 3 ── account trie over the storage root → the execution state root.
        (bytes32 executionStateRoot, bytes memory accountProofRlp) = _buildAccountProof(s, storageRoot);
        b.accountProofDepth = s.accountDepth + 1;

        // 4 ── SSZ: fold the execution state root up to a bodyRoot, and (if rotating) the next
        //      committee root up to a stateRoot.
        bytes32[] memory execBranch = _syntheticBranch("exec-branch", EXEC_BRANCH_DEPTH);
        bytes32 bodyRoot = _fold(executionStateRoot, execBranch, GINDEX_EXEC);

        bytes32 stateRoot;
        bytes memory nextCommitteeRlp = hex"80"; // absent: empty RLP string
        bytes memory nextBranchRlp = hex"c0"; // absent: empty RLP list
        if (s.rotation == Rotation.None) {
            stateRoot = keccak256("unused-state-root");
        } else {
            // Widen re-proves the window's stored `next`; Shift proves a fresh committee.
            uint256 provenSk = s.rotation == Rotation.Widen ? PEER_SK : PROVEN_SK;
            bytes32[] memory rotBranch = _syntheticBranch("next-committee-branch", NEXT_COMMITTEE_BRANCH_DEPTH);
            bytes memory provenAggregate = _committeeAggregate(provenSk);
            bytes32 sszRoot = _committeeRootFromCompressed(
                _compressedKeys(SYNC_COMMITTEE_SIZE, provenSk), ClprBls12381.compressG1(provenAggregate)
            );
            stateRoot = _fold(sszRoot, rotBranch, GINDEX_NEXT_COMMITTEE);
            nextCommitteeRlp = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, provenSk), provenAggregate);
            nextBranchRlp = _encodeBranch(rotBranch);
        }

        // 5 ── attested header → its SSZ root → the signing root the committee signs.
        b.beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(
            ATTESTED_SLOT, PROPOSER_INDEX, keccak256("parent"), stateRoot, bodyRoot
        );
        b.signingRoot = ClprBeaconSsz.computeSigningRoot(
            b.beaconBlockRoot, ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR)
        );

        // 6 ── real BLS: participation bitvector, aggregate signature, committee aggregate pubkey.
        b.bits = _bits(s.signers);
        b.signature = _aggSig(b.signingRoot, s.signers, SIGNER_SK);
        b.aggregatePubkey = _committeeAggregate(SIGNER_SK);
        b.committeeRoot = ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, SIGNER_SK));

        // 7 ── window trust anchor (flat 428-byte layout) and channel context.
        b.trustAnchor = _anchorFor(s.rotation, s.channelId, s.codeHash);
        b.channelContext = abi.encodePacked(s.channelId, abi.encodePacked(s.peerService));

        // 8 ── assemble the payload.
        b.proof = _assemble(
            _headerRlp(stateRoot, bodyRoot),
            SIGNATURE_SLOT,
            _syncAggregateRlp(b.bits, b.signature),
            executionStateRoot,
            _encodeBranch(execBranch),
            nextCommitteeRlp,
            nextBranchRlp,
            accountProofRlp,
            storageProofRlp,
            _bundleContent(b.payloads),
            _nonSignerListRlp(SYNC_COMMITTEE_SIZE - s.signers),
            s.manifest ? manifestProofRlp : bytes(""),
            s.manifest ? manifestPreimage : bytes("")
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Storage proof
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Build one storage trie holding the peer channel's real state, then emit a per-slot proof
    ///      for each slot the verifier derives. `+1` (packing `nextMessageId`/status) is non-zero, and
    ///      so are `+4` and the last message's running-hash slot when the bundle carries messages
    ///      (both holding `sentRunningHash`); the rest are proven *absent*,
    ///      which the verifier reads as zero — the shape a freshly-acked channel genuinely has.
    function _buildStorageProof(BundleSpec memory s, bytes32 sentRunningHash, uint64 nextMessageId)
        private
        returns (
            bytes32 storageRoot,
            bytes memory storageProofRlp,
            bytes memory manifestProofRlp,
            bytes memory manifestPreimage
        )
    {
        bytes32 cBase = keccak256(abi.encode(s.channelId, CHANNELS_BASE_SLOT));

        // Slot numbers
        bytes32[] memory slots = new bytes32[](7);
        slots[0] = bytes32(uint256(cBase) + 1); // verifier|status|nextMessageId   (non-zero)
        slots[1] = bytes32(uint256(cBase) + 2); // acked|received|nextExpectedReply (zero)
        slots[2] = bytes32(uint256(cBase) + 4); // sentRunningHash                 (non-zero iff N>0)
        slots[3] = bytes32(uint256(cBase) + 5); // receivedRunningHash             (zero)
        slots[4] = bytes32(uint256(cBase) + 16); // endpointManifestVersion        (zero)
        slots[5] = _lastMessageRunningHashSlot(s.channelId, nextMessageId - 1); // last message's running hash
        slots[6] = bytes32(MANIFEST_COMMITMENT_SLOT); // manifest commitment       (non-zero iff manifest)

        manifestPreimage = _manifestPreimage(s);

        // slot+1 packs verifier(20) | status(1) | nextMessageId(8) from the LSB.
        uint256 slot1 = uint256(uint160(s.peerService)) | (uint256(uint8(ClprTypes.ChannelStatus.ACTIVE)) << 160)
            | (uint256(nextMessageId) << 168);

        // Present (non-zero) vs absent (zero) slots.
        bool[] memory present = new bool[](7);
        bytes[] memory values = new bytes[](7);
        present[0] = true;
        values[0] = RLP.encode(slot1);
        // slot+2 packs ackedMessageId(8) | receivedMessageId(8) | nextExpectedReplyId(8) from the
        // LSB, so the peer's receivedMessageId sits at bits [64, 128).
        present[1] = s.ackedByPeer > 0;
        values[1] = RLP.encode(uint256(s.ackedByPeer) << 64);
        present[2] = s.messageCount > 0;
        values[2] = RLP.encode(uint256(sentRunningHash));
        present[5] = s.messageCount > 0;
        values[5] = RLP.encode(uint256(sentRunningHash));
        present[6] = s.manifest;
        values[6] = RLP.encode(uint256(keccak256(manifestPreimage)));

        EvmMptBuilder t = new EvmMptBuilder();
        storageRoot = _buildPaddedTrie(t, slots, present, values, s.storageDepth, s.denseBranches);

        // The five Channel slots, plus the last-message slot only when the bundle carries messages
        // (the 6-entry shape the relay sends then).
        uint256 entryCount = s.messageCount > 0 ? 6 : 5;
        bytes[] memory entries = new bytes[](entryCount);
        for (uint256 i = 0; i < entryCount; i++) {
            uint256 si = i < 5 ? i : 5;
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slots[si]));
            entry[1] = t.proofRlp(keccak256(abi.encodePacked(slots[si])));
            entries[i] = RLP.encode(entry);
        }
        storageProofRlp = RLP.encode(entries);

        bytes[] memory mEntry = new bytes[](2);
        mEntry[0] = RLP.encode(abi.encodePacked(slots[6]));
        mEntry[1] = t.proofRlp(keccak256(abi.encodePacked(slots[6])));
        bytes[] memory mList = new bytes[](1);
        mList[0] = RLP.encode(mEntry);
        manifestProofRlp = RLP.encode(mList);
    }

    /// @dev Insert every `present` slot plus depth-padding siblings for *all* slots (present and
    ///      absent alike), so both inclusion and exclusion proofs cross `depth` branch nodes.
    function _buildPaddedTrie(
        EvmMptBuilder t,
        bytes32[] memory slots,
        bool[] memory present,
        bytes[] memory values,
        uint256 depth,
        bool dense
    ) private returns (bytes32) {
        bytes32[] memory keys = new bytes32[](slots.length * (depth * (dense ? 15 : 1) + 1));
        bytes[] memory vals = new bytes[](keys.length);
        uint256 n;

        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 keyHash = keccak256(abi.encodePacked(slots[i]));
            bytes32[] memory pad = _pad(t, keyHash, depth, present[i], dense);
            if (present[i]) {
                keys[n] = keyHash;
                vals[n++] = values[i];
            }
            for (uint256 j = 0; j < pad.length; j++) {
                keys[n] = pad[j];
                vals[n++] = RLP.encode(uint256(0xF0 + j + 1)); // filler slot values
            }
        }

        bytes32[] memory k = new bytes32[](n);
        bytes[] memory v = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            k[i] = keys[i];
            v[i] = vals[i];
        }
        return t.build(k, v);
    }

    /// @dev Depth-padding sibling keys for `keyHash`, in the requested inclusion/exclusion and
    ///      sparse/dense combination.
    function _pad(EvmMptBuilder t, bytes32 keyHash, uint256 depth, bool isPresent, bool dense)
        private
        pure
        returns (bytes32[] memory)
    {
        if (dense) {
            return isPresent ? t.padKeysDensePresent(keyHash, depth) : t.padKeysDenseAbsent(keyHash, depth);
        }
        return isPresent ? t.padKeysPresent(keyHash, depth) : t.padKeysAbsent(keyHash, depth);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Account proof
    // ─────────────────────────────────────────────────────────────────────────

    function _buildAccountProof(BundleSpec memory s, bytes32 storageRoot)
        private
        returns (bytes32 stateRoot, bytes memory accountProofRlp)
    {
        bytes32 keyHash = keccak256(abi.encodePacked(s.peerService));

        EvmMptBuilder t = new EvmMptBuilder();
        bytes32[] memory pad = _pad(t, keyHash, s.accountDepth, true, s.denseBranches);

        bytes32[] memory keys = new bytes32[](pad.length + 1);
        bytes[] memory vals = new bytes[](keys.length);
        keys[0] = keyHash;
        vals[0] = _accountRlp(storageRoot, s.codeHash);
        for (uint256 i = 0; i < pad.length; i++) {
            keys[i + 1] = pad[i];
            // Other accounts in the trie: full 4-field leaves, so sibling nodes are realistically sized.
            vals[i + 1] = _accountRlp(keccak256(abi.encodePacked("other-storage", i)), keccak256("other-code"));
        }
        stateRoot = t.build(keys, vals);
        accountProofRlp = t.proofRlp(keyHash);
    }

    function _accountRlp(bytes32 storageRoot, bytes32 codeHash) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](4);
        f[0] = RLP.encode(uint256(1)); // nonce
        f[1] = RLP.encode(uint256(0)); // balance
        f[2] = RLP.encode(storageRoot);
        f[3] = RLP.encode(codeHash);
        return RLP.encode(f);
    }

    function _lastMessageRunningHashSlot(bytes32 channelId, uint64 messageId) internal pure returns (bytes32) {
        bytes32 qBase = keccak256(abi.encode(channelId, MESSAGE_QUEUES_BASE_SLOT));
        return bytes32(uint256(keccak256(abi.encode(messageId, qBase))) + 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Payload assembly
    // ─────────────────────────────────────────────────────────────────────────

    function _assemble(
        bytes memory headerRlp,
        uint64 signatureSlot,
        bytes memory aggRlp,
        bytes32 executionStateRoot,
        bytes memory execBranchRlp,
        bytes memory nextCommitteeRlp,
        bytes memory nextBranchRlp,
        bytes memory accountProofRlp,
        bytes memory storageProofRlp,
        bytes memory bundleContent,
        bytes memory nonSignerRlp,
        bytes memory manifestProofRlp,
        bytes memory manifestPreimage
    ) private pure returns (bytes memory) {
        bool withManifest = manifestPreimage.length > 0;
        bytes[] memory top = new bytes[](withManifest ? 13 : 11);
        top[0] = headerRlp;
        top[1] = RLP.encode(uint256(signatureSlot));
        top[2] = aggRlp;
        top[3] = RLP.encode(executionStateRoot);
        top[4] = execBranchRlp;
        top[5] = nextCommitteeRlp;
        top[6] = nextBranchRlp;
        top[7] = accountProofRlp;
        top[8] = storageProofRlp;
        top[9] = RLP.encode(bundleContent);
        top[10] = nonSignerRlp;
        if (withManifest) {
            top[11] = manifestProofRlp;
            top[12] = RLP.encode(manifestPreimage);
        }
        return RLP.encode(top);
    }

    function _headerRlp(bytes32 stateRoot, bytes32 bodyRoot) private pure returns (bytes memory) {
        bytes[] memory h = new bytes[](5);
        h[0] = RLP.encode(uint256(ATTESTED_SLOT));
        h[1] = RLP.encode(uint256(PROPOSER_INDEX));
        h[2] = RLP.encode(keccak256("parent"));
        h[3] = RLP.encode(stateRoot);
        h[4] = RLP.encode(bodyRoot);
        return RLP.encode(h);
    }

    function _syncAggregateRlp(bytes memory bits, bytes memory signature) private pure returns (bytes memory) {
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(signature);
        return RLP.encode(agg);
    }

    /// @dev `ClprBundleContent`: field 2 (LEN, repeated) per message payload. Field 1 (queue
    ///      metadata) is deliberately omitted — the verifier ignores it and takes metadata from the
    ///      storage proof.
    function _bundleContent(bytes[] memory payloads) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < payloads.length; i++) {
            out = abi.encodePacked(out, PB.encodeBytesField(2, payloads[i]));
        }
    }

    /// @dev Payload item 9: one `key128 ‖ proof288` entry per clear participation bit. All committee
    ///      keys are equal, so each level's sibling is that level's node value and a single path
    ///      authenticates every index — the verifier still folds all 9 levels per entry.
    function _nonSignerListRlp(uint256 count) internal view returns (bytes memory) {
        bytes memory sharedProof;
        bytes32 h = keccak256(genUncompressed);
        for (uint256 j = 0; j < ClprCommitteeMerkle.DEPTH; j++) {
            sharedProof = abi.encodePacked(sharedProof, h);
            h = keccak256(abi.encodePacked(h, h));
        }
        bytes[] memory entries = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            entries[i] = RLP.encode(abi.encodePacked(genUncompressed, sharedProof));
        }
        return RLP.encode(entries);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Small builders
    // ─────────────────────────────────────────────────────────────────────────

    function _payloads(BundleSpec memory s) internal pure returns (bytes[] memory out) {
        out = new bytes[](s.messageCount);
        for (uint256 i = 0; i < s.messageCount; i++) {
            out[i] = ClprProtobuf.encodeDataMessage(
                s.connectorId,
                abi.encodePacked(s.targetApp),
                hex"AA01BB02",
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodePacked("HELLO", uint8(i))
            );
        }
    }

    /// @dev The sha256 running-hash chain `BundleLib` recomputes; a fresh channel starts from zero.
    function _runningHash(bytes[] memory payloads) internal pure returns (bytes32 h) {
        for (uint256 i = 0; i < payloads.length; i++) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
        }
    }

    /// @dev The window anchor a bundle built for `rotation` verifies against.
    function _anchorFor(Rotation rotation, bytes32 channelId, bytes32 codeHash) internal view returns (bytes memory) {
        return rotation == Rotation.Shift
            ? _encodeWindowAnchor(ATTESTED_PERIOD - 1, PEER_SK, SIGNER_SK, channelId, codeHash)
            : _encodeWindowAnchor(ATTESTED_PERIOD, SIGNER_SK, PEER_SK, channelId, codeHash);
    }

    /// @dev Flat 428-byte window anchor:
    ///      `gvr ‖ forkVersion ‖ channelId ‖ codeHash ‖ period8 ‖ [aggregate128 ‖ committeeRoot32] × 2`.
    function _encodeWindowAnchor(uint64 period, uint256 currentSk, uint256 nextSk, bytes32 channelId, bytes32 codeHash)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            GVR,
            FORK_VERSION,
            channelId,
            codeHash,
            period,
            _committeeAggregate(currentSk),
            ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, currentSk)),
            _committeeAggregate(nextSk),
            ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, nextSk))
        );
    }

    /// @dev `Bitvector[512]`, LSB-first within each byte: the first `n` committee indices signed.
    function _bits(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(64);
        for (uint256 i = 0; i < n; i++) {
            // `2 ** (i & 7)` rather than a literal shift, matching the existing `_bits` fixture and
            // sidestepping the incorrect-shift lint. casting to 'uint8' is safe because the operand
            // is at most 0xFF: `2 ** (i & 7)` <= 128 and the accumulated byte is a uint8 already.
            // forge-lint: disable-next-line(unsafe-typecast)
            b[i >> 3] = bytes1(uint8(uint8(b[i >> 3]) | uint8(2 ** (i & 7))));
        }
    }

    function _syntheticBranch(string memory tag, uint256 depth) internal pure returns (bytes32[] memory branch) {
        branch = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            branch[i] = keccak256(abi.encodePacked(tag, i));
        }
    }

    /// @dev Fold a leaf to its SSZ root with the same rule as `ClprBeaconSsz.verifyProof`.
    function _fold(bytes32 leaf, bytes32[] memory branch, uint256 gindex) internal pure returns (bytes32 computed) {
        computed = leaf;
        uint256 idx = gindex;
        for (uint256 i = 0; i < branch.length; i++) {
            computed = (idx & 1 == 1)
                ? sha256(abi.encodePacked(branch[i], computed))
                : sha256(abi.encodePacked(computed, branch[i]));
            idx >>= 1;
        }
    }

    /// @dev A minimal one-endpoint manifest, version 1, bound to the peer service address.
    function _manifestPreimage(BundleSpec memory s) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = 1;
        m.serviceAddress = abi.encodePacked(s.peerService);
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex"01"});
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    /// @dev The 7-field `verifyConfig` payload that seeds the channel's genesis window: the same anchor
    ///      {_anchorFor} builds for `s.rotation`, so a bundle accepted by `verifyBundle` against that
    ///      anchor is also accepted by `submitBundle`.
    function _configProof(BundleSpec memory s, string memory chainId) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(s.peerService);
        lc.nanosSinceEpoch = 1000;
        lc.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });

        bool shift = s.rotation == Rotation.Shift;
        (uint256 currentSk, uint256 nextSk) = shift ? (PEER_SK, SIGNER_SK) : (SIGNER_SK, PEER_SK);
        uint64 configSlot = shift ? ATTESTED_SLOT - SLOTS_PER_SYNC_COMMITTEE_PERIOD : ATTESTED_SLOT;

        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(uint256(configSlot));
        // The aggregates must be the real committee aggregates (512·sk·G1), not a single generator:
        // they become the anchor's `aggregate_pubkey`s, and every bundle's BLS check subtracts
        // non-participants from the selected one. Seeding 1·G1 here yields an anchor that no honest
        // bundle can satisfy.
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, currentSk), _committeeAggregate(currentSk));
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, nextSk), _committeeAggregate(nextSk));
        cfg[3] = RLP.encode(GVR);
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(s.codeHash);
        return RLP.encode(cfg);
    }
}
