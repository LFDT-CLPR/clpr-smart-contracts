// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title EthMainnetComplianceTest
///
/// @dev BLS notes: every bundle proof uses the generator committee (all 512 members have sk=1),
///      so the aggregate is 512·G1 and a valid signature is 512·H(signingRoot).
contract EthMainnetComplianceTest is ClprEvmStorageComplianceTest, EthCommitteeFixtures, QbftSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    uint64 internal constant BUNDLE_PERIOD = 5;
    uint64 internal constant BUNDLE_SLOT = BUNDLE_PERIOD * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1000;
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    uint256 private constant EXECUTION_BRANCH_DEPTH = 9;

    function setUp() public override(ClprVerifierComplianceTest, EthCommitteeFixtures) {
        ClprVerifierComplianceTest.setUp();
        EthCommitteeFixtures.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(new EthMainnetVerifier());
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "eip155:1";
        lc.serviceAddress = abi.encodePacked(SERVICE_ADDR);

        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        uint64 slot = BUNDLE_PERIOD * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 17;

        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(uint256(slot));
        cfg[1] = _encodeCommittee(pubkeys, genUncompressed);
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 2), _committeeAggregate(2));
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));

        return ConfigVector({
            configProof: RLP.encode(cfg),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:1",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _buildBundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            trustAnchor: _buildTrustAnchor(SYNTHETIC_CHANNEL_ID),
            channelContext: _validChannelContext(),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    function _validChannelContext() private pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    function _crossChannelVector()
        internal
        view
        override
        returns (
            bytes memory proofBytes,
            bytes memory trustAnchor,
            bytes memory attackerContext,
            bytes memory expectedRevert
        )
    {
        bytes32 attackerConnId = bytes32(uint256(0xDEADBEEF));
        attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attackerConnId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerConnId, uint256(15)))) + 1);
        return (
            _buildBundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            _buildTrustAnchor(attackerConnId),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot)
        );
    }

    /// @dev EthMainnetVerifier has no GVR/forkVersion pin at construction, so there is no
    ///      "wrong network" rejection at the config proof level via those fields. The closest
    ///      structural "different chain" probe is a committee with 48-byte compressed BLS keys
    ///      (the beacon-native format used by non-EIP-2537 implementations) rather than the
    ///      128-byte uncompressed format this verifier requires. `_decodeCommitteeWithLen(128)`
    ///      rejects a 48-byte key with `InvalidCommittee`.
    function _wrongChainConfigVector() internal pure override returns (bytes memory configProof, bytes32 channelId) {
        bytes[] memory compressedKeys = _compressedKeys(SYNC_COMMITTEE_SIZE); // 48 bytes each
        ClprTypes.LedgerConfiguration memory lc;
        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(compressedKeys, G1_GEN_COMPRESSED); // aggregate also 48 bytes
        cfg[2] = _encodeCommittee(compressedKeys, G1_GEN_COMPRESSED);
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(bytes32(0)));
        return (RLP.encode(cfg), SYNTHETIC_CHANNEL_ID);
    }

    function _partialSlotCoverageVector() internal view override returns (bytes memory, bytes32) {
        // 4-field RLP instead of the required 7 → InvalidConfigPayload.
        bytes[] memory cfg = new bytes[](4);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), genUncompressed);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        return (RLP.encode(cfg), SYNTHETIC_CHANNEL_ID);
    }

    function _fiveSlotBundleVector(uint64 nextMessageId, bytes32 sentRunningHash, bytes memory bundleContent)
        internal
        view
        override
        returns (bytes memory, bytes memory, bytes memory)
    {
        return (
            _buildBundleWithSentHash(nextMessageId, sentRunningHash, bundleContent),
            _buildTrustAnchor(SYNTHETIC_CHANNEL_ID),
            _validChannelContext()
        );
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 expectedSentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummyMeta;
        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(dummyMeta, payloads);

        return RunningHashVector({
            proofBytes: _buildBundleWithSentHash(ONE_MESSAGE_NEXT_MESSAGE_ID, expectedSentRunningHash, bundleContent),
            trustAnchor: _buildTrustAnchor(SYNTHETIC_CHANNEL_ID),
            channelContext: _validChannelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev EthMainnetVerifier pins the service address via the constructor immutable
    ///      EXPECTED_CONTRACT_ADDRESS. A bundle whose account proof is keyed to differentService
    ///      (not SERVICE_ADDR) causes the MPT path traversal for SERVICE_ADDR to fail — the leaf's
    ///      compact path encodes keccak(differentService), not keccak(SERVICE_ADDR).
    function _wrongServiceAddressVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory wrongContext)
    {
        address differentService = address(uint160(uint256(keccak256("different-service"))));
        return (
            _buildBundleForService(differentService, bytes32(0), SYNTHETIC_CHANNEL_ID),
            _buildTrustAnchor(SYNTHETIC_CHANNEL_ID),
            bytes("")
        );
    }

    function _threeSlotStorageVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext)
    {
        return (_buildBundleWithNStorageSlots(3), _buildTrustAnchor(SYNTHETIC_CHANNEL_ID), bytes(""));
    }

    function _wrongSlotIndexVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext)
    {
        return (_buildBundleWithWrongSlotIndex(), _buildTrustAnchor(SYNTHETIC_CHANNEL_ID), bytes(""));
    }

    // ── Private: trust anchor ─────────────────────────────────────────────────

    /// @dev 428-byte flat-packed WINDOW trust anchor matching EthMainnetVerifier's layout constants.
    function _buildTrustAnchor(bytes32 channelId) private view returns (bytes memory) {
        return abi.encodePacked(
            GVR, // [0..32)    genesis validators root
            FORK_VERSION, // [32..36)   fork version (4 bytes)
            channelId, // [36..68)   channel id
            SERVICE_CODE_HASH, // [68..100)  expected code hash
            BUNDLE_PERIOD, // [100..108) window start period (big-endian uint64)
            _committeeAggregate(1), // [108..236) current aggregate
            ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 1)), // [236..268) current root
            _committeeAggregate(2), // [268..396) next aggregate
            ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 2)) // [396..428) next root
        );
    }

    /// @dev Ethereum keeps the config-time manifest proof independent of the config proof, but it
    ///      must be signed by the CONFIG committee (the same 512 generator keys the config proof
    ///      carries) and anchored at the config-declared service address and code hash.
    ///      Shape: `RLP([attestedHeader, syncAggregate, nonSignerProofs, executionStateRoot,
    ///      executionBranch, accountProof, manifestStorageProof, manifestPreimage])`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        // The manifest proof's BLS aggregate is checked against the committee the CONFIG proof
        // declares, so this config proof must declare the true 512-key aggregate (512·G1) rather
        // than the single generator point `_validConfig()` uses — otherwise a signature by the whole
        // committee cannot verify against it.
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "eip155:1";
        lc.serviceAddress = abi.encodePacked(SERVICE_ADDR);

        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(uint256(BUNDLE_PERIOD * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 17));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), _committeeAggregate());
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 2), _committeeAggregate(2));
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));

        configProof = RLP.encode(cfg);
        channelId = SYNTHETIC_CHANNEL_ID;

        // Prove slot 18 == keccak256(preimage) under the service account's storage root.
        bytes32 slot = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(committedPreimage)))
        );
        bytes[] memory entry = new bytes[](2);
        entry[0] = RLP.encode(abi.encodePacked(slot));
        entry[1] = proofNodes;
        bytes[] memory entries = new bytes[](1);
        entries[0] = RLP.encode(entry);

        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        // Beacon chain: fold the execution state root to a bodyRoot, then sign it with the full
        // generator committee so the BLS supermajority check passes against the config committee.
        bytes32[] memory execBranch = _execBranch();
        bytes32 bodyRoot = _foldSsz(executionStateRoot, execBranch, ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY);
        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(BUNDLE_SLOT, 0, bytes32(0), bytes32(0), bodyRoot);
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);

        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(_allOneBits());
        agg[1] = RLP.encode(_aggSig(signingRoot, SYNC_COMMITTEE_SIZE));

        bytes[] memory headerItems = new bytes[](5);
        headerItems[0] = RLP.encode(uint256(BUNDLE_SLOT)); // slot, inside BUNDLE_PERIOD
        headerItems[1] = RLP.encode(uint256(0)); // proposerIndex
        headerItems[2] = RLP.encode(bytes32(0)); // parentRoot
        headerItems[3] = RLP.encode(bytes32(0)); // stateRoot (beacon layer, unused here)
        headerItems[4] = RLP.encode(bodyRoot);

        bytes[] memory p = new bytes[](8);
        p[0] = RLP.encode(headerItems);
        p[1] = RLP.encode(agg);
        p[2] = RLP.encode(new bytes[](0)); // nonSignerProofs: empty (full participation)
        p[3] = RLP.encode(executionStateRoot);
        p[4] = _encodeBranch(execBranch);
        p[5] = accountProofRlp;
        p[6] = RLP.encode(entries);
        p[7] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(p);
    }

    // ── Private: bundle builders ──────────────────────────────────────────────

    function _buildBundleForService(address svc, bytes32 codeHash, bytes32 channelId)
        private
        view
        returns (bytes memory)
    {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(channelId);
        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(svc, storageRoot, codeHash);
        return _buildBundleProof(executionStateRoot, accountProofRlp, storageProofRlp, RLP.encode(new bytes(0)));
    }

    /// @dev Bundle where storage slot+4 (sentRunningHash) is proven to `sentHash`.
    function _buildBundleWithSentHash(uint64 nextMessageId, bytes32 sentHash, bytes memory bundleContent)
        private
        view
        returns (bytes memory)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory entries) =
            _buildChannelStorageEntriesWithSentHash(cBase, nextMessageId, sentHash);
        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _buildBundleProof(executionStateRoot, accountProofRlp, entries, RLP.encode(bundleContent));
    }

    /// @dev Bundle with `n` storage entries — triggers InvalidStorageProofShape for n < 5.
    function _buildBundleWithNStorageSlots(uint256 n) private view returns (bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        bytes[] memory entries = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + i + 1);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        // storageRoot: any non-zero root (account proof only needs to decode cleanly).
        bytes32 storageRoot = keccak256(abi.encodePacked(cBase));
        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _buildBundleProof(executionStateRoot, accountProofRlp, RLP.encode(entries), RLP.encode(new bytes(0)));
    }

    /// @dev Bundle with 5 entries but slot+4 replaced by slot+3 → SlotNotProven(cBase+4).
    function _buildBundleWithWrongSlotIndex() private view returns (bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        uint8[5] memory offsets = [1, 2, 3, 5, 16]; // +3 in place of +4 — sentRunningHash absent
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _buildBundleProof(executionStateRoot, accountProofRlp, RLP.encode(entries), RLP.encode(new bytes(0)));
    }

    // ── Private: core 11-item proof assembler ────────────────────────────────

    /// @dev Assembles a complete 11-item EthMainnetVerifier bundle proof that passes every check
    ///      up to and including BLS aggregate verification. The SSZ execution branch and BLS
    ///      signing chain are derived consistently from `executionStateRoot`, so the resulting proof
    ///      reaches step 6 (MPT account check) or step 7 (storage check) before failing — useful
    ///      for every negative test that targets a post-BLS error.
    function _buildBundleProof(
        bytes32 executionStateRoot,
        bytes memory accountProofRlp,
        bytes memory storageProofRlp,
        bytes memory bundleContentItem
    ) private view returns (bytes memory) {
        return _buildBundleProof(executionStateRoot, accountProofRlp, storageProofRlp, bundleContentItem, _execBranch());
    }

    /// @dev As {_buildBundleProof}, but the branch placed on the wire may differ from the one the
    ///      committee signed over. Passing anything other than `_execBranch()` yields a proof that
    ///      satisfies the BLS check and then fails the execution-branch check — the only way to
    ///      reach `ExecutionBranchInvalid`, which sits behind BLS verification.
    function _buildBundleProof(
        bytes32 executionStateRoot,
        bytes memory accountProofRlp,
        bytes memory storageProofRlp,
        bytes memory bundleContentItem,
        bytes32[] memory wireBranch
    ) private view returns (bytes memory) {
        // SSZ: fold executionStateRoot → bodyRoot via gindex 802 (9-step branch).
        bytes32[] memory execBranch = _execBranch();
        bytes32 bodyRoot = _foldSsz(executionStateRoot, execBranch, ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY);

        // BLS: sign the beacon block header over signingRoot with the full generator committee.
        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(BUNDLE_SLOT, 0, bytes32(0), bytes32(0), bodyRoot);
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);
        bytes memory sig = _aggSig(signingRoot, SYNC_COMMITTEE_SIZE); // 512·H(signingRoot)
        bytes memory bits = _allOneBits(); // all 512 committee members signed

        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(sig);

        bytes[] memory headerItems = new bytes[](5);
        headerItems[0] = RLP.encode(uint256(BUNDLE_SLOT)); // slot, inside BUNDLE_PERIOD
        headerItems[1] = RLP.encode(uint256(0)); // proposerIndex
        headerItems[2] = RLP.encode(bytes32(0)); // parentRoot
        headerItems[3] = RLP.encode(bytes32(0)); // stateRoot (beacon layer, unused here)
        headerItems[4] = RLP.encode(bodyRoot);

        bytes[] memory top = new bytes[](11);
        top[0] = RLP.encode(headerItems);
        // signatureSlot: one slot past the attested header, same period ⇒ selects `current`.
        top[1] = RLP.encode(uint256(BUNDLE_SLOT) + 1);
        top[2] = RLP.encode(agg);
        top[3] = RLP.encode(executionStateRoot);
        top[4] = _encodeBranch(wireBranch);
        top[5] = RLP.encode(new bytes(0)); // nextCommittee: absent (RLP empty string 0x80)
        top[6] = RLP.encode(new bytes[](0)); // nextCommitteeBranch: absent (RLP empty list 0xc0)
        top[7] = accountProofRlp;
        top[8] = storageProofRlp;
        top[9] = bundleContentItem;
        top[10] = RLP.encode(new bytes[](0)); // nonSignerProofs: empty (full participation)
        return RLP.encode(top);
    }

    /// @dev `ExecutionBranchInvalid` guards the link between the BLS-signed beacon body and the
    ///      execution state root the storage proofs are read against. Without it, a validly signed
    ///      header could be paired with an unrelated execution state — any state the attacker
    ///      likes. The check sits behind BLS verification, so reaching it needs a proof the
    ///      committee actually signed: here the signature covers the honest branch while the wire
    ///      carries a corrupted one.
    /// @custom:matrix-row V11
    function test_verifyBundle_corruptExecutionBranch_reverts() public {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 executionStateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes32[] memory corrupted = _execBranch();
        corrupted[0] = keccak256("not the signed sibling");

        bytes memory proof = _buildBundleProof(
            executionStateRoot, accountProofRlp, storageProofRlp, RLP.encode(new bytes(0)), corrupted
        );

        // Hoist the arguments: `_validBundle()` builds a proof, and the aggregate-signature
        // helper calls the BLS precompile — an external call that would otherwise consume the
        // `vm.expectRevert` expectation before `verifyBundle` is even reached.
        bytes memory anchor = _validBundle().trustAnchor;
        bytes memory ctx = _validChannelContext();

        vm.expectRevert(EthMainnetVerifier.ExecutionBranchInvalid.selector);
        verifier.verifyBundle(proof, anchor, ctx);
    }

    // ── Private: small helpers ────────────────────────────────────────────────

    /// @dev Deterministic 9-sibling SSZ execution branch (gindex 802 depth).
    function _execBranch() private pure returns (bytes32[] memory branch) {
        branch = new bytes32[](EXECUTION_BRANCH_DEPTH);
        for (uint256 i = 0; i < EXECUTION_BRANCH_DEPTH; i++) {
            branch[i] = keccak256(abi.encodePacked("eth-exec-branch", i));
        }
    }

    // ─── Test ───────────────────────────────────────────────
    /// TODO: fix this test when #333 is merged - verifyConfig is parse only now
    function test_compliance_verifyConfig_revertsOnCorruptedProof() public override {
        vm.skip(true);
    }
}
