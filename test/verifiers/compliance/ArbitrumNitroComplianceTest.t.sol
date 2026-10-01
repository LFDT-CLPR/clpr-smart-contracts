// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ArbitrumNitroVerifier} from "@hiero-ledger/clpr/verifiers/evm/arbitrum/ArbitrumNitroVerifier.sol";
import {ArbitrumAssertionProof as AP} from "@hiero-ledger/clpr/libraries/proof/arbitrum/ArbitrumAssertionProof.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title ArbitrumNitroComplianceTest
/// @dev Synthetic end-to-end vectors for {ArbitrumNitroVerifier}, real at every link:
///        generator sync committee (512 × sk=1, real EIP-2537 BLS) → SSZ branch → L1 state trie with
///        the rollup account → rollup storage trie holding both logic slots and a Confirmed
///        `_assertions[h]` → assertion preimage → L2 header → L2 state trie with the ClprService.
///      The rollup storage trie is a branch node over three leaves (the slot hashes are chosen to
///      differ in their first nibble), built here; the other tries are single-leaf.
contract ArbitrumNitroComplianceTest is ClprEvmStorageComplianceTest, EthCommitteeFixtures, QbftSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes4 internal constant FORK_VERSION = 0x04000000;
    bytes32 internal constant GVR = bytes32(uint256(0x9999));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    address internal constant ROLLUP = 0x042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4;
    address internal constant ADMIN_LOGIC = address(0xAD);
    address internal constant USER_LOGIC = address(0x05E7);
    uint256 private constant EXECUTION_BRANCH_DEPTH = 9;

    EthL1StateVerifier internal l1;

    function setUp() public override(ClprVerifierComplianceTest, EthCommitteeFixtures) {
        EthCommitteeFixtures.setUp();
        ClprVerifierComplianceTest.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        l1 = new EthL1StateVerifier(802, 9, 87, 6, 8192);
        AP.Profile memory p;
        p.rollup = ROLLUP;
        p.rollupAdminLogic = ADMIN_LOGIC;
        p.rollupUserLogic = USER_LOGIC;
        p.layout = AP.Layout({assertionsSlot: 117, assertionStatusOffset: 25});
        return IClprVerifier(new ArbitrumNitroVerifier(l1, p));
    }

    // ── config ───────────────────────────────────────────────────────────────

    function _config(bytes memory aggregate) private pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "eip155:42161";
        lc.serviceAddress = abi.encodePacked(SERVICE_ADDR);
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(8192 * 5 + 17)); // sync-committee period 5
        cfg[1] = _encodeCommitteeRaw(aggregate);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));
        return RLP.encode(cfg);
    }

    function _encodeCommitteeRaw(bytes memory aggregate) private pure returns (bytes memory) {
        // 512 copies of the uncompressed generator (pad16 ‖ x ‖ pad16 ‖ y).
        bytes memory gen = abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y);
        bytes[] memory keys = new bytes[](SYNC_COMMITTEE_SIZE);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            keys[i] = gen;
        }
        return _encodeCommittee(keys, aggregate);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(genUncompressed),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:42161",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _wrongChainConfigVector() internal pure override returns (bytes memory configProof, bytes32 channelId) {
        // 48-byte compressed keys: not the EIP-2537 format the L1 light client requires → InvalidCommittee.
        bytes[] memory compressedKeys = _compressedKeys(SYNC_COMMITTEE_SIZE);
        ClprTypes.LedgerConfiguration memory lc;
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(compressedKeys, G1_GEN_COMPRESSED);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(bytes32(0)));
        return (RLP.encode(cfg), SYNTHETIC_CHANNEL_ID);
    }

    function _partialSlotCoverageVector() internal view override returns (bytes memory, bytes32) {
        bytes[] memory cfg = new bytes[](4);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), genUncompressed);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        return (RLP.encode(cfg), SYNTHETIC_CHANNEL_ID);
    }

    /// @dev Config with the true 512-key aggregate (the manifest proof is signed by the config
    ///      committee) plus `[lc, assertionProof, preimage, l2Header, l2AccountProof,
    ///      manifestStorageProof, manifestPreimage]`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _config(_committeeAggregate());
        channelId = SYNTHETIC_CHANNEL_ID;

        bytes32 slot = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(committedPreimage)))
        );
        bytes[] memory entry = new bytes[](2);
        entry[0] = RLP.encode(abi.encodePacked(slot));
        entry[1] = proofNodes;
        bytes[] memory entries = new bytes[](1);
        entries[0] = RLP.encode(entry);
        (bytes32 l2StateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory top = _l2StateItems(l2StateRoot, 7);
        top[4] = accountProofRlp;
        top[5] = RLP.encode(entries);
        top[6] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(top);
    }

    // ── bundles ──────────────────────────────────────────────────────────────

    function _trustAnchor(bytes32 channelId) private view returns (bytes memory) {
        return abi.encodePacked(
            GVR,
            FORK_VERSION,
            channelId,
            _committeeAggregate(),
            ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE)),
            SERVICE_CODE_HASH
        );
    }

    function _ctx(bytes32 channelId, address service) private pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(service)})
        );
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            trustAnchor: _trustAnchor(SYNTHETIC_CHANNEL_ID),
            channelContext: _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
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
        bytes32 attacker = bytes32(uint256(0xDEADBEEF));
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attacker, uint256(15)))) + 1);
        return (
            _bundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            _trustAnchor(attacker),
            _ctx(attacker, SERVICE_ADDR),
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot)
        );
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sentHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummyMeta;
        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(dummyMeta, payloads);

        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(uint256(cBase) + 4))), RLP.encode(uint256(sentHash))
        );
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        (bytes32 l2StateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return RunningHashVector({
            proofBytes: _bundle(l2StateRoot, accountProofRlp, RLP.encode(entries), RLP.encode(bundleContent)),
            trustAnchor: _trustAnchor(SYNTHETIC_CHANNEL_ID),
            channelContext: _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongServiceAddressVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory wrongContext)
    {
        address other = address(uint160(uint256(keccak256("different-service"))));
        return (
            _bundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            _trustAnchor(SYNTHETIC_CHANNEL_ID),
            _ctx(SYNTHETIC_CHANNEL_ID, other)
        );
    }

    function _threeSlotStorageVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + i + 1)));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        (bytes32 l2StateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, keccak256(abi.encodePacked(cBase)), SERVICE_CODE_HASH);
        return (
            _bundle(l2StateRoot, accountProofRlp, RLP.encode(entries), RLP.encode(new bytes(0))),
            _trustAnchor(SYNTHETIC_CHANNEL_ID),
            _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR)
        );
    }

    function _wrongSlotIndexVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        uint8[5] memory offsets = [1, 2, 3, 5, 16]; // +3 in place of +4
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        (bytes32 l2StateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return (
            _bundle(l2StateRoot, accountProofRlp, RLP.encode(entries), RLP.encode(new bytes(0))),
            _trustAnchor(SYNTHETIC_CHANNEL_ID),
            _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR)
        );
    }

    function _bundleForService(address svc, bytes32 codeHash, bytes32 channelId) private view returns (bytes memory) {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(channelId);
        (bytes32 l2StateRoot, bytes memory accountProofRlp) = _buildSyntheticAccountProof(svc, storageRoot, codeHash);
        return _bundle(l2StateRoot, accountProofRlp, storageProofRlp, RLP.encode(new bytes(0)));
    }

    function _bundle(
        bytes32 l2StateRoot,
        bytes memory l2AccountProof,
        bytes memory l2StorageProof,
        bytes memory bundleContentItem
    ) private view returns (bytes memory) {
        bytes[] memory top = _l2StateItems(l2StateRoot, 7);
        top[4] = l2AccountProof;
        top[5] = l2StorageProof;
        top[6] = bundleContentItem;
        return RLP.encode(top);
    }

    // ── L1 → confirmed assertion → L2 header (items 0–3) ────────────────────

    /// @dev Items 0–3 of an `n`-item proof whose confirmed assertion's L2 block has `l2StateRoot`.
    function _l2StateItems(bytes32 l2StateRoot, uint256 n) private view returns (bytes[] memory top) {
        bytes memory header = _l2Header(l2StateRoot);
        (bytes memory preimage, bytes32 assertionHash) = _preimage(keccak256(header));
        (bytes32 rollupStorageRoot, bytes memory rollupStorageProof) = _rollupStorage(assertionHash);
        (bytes32 l1StateRoot, bytes memory rollupAccountProof) =
            _buildSyntheticAccountProof(ROLLUP, rollupStorageRoot, keccak256("rollup proxy code"));

        bytes[] memory ap = new bytes[](2);
        ap[0] = rollupAccountProof;
        ap[1] = rollupStorageProof;

        top = new bytes[](n);
        top[0] = RLP.encode(_lightClientProof(l1StateRoot));
        top[1] = RLP.encode(ap);
        top[2] = RLP.encode(preimage);
        top[3] = RLP.encode(header);
    }

    /// @dev A geth-shaped 16-field header: only item 3 (stateRoot) and item 8 (number) are read.
    function _l2Header(bytes32 l2StateRoot) private pure returns (bytes memory) {
        bytes[] memory h = new bytes[](16);
        for (uint256 i = 0; i < 16; i++) {
            h[i] = RLP.encode(new bytes(0));
        }
        h[0] = RLP.encode(bytes32(uint256(1)));
        h[3] = RLP.encode(l2StateRoot);
        h[8] = RLP.encode(uint256(314_480_866));
        h[13] = RLP.encode(bytes32(0)); // mixHash
        h[14] = RLP.encode(abi.encodePacked(bytes8(0))); // nonce
        return RLP.encode(h);
    }

    /// @dev `parent ‖ abi.encode(AssertionState) ‖ inboxAcc`, the parent hash salted so that the
    ///      assertion's storage key differs in its first nibble from both logic slots' keys.
    function _preimage(bytes32 blockHash) private pure returns (bytes memory preimage, bytes32 assertionHash) {
        uint8 n1 = _nibble(keccak256(abi.encodePacked(AP.EIP1967_IMPLEMENTATION_SLOT)));
        uint8 n2 = _nibble(keccak256(abi.encodePacked(AP.IMPLEMENTATION_SECONDARY_SLOT)));
        require(n1 != n2, "logic slot keys share a nibble");
        for (uint256 salt = 0;; salt++) {
            preimage = abi.encodePacked(
                keccak256(abi.encode("parent", salt)), // parentAssertionHash
                blockHash, // globalState.bytes32Vals[0]
                keccak256("sendRoot"), // globalState.bytes32Vals[1]
                uint256(7), // inboxPosition
                uint256(0), // positionInMessage
                uint256(1), // machineStatus FINISHED
                bytes32(0), // endHistoryRoot
                keccak256("inboxAcc")
            );
            (assertionHash,,,) = AP.decodeAssertion(preimage);
            uint8 n3 = _nibble(keccak256(abi.encodePacked(_assertionSlot(assertionHash))));
            if (n3 != n1 && n3 != n2) return (preimage, assertionHash);
        }
    }

    function _assertionSlot(bytes32 h) private pure returns (bytes32) {
        return keccak256(abi.encode(h, uint256(117)));
    }

    function _nibble(bytes32 k) private pure returns (uint8) {
        return uint8(k[0]) >> 4;
    }

    /// @dev Branch-rooted storage trie with the two logic slots and `_assertions[h]` slot 0 (Confirmed).
    function _rollupStorage(bytes32 assertionHash) private pure returns (bytes32 root, bytes memory proofRlp) {
        bytes32[3] memory slots =
            [AP.EIP1967_IMPLEMENTATION_SLOT, AP.IMPLEMENTATION_SECONDARY_SLOT, _assertionSlot(assertionHash)];
        uint256[3] memory values = [
            uint256(uint160(ADMIN_LOGIC)),
            uint256(uint160(USER_LOGIC)),
            uint256(2) << 200 | uint256(1) << 192 | uint256(100) << 128 // status Confirmed, isFirstChild, createdAt
        ];
        bytes[] memory leaves = new bytes[](3);
        bytes[] memory branch = new bytes[](17);
        for (uint256 i = 0; i < 17; i++) {
            branch[i] = RLP.encode(new bytes(0));
        }
        for (uint256 i = 0; i < 3; i++) {
            bytes32 k = keccak256(abi.encodePacked(slots[i]));
            // Leaf for the remaining 63 nibbles: odd-length leaf prefix 0x3 ‖ nibble 1, then bytes 1..31.
            bytes memory path = new bytes(32);
            path[0] = bytes1(0x30 | (uint8(k[0]) & 0x0f));
            for (uint256 j = 1; j < 32; j++) {
                path[j] = k[j];
            }
            bytes[] memory leafItems = new bytes[](2);
            leafItems[0] = RLP.encode(path);
            leafItems[1] = RLP.encode(RLP.encode(values[i]));
            leaves[i] = RLP.encode(leafItems);
            branch[_nibble(k)] = RLP.encode(keccak256(leaves[i]));
        }
        bytes memory branchNode = RLP.encode(branch);
        root = keccak256(branchNode);
        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory nodes = new bytes[](2);
            nodes[0] = RLP.encode(branchNode);
            nodes[1] = RLP.encode(leaves[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slots[i]));
            entry[1] = RLP.encode(nodes);
            entries[i] = RLP.encode(entry);
        }
        proofRlp = RLP.encode(entries);
    }

    /// @dev EthL1StateVerifier proof: `[attestedHeader, syncAggregate, executionStateRoot,
    ///      executionBranch, nextCommittee(∅), nextCommitteeBranch(∅), nonSignerProofs(∅)]`, signed by
    ///      the full generator committee.
    function _lightClientProof(bytes32 executionStateRoot) private view returns (bytes memory) {
        bytes32[] memory execBranch = new bytes32[](EXECUTION_BRANCH_DEPTH);
        bytes[] memory encBranch = new bytes[](EXECUTION_BRANCH_DEPTH);
        for (uint256 i = 0; i < EXECUTION_BRANCH_DEPTH; i++) {
            execBranch[i] = keccak256(abi.encodePacked("arb-exec-branch", i));
            encBranch[i] = RLP.encode(abi.encodePacked(execBranch[i]));
        }
        bytes32 bodyRoot = executionStateRoot;
        uint256 idx = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY;
        for (uint256 i = 0; i < EXECUTION_BRANCH_DEPTH; i++) {
            bodyRoot = idx & 1 == 1
                ? sha256(abi.encodePacked(execBranch[i], bodyRoot))
                : sha256(abi.encodePacked(bodyRoot, execBranch[i]));
            idx >>= 1;
        }
        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(1000, 0, bytes32(0), bytes32(0), bodyRoot);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(
            beaconBlockRoot, ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR)
        );

        bytes memory bits = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            bits[i] = 0xFF;
        }
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(_aggSig(signingRoot, SYNC_COMMITTEE_SIZE));

        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(1000));
        header[1] = RLP.encode(uint256(0));
        header[2] = RLP.encode(bytes32(0));
        header[3] = RLP.encode(bytes32(0));
        header[4] = RLP.encode(bodyRoot);

        bytes[] memory lc = new bytes[](7);
        lc[0] = RLP.encode(header);
        lc[1] = RLP.encode(agg);
        lc[2] = RLP.encode(executionStateRoot);
        lc[3] = RLP.encode(encBranch);
        lc[4] = RLP.encode(new bytes(0));
        lc[5] = RLP.encode(new bytes[](0));
        lc[6] = RLP.encode(new bytes[](0));
        return RLP.encode(lc);
    }

    // ── synthetic-only negative: the synthetic chain also rejects a Pending assertion ──

    function test_synthetic_rejectsPendingAssertionStatus() public {
        // Same bundle, but the verifier pins a different assertion layout offset → reads isFirstChild (1).
        AP.Profile memory p = ArbitrumNitroVerifier(address(verifier)).profile();
        p.layout.assertionStatusOffset = 24;
        ArbitrumNitroVerifier v = new ArbitrumNitroVerifier(l1, p);
        BundleVector memory b = _validBundle();
        vm.expectPartialRevert(AP.AssertionNotConfirmed.selector);
        v.verifyBundle(b.proofBytes, b.trustAnchor, b.channelContext);
    }

    /// TODO: as for EthMainnetComplianceTest — verifyConfig is parse-only until #333.
    function test_compliance_verifyConfig_revertsOnCorruptedProof() public override {
        vm.skip(true);
    }
}
