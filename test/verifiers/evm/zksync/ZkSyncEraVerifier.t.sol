// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ZkSyncEraVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/ZkSyncEraVerifier.sol";
import {IZkSyncStateTreeVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/lib/IZkSyncStateTreeVerifier.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";

/// @dev Stand-in for the Ethereum light client: returns a fixed L1 execution state root for any proof,
///      so the diamond and tree logic can be tested against synthetic L1 state. The real light client
///      runs in {ZkSyncEraVerifierEndToEndTest} (generator committee) and in the live vitest spec.
contract MockZkL1StateVerifier is IEthL1StateVerifier {
    bytes32 internal immutable STATE_ROOT;

    constructor(bytes32 stateRoot) {
        STATE_ROOT = stateRoot;
    }

    function verifyL1State(bytes calldata, bytes calldata)
        external
        view
        returns (bytes32, uint64, bytes memory, bytes memory)
    {
        return (STATE_ROOT, 0, "", "");
    }

    function genesisTrustAnchor(bytes calldata, bytes32)
        external
        pure
        returns (bytes memory, bytes memory, bytes memory)
    {
        revert("unused");
    }
}

/// @dev Shared plumbing over test/verifiers/evm/zksync/fixtures/synthetic.json
///      (`npx tsx test/e2e/relay/buildZkSyncSyntheticFixture.ts`).
abstract contract ZkSyncFixture is EthCommitteeFixtures {
    string internal json;
    bytes32 internal l1StateRoot;
    address internal diamond;
    address internal otherDiamond;
    uint256 internal protocolVersion;
    address internal service;
    bytes32 internal serviceCodeHash;
    bytes32 internal channelId;
    bytes32 internal l2Root;
    IZkSyncStateTreeVerifier internal tree;

    function setUp() public virtual override {
        super.setUp();
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/zksync/fixtures/synthetic.json"));
        l1StateRoot = vm.parseJsonBytes32(json, ".l1.stateRoot");
        diamond = vm.parseJsonAddress(json, ".l1.diamond");
        otherDiamond = vm.parseJsonAddress(json, ".l1.otherDiamond");
        protocolVersion = uint256(vm.parseJsonBytes32(json, ".l1.protocolVersion"));
        service = vm.parseJsonAddress(json, ".l2.service");
        serviceCodeHash = vm.parseJsonBytes32(json, ".l2.serviceCodeHash");
        channelId = vm.parseJsonBytes32(json, ".l2.channelId");
        l2Root = vm.parseJsonBytes32(json, ".l2.root");
        // Deployed from its artifact: it compiles in the legacy profile (see foundry.toml).
        tree = IZkSyncStateTreeVerifier(deployCode("ZkSyncStateTreeVerifier.sol:ZkSyncStateTreeVerifier"));
    }

    function _profile(address d) internal view returns (ZkSyncEraVerifier.Profile memory) {
        return ZkSyncEraVerifier.Profile({
            diamondProxy: d,
            totalBatchesExecutedSlot: 11,
            storedBatchHashesSlot: 14,
            protocolVersionSlot: 33,
            minProtocolVersion: protocolVersion,
            maxProtocolVersion: protocolVersion
        });
    }

    function _anchor(bytes32 cid, bytes32 codeHash) internal pure returns (bytes memory a) {
        a = new bytes(EthBeaconLightClient.TRUST_ANCHOR_LENGTH);
        assembly {
            let d := add(a, 32)
            mstore(add(d, 36), cid)
            mstore(add(d, 228), codeHash)
        }
    }

    function _ctx(bytes32 cid) internal view returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: cid, remoteServiceAddress: abi.encodePacked(service)})
        );
    }

    function _batch(string memory name) internal view returns (bytes memory info, bytes memory diamondProof) {
        info = vm.parseJsonBytes(json, string.concat(".batches.", name, ".info"));
        diamondProof = vm.parseJsonBytes(json, string.concat(".batches.", name, ".diamondProof"));
    }

    function _l2(string memory path) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".proofs.", path));
    }

    function _bundle(bytes memory lightClientProof, string memory batch, bytes memory l2Proof)
        internal
        view
        returns (bytes memory)
    {
        (bytes memory info, bytes memory dp) = _batch(batch);
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(lightClientProof);
        items[1] = dp;
        items[2] = RLP.encode(info);
        items[3] = RLP.encode(l2Proof);
        items[4] = RLP.encode(bytes(""));
        return RLP.encode(items);
    }

    /// The (account, key) pairs a 6/7-entry proof covers: code hash, Channel slots, [last message].
    function _entryKeys(bool withMessage) internal view returns (address[] memory a, bytes32[] memory k) {
        uint256 n = withMessage ? 7 : 6;
        a = new address[](n);
        k = new bytes32[](n);
        a[0] = address(0x8002);
        k[0] = bytes32(uint256(uint160(service)));
        uint256 cBase = uint256(keccak256(abi.encode(channelId, uint256(15))));
        uint8[5] memory offs = [1, 2, 4, 5, 16];
        for (uint256 i = 0; i < 5; i++) {
            a[1 + i] = service;
            k[1 + i] = bytes32(cBase + offs[i]);
        }
        if (withMessage) {
            uint256 qBase = uint256(keccak256(abi.encode(channelId, uint256(1))));
            uint64 last = uint64(vm.parseJsonUint(json, ".l2.expected.nextMessageId") - 1);
            a[6] = service;
            k[6] = bytes32(uint256(keccak256(abi.encode(last, qBase))) + 1);
        }
    }

    /// The same entries in RECORDED form (value ‖ 0 ‖ 0xffff), parsed from a packed proof.
    function _recordedForm(bytes memory packed) internal pure returns (bytes memory out) {
        uint256 off = 0;
        while (off < packed.length) {
            bytes32 value;
            assembly {
                value := mload(add(add(packed, 0x20), off))
            }
            uint256 pathLen = (uint256(uint8(packed[off + 40])) << 8) | uint8(packed[off + 41]);
            out = bytes.concat(out, abi.encodePacked(value, uint64(0), uint16(0xffff)));
            off += 42 + 32 * pathLen;
        }
    }

    function _assertCurrent(ClprTypes.QueueMetadata memory m) internal view {
        assertEq(uint8(m.state), vm.parseJsonUint(json, ".l2.expected.status"), "status");
        assertEq(m.nextMessageId, vm.parseJsonUint(json, ".l2.expected.nextMessageId"), "nextMessageId");
        assertEq(m.receivedMessageId, vm.parseJsonUint(json, ".l2.expected.receivedMessageId"), "receivedMessageId");
        assertEq(m.sentRunningHash, vm.parseJsonBytes32(json, ".l2.expected.sentRunningHash"), "sentRunningHash");
        assertEq(
            m.receivedRunningHash, vm.parseJsonBytes32(json, ".l2.expected.receivedRunningHash"), "receivedRunningHash"
        );
        assertEq(
            m.endpointManifestVersion,
            vm.parseJsonUint(json, ".l2.expected.endpointManifestVersion"),
            "endpointManifestVersion"
        );
    }
}

/// @notice Executed-batch acceptance and the L2 binding, on synthetic L1 state with the light client mocked.
contract ZkSyncEraVerifierTest is ZkSyncFixture {
    MockZkL1StateVerifier internal l1;
    ZkSyncEraVerifier internal verifier;
    bytes internal anchor;
    bytes internal ctx;

    function setUp() public override {
        super.setUp();
        l1 = new MockZkL1StateVerifier(l1StateRoot);
        verifier = new ZkSyncEraVerifier(l1, tree, _profile(diamond));
        anchor = _anchor(channelId, serviceCodeHash);
        ctx = _ctx(channelId);
    }

    function _verify(string memory batch, bytes memory l2Proof)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m)
    {
        (m,,,,) = verifier.verifyBundle(_bundle("", batch, l2Proof), anchor, ctx);
    }

    // ── accepted ─────────────────────────────────────────────────────────────

    function test_acceptsExecutedBatch_ackOnly() public view {
        uint256 g = gasleft();
        ClprTypes.QueueMetadata memory m = _verify("current", _l2("current.ack"));
        console.log("verifyBundle (mock L1 client, 6 tree entries) gas:", g - gasleft());
        _assertCurrent(m);
    }

    function test_acceptsExecutedBatch_withMessageSlot() public view {
        uint256 g = gasleft();
        ClprTypes.QueueMetadata memory m = _verify("current", _l2("current.withMessage"));
        console.log("verifyBundle (mock L1 client, 7 tree entries) gas:", g - gasleft());
        _assertCurrent(m);
    }

    function test_acceptsUnpinnedCodeHash() public view {
        (ClprTypes.QueueMetadata memory m,,,,) =
            verifier.verifyBundle(_bundle("", "current", _l2("current.unpinned")), _anchor(channelId, 0), ctx);
        _assertCurrent(m);
    }

    /// An older executed batch is still a valid (final) state; the CLPR Service, not the verifier, rejects
    /// metadata that does not advance.
    function test_acceptsOlderExecutedBatch_withItsOwnState() public view {
        ClprTypes.QueueMetadata memory m = _verify("older", _l2("older.ack"));
        assertEq(m.nextMessageId, vm.parseJsonUint(json, ".l2.expectedOlder.nextMessageId"));
        assertEq(m.sentRunningHash, vm.parseJsonBytes32(json, ".l2.expectedOlder.sentRunningHash"));
    }

    function test_acceptsLegacyStoredBatchInfoEncoding() public view {
        // The legacy batch commits the older tree.
        ClprTypes.QueueMetadata memory m = _verify("legacy", _l2("older.ack"));
        assertEq(m.nextMessageId, vm.parseJsonUint(json, ".l2.expectedOlder.nextMessageId"));
    }

    function test_verifyL2StateRoot() public view {
        (bytes32 r, uint256 n, bytes memory na, bytes memory naId) =
            verifier.verifyL2StateRoot(_bundle("", "current", ""), anchor);
        assertEq(r, l2Root);
        assertEq(n, vm.parseJsonUint(json, ".batches.current.number"));
        assertEq(na.length + naId.length, 0);
    }

    function test_manifestUpdate() public {
        (bytes memory info, bytes memory dp) = _batch("current");
        bytes[] memory items = new bytes[](7);
        items[0] = RLP.encode(bytes(""));
        items[1] = dp;
        items[2] = RLP.encode(info);
        items[3] = RLP.encode(_l2("current.ack"));
        items[4] = RLP.encode(bytes(""));
        items[5] = RLP.encode(_l2("current.manifest"));
        items[6] = RLP.encode(vm.parseJsonBytes(json, ".l2.manifestPreimage"));
        (,,,, ClprTypes.ClprEndpointManifest memory man) = verifier.verifyBundle(RLP.encode(items), anchor, ctx);
        assertEq(man.version, 2);
        assertEq(man.serviceAddress, abi.encodePacked(service));
        assertEq(man.endpoints.length, 1);
        assertEq(man.endpoints[0].port, 50211);

        items[6] = RLP.encode(bytes.concat(vm.parseJsonBytes(json, ".l2.manifestPreimage"), hex"00"));
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        this.callVerify(RLP.encode(items));
    }

    function callVerify(bytes memory proof) external view {
        verifier.verifyBundle(proof, anchor, ctx);
    }

    /// Split delivery: the tree proofs go through `recordStorage` first, the bundle then references them.
    function test_recordedEntries_acceptedAndCheap() public {
        (address[] memory a, bytes32[] memory k) = _entryKeys(true);
        bytes memory full = _l2("current.withMessage");
        uint256 g = gasleft();
        tree.recordStorage(l2Root, a, k, full);
        console.log("recordStorage (7 entries) gas:", g - gasleft());
        bytes memory rec = _recordedForm(full);
        g = gasleft();
        ClprTypes.QueueMetadata memory m = _verify("current", rec);
        console.log("verifyBundle (mock L1 client, 7 RECORDED entries) gas:", g - gasleft());
        _assertCurrent(m);
    }

    /// A record under another batch's root does not carry over.
    function test_recordedEntries_boundToTheRoot() public {
        (address[] memory a, bytes32[] memory k) = _entryKeys(false);
        bytes memory older = _l2("older.ack");
        tree.recordStorage(vm.parseJsonBytes32(json, ".l2.olderRoot"), a, k, older);
        bytes memory proof = _bundle("", "current", _recordedForm(older));
        vm.expectPartialRevert(IZkSyncStateTreeVerifier.EntryNotRecorded.selector);
        verifier.verifyBundle(proof, anchor, ctx);
        // …but the older batch itself verifies from the records.
        _verify("older", _recordedForm(older));
    }

    // ── L1: executed batches only ──────────────────────────────────────────────

    function test_rejectsCommittedButNotExecutedBatch() public {
        bytes memory proof = _bundle("", "notExecuted", _l2("current.ack"));
        vm.expectRevert(abi.encodeWithSelector(ZkSyncEraVerifier.BatchNotExecuted.selector, 1001, 1000));
        verifier.verifyBundle(proof, anchor, ctx);
    }

    function test_rejectsTamperedStoredBatchInfo() public {
        (bytes memory info, bytes memory dp) = _batch("current");
        info[287] = bytes1(uint8(info[287]) ^ 1); // commitment
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(bytes(""));
        items[1] = dp;
        items[2] = RLP.encode(info);
        items[3] = RLP.encode(_l2("current.ack"));
        items[4] = RLP.encode(bytes(""));
        vm.expectRevert(abi.encodeWithSelector(ZkSyncEraVerifier.StoredBatchHashMismatch.selector, 1000));
        verifier.verifyBundle(RLP.encode(items), anchor, ctx);
    }

    /// Replaying an older batch's info under a newer batch number (or vice versa) fails: the stored hash
    /// is keyed by the batch number inside the preimage.
    function test_rejectsBatchInfoUnderOtherBatchProof() public {
        (bytes memory info,) = _batch("older");
        (, bytes memory dp) = _batch("current");
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(bytes(""));
        items[1] = dp;
        items[2] = RLP.encode(info);
        items[3] = RLP.encode(_l2("older.ack"));
        items[4] = RLP.encode(bytes(""));
        vm.expectRevert(); // the diamond proof carries no storedBatchHashes[N-1] entry
        verifier.verifyBundle(RLP.encode(items), anchor, ctx);
    }

    function test_rejectsStoredBatchInfoWithWrongLength() public {
        (bytes memory info, bytes memory dp) = _batch("current");
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(bytes(""));
        items[1] = dp;
        items[2] = RLP.encode(bytes.concat(info, hex"00"));
        items[3] = RLP.encode(_l2("current.ack"));
        items[4] = RLP.encode(bytes(""));
        vm.expectRevert(ZkSyncEraVerifier.InvalidStoredBatchInfo.selector);
        verifier.verifyBundle(RLP.encode(items), anchor, ctx);
    }

    function test_rejectsUnsupportedProtocolVersion() public {
        ZkSyncEraVerifier.Profile memory p = _profile(diamond);
        p.minProtocolVersion = protocolVersion + 1;
        p.maxProtocolVersion = protocolVersion + 5;
        ZkSyncEraVerifier v = new ZkSyncEraVerifier(l1, tree, p);
        bytes memory proof = _bundle("", "current", _l2("current.ack"));
        vm.expectRevert(abi.encodeWithSelector(ZkSyncEraVerifier.UnsupportedProtocolVersion.selector, protocolVersion));
        v.verifyBundle(proof, anchor, ctx);
    }

    /// Pinned to another chain's diamond, this chain's diamond proof does not verify.
    function test_rejectsProofForOtherDiamond() public {
        ZkSyncEraVerifier v = new ZkSyncEraVerifier(l1, tree, _profile(otherDiamond));
        bytes memory proof = _bundle("", "current", _l2("current.ack"));
        vm.expectRevert();
        v.verifyBundle(proof, anchor, ctx);
    }

    function test_rejectsOtherL1StateRoot() public {
        ZkSyncEraVerifier v =
            new ZkSyncEraVerifier(new MockZkL1StateVerifier(keccak256("other")), tree, _profile(diamond));
        bytes memory proof = _bundle("", "current", _l2("current.ack"));
        vm.expectRevert();
        v.verifyBundle(proof, anchor, ctx);
    }

    // ── L2 binding ────────────────────────────────────────────────────────────

    function test_rejectsWrongPinnedCodeHash() public {
        bytes memory proof = _bundle("", "current", _l2("current.ack"));
        // The code entry proves the real hash; the anchor pins another one.
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(channelId, keccak256("other code")), ctx);
    }

    function test_rejectsOtherChannel() public {
        bytes memory proof = _bundle("", "current", _l2("current.ack"));
        vm.expectRevert(abi.encodeWithSelector(IZkSyncStateTreeVerifier.StorageProofRootMismatch.selector, 1));
        verifier.verifyBundle(proof, _anchor(keccak256("other channel"), serviceCodeHash), _ctx(keccak256("x")));
    }

    function test_rejectsL2ProofOfOtherBatch() public {
        // The older tree's proofs under the current batch's root.
        bytes memory proof = _bundle("", "current", _l2("older.ack"));
        vm.expectPartialRevert(IZkSyncStateTreeVerifier.StorageProofRootMismatch.selector);
        verifier.verifyBundle(proof, anchor, ctx);
    }

    function test_rejectsWrongStorageValue() public {
        bytes memory l2 = _l2("current.ack");
        // Entry 0 is the code hash; flip a value byte of the first channel entry (entry 1).
        uint256 entry1 = 42 + 32 * _pathLen(l2, 0);
        l2[entry1 + 31] = bytes1(uint8(l2[entry1 + 31]) ^ 1);
        bytes memory proof = _bundle("", "current", l2);
        vm.expectRevert(abi.encodeWithSelector(IZkSyncStateTreeVerifier.StorageProofRootMismatch.selector, 1));
        verifier.verifyBundle(proof, anchor, ctx);
    }

    /// A message-bearing bundle whose claimed nextMessageId is changed still has to prove it.
    function test_rejectsForgedNextMessageId() public {
        bytes memory l2 = _l2("current.withMessage");
        uint256 entry1 = 42 + 32 * _pathLen(l2, 0);
        l2[entry1 + 31 - 21] = bytes1(uint8(l2[entry1 + 31 - 21]) ^ 1); // a nextMessageId byte (bits 168+)
        bytes memory proof = _bundle("", "current", l2);
        vm.expectPartialRevert(IZkSyncStateTreeVerifier.StorageProofRootMismatch.selector);
        verifier.verifyBundle(proof, anchor, ctx);
    }

    function test_rejectsWrongEntryCount() public {
        // Code entry pinned but proof without it (5 entries) → shape error.
        bytes memory proof = _bundle("", "current", _l2("current.unpinned"));
        vm.expectRevert(ClprEvmBundleVerifier.InvalidStorageProofShape.selector);
        verifier.verifyBundle(proof, anchor, ctx);
        proof = _bundle("", "current", bytes.concat(_l2("current.ack"), hex"00"));
        vm.expectRevert(ZkSyncEraVerifier.MalformedL2StorageProof.selector);
        verifier.verifyBundle(proof, anchor, ctx);
    }

    function test_rejectsBadShapes() public {
        vm.expectRevert(ZkSyncEraVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(_bundle("", "current", _l2("current.ack")), hex"00", ctx);
        bytes[] memory three = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            three[i] = RLP.encode(bytes(""));
        }
        vm.expectRevert(ZkSyncEraVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(RLP.encode(three), anchor, ctx);
    }

    function test_constructor_rejectsIncompleteProfile() public {
        ZkSyncEraVerifier.Profile memory p = _profile(diamond);
        vm.expectRevert(ZkSyncEraVerifier.InvalidDeployment.selector);
        new ZkSyncEraVerifier(IEthL1StateVerifier(address(0)), tree, p);
        vm.expectRevert(ZkSyncEraVerifier.InvalidDeployment.selector);
        new ZkSyncEraVerifier(l1, IZkSyncStateTreeVerifier(address(0)), p);
        p.minProtocolVersion = p.maxProtocolVersion + 1;
        vm.expectRevert(ZkSyncEraVerifier.InvalidDeployment.selector);
        new ZkSyncEraVerifier(l1, tree, p);
        p = _profile(address(0));
        vm.expectRevert(ZkSyncEraVerifier.InvalidDeployment.selector);
        new ZkSyncEraVerifier(l1, tree, p);
    }

    function test_profile_roundTrips() public view {
        assertEq(abi.encode(verifier.profile()), abi.encode(_profile(diamond)));
    }

    function _pathLen(bytes memory l2, uint256 off) internal pure returns (uint256 n) {
        n = (uint256(uint8(l2[off + 40])) << 8) | uint8(l2[off + 41]);
    }
}

/// @notice End to end with the REAL {EthL1StateVerifier}: a generator sync committee (sk = 1) signs a
///         beacon header whose body commits the synthetic L1 state root, so BLS, the SSZ execution branch,
///         the diamond MPT proofs and the Blake2s tree proofs all run for real.
contract ZkSyncEraVerifierEndToEndTest is ZkSyncFixture {
    bytes4 internal constant FORK_VERSION = 0x06000000;
    bytes32 internal constant GVR = bytes32(uint256(0x5e9011a));
    uint64 internal constant SLOT = 8192 * 3 + 5;
    EthL1StateVerifier internal l1;
    ZkSyncEraVerifier internal verifier;
    bytes internal anchor;
    bytes internal lightClientProof;
    bytes internal signature;

    function setUp() public override {
        super.setUp();
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        verifier = new ZkSyncEraVerifier(l1, tree, _profile(diamond));
        anchor = EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            _committeeAggregate(),
            GVR,
            abi.encodePacked(FORK_VERSION),
            channelId,
            serviceCodeHash
        );
        lightClientProof = _lightClientProof(_fullBits(), SYNC_COMMITTEE_SIZE);
    }

    function _lightClientProof(bytes memory bits, uint256 signers) internal returns (bytes memory) {
        return _lightClientProof(bits, signers, false);
    }

    /// @param rotate also carry a sync-committee rotation (generator next committee, synthetic gindex-87
    ///        branch folded into the attested header's state_root).
    function _lightClientProof(bytes memory bits, uint256 signers, bool rotate) internal returns (bytes memory) {
        bytes32 beaconStateRoot = bytes32(uint256(2));
        bytes memory nextCommittee = "";
        bytes32[] memory nextBranch = new bytes32[](0);
        if (rotate) {
            nextBranch = new bytes32[](6);
            for (uint256 i = 0; i < 6; i++) {
                nextBranch[i] = keccak256(abi.encodePacked("next-committee-branch", i));
            }
            beaconStateRoot = _sszFold(
                _committeeRootFromCompressed(_compressedKeys(SYNC_COMMITTEE_SIZE), G1_GEN_COMPRESSED),
                nextBranch,
                ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE
            );
            nextCommittee = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), genUncompressed);
        }
        bytes32[] memory branch = new bytes32[](9);
        bytes32 bodyRoot = l1StateRoot;
        uint256 idx = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY;
        for (uint256 i = 0; i < 9; i++) {
            bodyRoot = idx & 1 == 1
                ? sha256(abi.encodePacked(branch[i], bodyRoot))
                : sha256(abi.encodePacked(bodyRoot, branch[i]));
            idx >>= 1;
        }
        bytes32 headerRoot =
            ClprBeaconSsz.beaconBlockHeaderRoot(SLOT, 7, bytes32(uint256(1)), beaconStateRoot, bodyRoot);
        bytes32 signingRoot =
            ClprBeaconSsz.computeSigningRoot(headerRoot, ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR));
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(SLOT));
        header[1] = RLP.encode(uint256(7));
        header[2] = RLP.encode(bytes32(uint256(1)));
        header[3] = RLP.encode(beaconStateRoot);
        header[4] = RLP.encode(bodyRoot);
        signature = _aggSig(signingRoot, signers);
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(signature);
        bytes[] memory br = new bytes[](9);
        for (uint256 i = 0; i < 9; i++) {
            br[i] = RLP.encode(branch[i]);
        }
        bytes[] memory lc = new bytes[](7);
        lc[0] = RLP.encode(header);
        lc[1] = RLP.encode(agg);
        lc[2] = RLP.encode(l1StateRoot);
        lc[3] = RLP.encode(br);
        if (rotate) {
            bytes[] memory nb = new bytes[](6);
            for (uint256 i = 0; i < 6; i++) {
                nb[i] = RLP.encode(nextBranch[i]);
            }
            lc[4] = nextCommittee;
            lc[5] = RLP.encode(nb);
        } else {
            lc[4] = RLP.encode(bytes("")); // no rotation
            lc[5] = RLP.encode(new bytes[](0));
        }
        lc[6] = RLP.encode(new bytes[](0)); // full participation: no non-signers
        return RLP.encode(lc);
    }

    function _sszFold(bytes32 leaf, bytes32[] memory branch, uint256 gindex) internal pure returns (bytes32 h) {
        h = leaf;
        for (uint256 i = 0; i < branch.length; i++) {
            h = gindex & 1 == 1 ? sha256(abi.encodePacked(branch[i], h)) : sha256(abi.encodePacked(h, branch[i]));
            gindex >>= 1;
        }
    }

    function _fullBits() internal pure returns (bytes memory b) {
        b = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            b[i] = 0xff;
        }
    }

    function test_endToEnd_ackBundle_withRealLightClient() public view {
        bytes memory proof = _bundle(lightClientProof, "current", _l2("current.ack"));
        bytes memory ctx = _ctx(channelId);
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,, bytes memory na,,) = verifier.verifyBundle(proof, anchor, ctx);
        uint256 used = g - gasleft();
        _assertCurrent(m);
        assertEq(na.length, 0);
        console.log("ZkSyncEraVerifier.verifyBundle (512/512, 6 tree entries, no rotation) execution gas:", used);
        console.log("  proofBytes:", proof.length);
    }

    function test_endToEnd_messageBundle_withRealLightClient() public view {
        bytes memory proof = _bundle(lightClientProof, "current", _l2("current.withMessage"));
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,,,,) = verifier.verifyBundle(proof, anchor, _ctx(channelId));
        console.log(
            "ZkSyncEraVerifier.verifyBundle (512/512, 7 tree entries, no rotation) execution gas:", g - gasleft()
        );
        console.log("  proofBytes:", proof.length);
        _assertCurrent(m);
    }

    /// Worst case: a message-bearing bundle that also rotates the sync committee.
    function test_endToEnd_rotationBundle_withRealLightClient() public {
        bytes memory lc = _lightClientProof(_fullBits(), SYNC_COMMITTEE_SIZE, true);
        bytes memory proof = _bundle(lc, "current", _l2("current.withMessage"));
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,, bytes memory na, bytes memory naId,) =
            verifier.verifyBundle(proof, anchor, _ctx(channelId));
        uint256 used = g - gasleft();
        _assertCurrent(m);
        assertEq(na.length, EthBeaconLightClient.TRUST_ANCHOR_LENGTH, "successor anchor");
        assertEq(naId, abi.encodePacked(uint64(4)), "next period");
        console.log("ZkSyncEraVerifier.verifyBundle (7 tree entries + committee rotation) execution gas:", used);
        console.log("  proofBytes:", proof.length);
    }

    /// The split path keeps even a rotation bundle well inside Hedera's limit.
    function test_endToEnd_rotationBundle_recordedEntries() public {
        (address[] memory a, bytes32[] memory k) = _entryKeys(true);
        bytes memory full = _l2("current.withMessage");
        tree.recordStorage(l2Root, a, k, full);
        bytes memory lc = _lightClientProof(_fullBits(), SYNC_COMMITTEE_SIZE, true);
        bytes memory proof = _bundle(lc, "current", _recordedForm(full));
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,, bytes memory na,,) = verifier.verifyBundle(proof, anchor, _ctx(channelId));
        console.log("ZkSyncEraVerifier.verifyBundle (7 RECORDED entries + rotation) execution gas:", g - gasleft());
        console.log("  proofBytes:", proof.length);
        _assertCurrent(m);
        assertEq(na.length, EthBeaconLightClient.TRUST_ANCHOR_LENGTH);
    }

    function test_endToEnd_rejectsBadSignature() public {
        bytes memory proof = _bundle(lightClientProof, "current", _l2("current.ack"));
        // Flip one byte inside the aggregate signature (it is unique in the encoding).
        bytes memory sig = signature;
        uint256 at = _indexOf(proof, sig);
        proof[at + 40] = bytes1(uint8(proof[at + 40]) ^ 1);
        vm.expectRevert();
        verifier.verifyBundle(proof, anchor, _ctx(channelId));
    }

    function test_endToEnd_rejectsBelowTwoThirds() public {
        // 341 of 512 signers (< 2/3): bits for the first 341 members, signature by exactly them.
        bytes memory bits = new bytes(64);
        for (uint256 i = 0; i < 341; i++) {
            bits[i / 8] = bytes1(uint8(bits[i / 8]) | uint8(1 << (i % 8)));
        }
        bytes memory lc = _lightClientProof(bits, 341);
        bytes memory proof = _bundle(lc, "current", _l2("current.ack"));
        vm.expectRevert(abi.encodeWithSelector(EthBeaconLightClient.InsufficientParticipation.selector, 341, 512));
        verifier.verifyBundle(proof, anchor, _ctx(channelId));
    }

    /// An anchor for another committee (here: another aggregate key) does not accept this signature.
    function test_endToEnd_rejectsWrongCommitteeAnchor() public {
        bytes memory proof = _bundle(lightClientProof, "current", _l2("current.ack"));
        bytes memory other = EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            genUncompressed,
            GVR,
            abi.encodePacked(FORK_VERSION),
            channelId,
            serviceCodeHash
        );
        vm.expectRevert();
        verifier.verifyBundle(proof, other, _ctx(channelId));
    }

    function test_endToEnd_rejectsSignatureUnderOtherForkVersion() public {
        bytes memory proof = _bundle(lightClientProof, "current", _l2("current.ack"));
        bytes memory other = anchor;
        other[35] = 0x01; // fork version byte 3
        vm.expectRevert();
        verifier.verifyBundle(proof, other, _ctx(channelId));
    }

    function test_verifyConfig_buildsEthAnchorAndDecodesLedgerConfig() public view {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "eip155:300";
        lc.serviceAddress = abi.encodePacked(service);
        lc.throttles.maxPeerEndpoints = 9;
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(SLOT));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), _committeeAggregate());
        cfg[2] = RLP.encode(GVR);
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(serviceCodeHash);

        // Config-time manifest proof under the genesis anchor.
        (bytes memory info, bytes memory dp) = _batch("current");
        bytes[] memory man = new bytes[](5);
        man[0] = RLP.encode(lightClientProof);
        man[1] = dp;
        man[2] = RLP.encode(info);
        man[3] = RLP.encode(_l2("current.manifestWithCode"));
        man[4] = RLP.encode(vm.parseJsonBytes(json, ".l2.manifestPreimage"));
        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,,
            ClprTypes.Throttles memory throttles,
            bytes memory initialAnchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory manifest
        ) = verifier.verifyConfig(RLP.encode(cfg), channelId, RLP.encode(man));
        assertEq(initialAnchor, anchor, "same anchor as the bundle path");
        assertEq(anchorId, abi.encodePacked(uint64(3)));
        assertEq(chainId, "eip155:300");
        assertEq(serviceAddress, abi.encodePacked(service));
        assertEq(throttles.maxPeerEndpoints, 9);
        assertEq(channelContext, _ctx(channelId));
        assertEq(manifest.version, 2);
    }

    function _indexOf(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < 8 && ok; j++) {
                ok = hay[i + j] == needle[j];
            }
            if (ok && keccak256(abi.encodePacked(_slice(hay, i, needle.length))) == keccak256(needle)) return i;
        }
        revert("needle not found");
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[off + i];
        }
    }
}
