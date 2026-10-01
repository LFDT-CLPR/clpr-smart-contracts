// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ArbitrumNitroVerifier} from "@hiero-ledger/clpr/verifiers/evm/arbitrum/ArbitrumNitroVerifier.sol";
import {ArbitrumAssertionProof as AP} from "@hiero-ledger/clpr/libraries/proof/arbitrum/ArbitrumAssertionProof.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {EthBeaconLightClient as LC} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Stand-in for the Ethereum light client: returns a fixed L1 execution state root for any proof,
///      so the Arbitrum half can be exercised against the live L1 state in isolation.
contract MockL1 is IEthL1StateVerifier {
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

/// @notice ArbitrumNitroVerifier against REAL Arbitrum Sepolia data settled on Ethereum Sepolia:
///         test/verifiers/evm/arbitrum/fixtures/live.json, generated from
///         test/e2e/fixtures/arbitrum-live/capture.json by test/e2e/relay/buildArbitrumLiveProof.ts.
///         Every positive case runs the real sync-committee BLS light client (EIP-2537); negative
///         cases tamper one link of a real proof.
contract ArbitrumNitroVerifierLiveTest is Test {
    using Memory for Memory.Slice;

    string internal json;
    EthL1StateVerifier internal l1;
    ArbitrumNitroVerifier internal verifier; // real light client
    ArbitrumNitroVerifier internal mocked; // L1 state root from the fixture

    bytes internal anchor;
    bytes internal ctx;
    bytes internal bundle;
    bytes[] internal items;

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), _fixture()));
        // Electra/Fulu beacon layout: execution state_root gindex 802 (depth 9), next_sync_committee 87 (depth 6).
        l1 = new EthL1StateVerifier(802, 9, 87, 6, 8192);
        verifier = new ArbitrumNitroVerifier(l1, _profile());
        mocked = new ArbitrumNitroVerifier(new MockL1(vm.parseJsonBytes32(json, ".l1StateRoot")), _profile());
        anchor = vm.parseJsonBytes(json, ".trustAnchor");
        ctx = vm.parseJsonBytes(json, ".channelContext");
        bundle = vm.parseJsonBytes(json, ".confirmed.bundle");
        items = vm.parseJsonBytesArray(json, ".confirmed.items");
    }

    /// @dev The live fixture this suite replays; profile suites (Plume) override it.
    function _fixture() internal pure virtual returns (string memory) {
        return "/test/verifiers/evm/arbitrum/fixtures/live.json";
    }

    function _profile() internal view returns (AP.Profile memory p) {
        p.rollup = vm.parseJsonAddress(json, ".rollup");
        p.rollupAdminLogic = vm.parseJsonAddress(json, ".rollupAdminLogic");
        p.rollupUserLogic = vm.parseJsonAddress(json, ".rollupUserLogic");
        p.layout = AP.Layout({assertionsSlot: 117, assertionStatusOffset: 25});
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    function _with(uint256 idx, bytes memory item) internal view returns (bytes memory) {
        bytes[] memory it = new bytes[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            it[i] = i == idx ? item : items[i];
        }
        return RLP.encode(it);
    }

    function _raw(Memory.Slice[] memory s) internal pure returns (bytes[] memory out) {
        out = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = s[i].toBytes();
        }
    }

    /// The light-client proof (item 0 wraps it in an RLP string) with item `idx` replaced.
    function _lcWith(uint256 idx, bytes memory item) internal view returns (bytes memory) {
        bytes[] memory lc = _raw(RLP.decodeList(vm.parseJsonBytes(json, ".lightClientProof")));
        lc[idx] = item;
        return _with(0, RLP.encode(RLP.encode(lc)));
    }

    function _flip(bytes memory b, uint256 i) internal pure returns (bytes memory) {
        bytes memory c = bytes.concat(b);
        c[i] = c[i] ^ 0x01;
        return c;
    }

    function _bytesItem(bytes memory raw) internal pure returns (bytes memory) {
        return RLP.encode(raw);
    }

    // ── positive: full chain on live data ───────────────────────────────────
    function test_live_verifyBundle_realLightClient() public view {
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId,
            ClprTypes.ClprEndpointManifest memory manifest
        ) = verifier.verifyBundle(bundle, anchor, ctx);
        // The ClprService stand-in has no channel: genuine exclusion proofs → zeroed metadata.
        assertEq(m.nextMessageId, 0);
        assertEq(m.receivedMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
        assertEq(payloads.length, 0);
        assertEq(newAnchor.length, 0);
        assertEq(newAnchorId.length, 0);
        assertEq(manifest.version, 0);
    }

    /// Callee gas only (`vm.lastCallGas`): the test contract's own memory (the parsed fixture) would
    /// otherwise inflate a `gasleft()` delta through calldata encoding.
    function test_live_gasBreakdown() public {
        l1.verifyL1State(vm.parseJsonBytes(json, ".lightClientProof"), anchor);
        uint256 lcGas = vm.lastCallGas().gasTotalUsed;
        mocked.verifyL2State(bundle, anchor);
        uint256 assertionGas = vm.lastCallGas().gasTotalUsed;
        mocked.verifyBundle(bundle, anchor, ctx);
        uint256 mockedGas = vm.lastCallGas().gasTotalUsed;
        verifier.verifyBundle(bundle, anchor, ctx);
        uint256 fullGas = vm.lastCallGas().gasTotalUsed;
        console.log("light client (verifyL1State):", lcGas);
        console.log("L1 rollup storage -> confirmed assertion -> L2 header (mocked L1):", assertionGas);
        console.log("full bundle, mocked L1:", mockedGas);
        console.log("full bundle, real light client:", fullGas, "calldata bytes:", bundle.length);
        assertLt(fullGas, 15_000_000);
    }

    function test_live_verifyL2State_returnsTheConfirmedAssertionsBlock() public view {
        (AP.ConfirmedState memory s,,) =
            verifier.verifyL2State(vm.parseJsonBytes(json, ".confirmed.l2StateProof"), anchor);
        assertEq(s.assertionHash, vm.parseJsonBytes32(json, ".confirmed.assertionHash"));
        assertEq(s.l2BlockHash, vm.parseJsonBytes32(json, ".confirmed.l2BlockHash"));
        assertEq(s.l2StateRoot, vm.parseJsonBytes32(json, ".confirmed.l2StateRoot"));
        assertEq(s.l2BlockNumber, vm.parseUint(vm.parseJsonString(json, ".confirmed.l2BlockNumber")));
        assertEq(s.sendRoot, vm.parseJsonBytes32(json, ".confirmed.sendRoot"));
    }

    function test_live_mockedL1_matchesRealLightClient() public view {
        (AP.ConfirmedState memory a,,) = verifier.verifyL2State(bundle, anchor);
        (AP.ConfirmedState memory b,,) = mocked.verifyL2State(bundle, anchor);
        assertEq(a.l2StateRoot, b.l2StateRoot);
    }

    function test_live_profile_roundTrips() public view {
        AP.Profile memory p = verifier.profile();
        assertEq(p.rollup, vm.parseJsonAddress(json, ".rollup"));
        assertEq(p.rollupAdminLogic, vm.parseJsonAddress(json, ".rollupAdminLogic"));
        assertEq(p.rollupUserLogic, vm.parseJsonAddress(json, ".rollupUserLogic"));
        assertEq(p.layout.assertionsSlot, 117);
        assertEq(p.layout.assertionStatusOffset, 25);
    }

    // ── negative: L1 light client ───────────────────────────────────────────
    function test_rejects_badSignature_tamperedAttestedHeader() public {
        Memory.Slice[] memory hs = RLP.readList(RLP.decodeList(vm.parseJsonBytes(json, ".lightClientProof"))[0]);
        bytes[] memory h = _raw(hs);
        h[1] = RLP.encode(RLP.readUint256(hs[1]) + 1); // proposer_index + 1 → another signing root
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(_lcWith(0, RLP.encode(h)), anchor, ctx);
    }

    function test_rejects_badSignature_otherG2Point() public {
        Memory.Slice[] memory agg = RLP.readList(RLP.decodeList(vm.parseJsonBytes(json, ".lightClientProof"))[1]);
        bytes[] memory a = _raw(agg);
        // A valid G2 point in the subgroup, but a signature over another message.
        bytes memory sig = RLP.readBytes(agg[1]);
        bytes memory other = ClprBeaconBls.hashToG2(keccak256("not the attested header"));
        assertTrue(keccak256(sig) != keccak256(other));
        a[1] = RLP.encode(other);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(_lcWith(1, RLP.encode(a)), anchor, ctx);
    }

    function test_rejects_belowThreshold() public {
        Memory.Slice[] memory agg = RLP.readList(RLP.decodeList(vm.parseJsonBytes(json, ".lightClientProof"))[1]);
        bytes[] memory a = _raw(agg);
        bytes memory bits = RLP.readBytes(agg[0]);
        for (uint256 i = 0; i < 22; i++) {
            bits[i] = 0x00; // clear 176 members → < 342 participants
        }
        a[0] = RLP.encode(bits);
        vm.expectPartialRevert(LC.InsufficientParticipation.selector);
        verifier.verifyBundle(_lcWith(1, RLP.encode(a)), anchor, ctx);
    }

    function test_rejects_flippedParticipationBit() public {
        Memory.Slice[] memory agg = RLP.readList(RLP.decodeList(vm.parseJsonBytes(json, ".lightClientProof"))[1]);
        bytes[] memory a = _raw(agg);
        bytes memory bits = RLP.readBytes(agg[0]);
        // Find a set bit and clear it: one more non-signer than proofs carried.
        uint256 i;
        while (bits[i] == 0) i++;
        bits[i] = bits[i] & (bits[i] ^ bytes1(uint8(1) << _lowestSet(uint8(bits[i]))));
        a[0] = RLP.encode(bits);
        vm.expectPartialRevert(LC.NonSignerProofCountMismatch.selector);
        verifier.verifyBundle(_lcWith(1, RLP.encode(a)), anchor, ctx);
    }

    function _lowestSet(uint8 b) internal pure returns (uint8 k) {
        while ((b >> k) & 1 == 0) k++;
    }

    function test_rejects_wrongValidatorSet_committeeRoot() public {
        bytes memory bad = _flip(anchor, LC.ANCHOR_OFF_COMMITTEE_ROOT + 5);
        // The live update has non-signers whose Merkle proofs no longer reach the root; with full
        // participation the BLS check against the anchor aggregate fails instead.
        vm.expectRevert();
        verifier.verifyBundle(bundle, bad, ctx);
    }

    function test_rejects_wrongValidatorSet_aggregate() public {
        bytes memory bad = bytes.concat(anchor);
        bytes memory other = ClprBeaconBls.hashToG2(bytes32(0)); // any bytes: G1 decode/BLS must fail
        for (uint256 i = 0; i < 64; i++) {
            bad[LC.ANCHOR_OFF_AGGREGATE + 64 + i] = other[i];
        }
        vm.expectRevert();
        verifier.verifyBundle(bundle, bad, ctx);
    }

    function test_rejects_staleAnchor_otherForkVersion() public {
        bytes memory bad = _flip(anchor, LC.ANCHOR_OFF_FORK_VERSION + 3); // previous fork's domain
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(bundle, bad, ctx);
    }

    function test_rejects_forgedExecutionStateRoot() public {
        vm.expectRevert(LC.ExecutionBranchInvalid.selector);
        verifier.verifyBundle(_lcWith(2, RLP.encode(keccak256("forged L1 state"))), anchor, ctx);
    }

    // ── negative: L1 rollup storage → assertion ─────────────────────────────
    /// A real Pending assertion (the latest confirmed one's child) under its own real light-client proof
    /// (the main attested block, or the rotation update's when no child existed at the main block).
    function test_rejects_pendingAssertion() public {
        vm.skip(!vm.parseJsonBool(json, ".hasPending"));
        vm.expectRevert(
            abi.encodeWithSelector(
                AP.AssertionNotConfirmed.selector, vm.parseJsonBytes32(json, ".pending.assertionHash"), uint8(1)
            )
        );
        verifier.verifyL2State(vm.parseJsonBytes(json, ".pending.l2StateProof"), anchor);
    }

    function test_rejects_neverCreatedAssertion_exclusionProof() public {
        bytes memory b = _with(1, vm.parseJsonBytes(json, ".forged.assertionProofItem"));
        b = _withIn(b, 2, _bytesItem(vm.parseJsonBytes(json, ".forged.preimage")));
        vm.expectRevert(
            abi.encodeWithSelector(
                AP.AssertionNotConfirmed.selector, vm.parseJsonBytes32(json, ".forged.assertionHash"), uint8(0)
            )
        );
        verifier.verifyBundle(b, anchor, ctx);
    }

    function test_rejects_preimageNotMatchingProvenSlot() public {
        // Forged preimage with the REAL assertion's storage proof: the derived slot is not proven.
        bytes memory b = _with(2, _bytesItem(vm.parseJsonBytes(json, ".forged.preimage")));
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        mocked.verifyBundle(b, anchor, ctx);
    }

    function test_rejects_machineNotFinished() public {
        bytes memory pre = vm.parseJsonBytes(json, ".confirmed.preimage");
        pre[32 + 4 * 32 + 31] = 0x02; // afterState.machineStatus = ERRORED
        vm.expectRevert(abi.encodeWithSelector(AP.MachineNotFinished.selector, uint256(2)));
        mocked.verifyBundle(_with(2, _bytesItem(pre)), anchor, ctx);
    }

    function test_rejects_badPreimageLength() public {
        bytes memory pre = vm.parseJsonBytes(json, ".confirmed.preimage");
        vm.expectRevert(AP.InvalidAssertionPreimage.selector);
        mocked.verifyBundle(_with(2, _bytesItem(bytes.concat(pre, hex"00"))), anchor, ctx);
    }

    function test_rejects_unpinnedRollupLogic() public {
        AP.Profile memory p = _profile();
        p.rollupUserLogic = address(0xBEEF);
        ArbitrumNitroVerifier v = new ArbitrumNitroVerifier(new MockL1(vm.parseJsonBytes32(json, ".l1StateRoot")), p);
        vm.expectRevert(
            abi.encodeWithSelector(AP.RollupLogicMismatch.selector, p.rollupAdminLogic, _profile().rollupUserLogic)
        );
        v.verifyBundle(bundle, anchor, ctx);
    }

    function test_rejects_rollupOfAnotherChain() public {
        AP.Profile memory p = _profile();
        p.rollup = 0x4DCeB440657f21083db8aDd07665f8ddBe1DCfc0; // Arbitrum One's rollup: no such account proof
        ArbitrumNitroVerifier v = new ArbitrumNitroVerifier(new MockL1(vm.parseJsonBytes32(json, ".l1StateRoot")), p);
        vm.expectRevert();
        v.verifyBundle(bundle, anchor, ctx);
    }

    function test_rejects_otherL1StateRoot() public {
        ArbitrumNitroVerifier v = new ArbitrumNitroVerifier(new MockL1(keccak256("other L1 state")), _profile());
        vm.expectRevert();
        v.verifyBundle(bundle, anchor, ctx);
    }

    function test_rejects_tamperedRollupStorageProof() public {
        Memory.Slice[] memory ap = RLP.decodeList(items[1]);
        bytes[] memory apRaw = _raw(ap);
        Memory.Slice[] memory entries = RLP.readList(ap[1]);
        bytes[] memory e = _raw(entries);
        // Entry 2 is _assertions[h]: corrupt its leaf node.
        Memory.Slice[] memory entry = RLP.readList(entries[2]);
        Memory.Slice[] memory nodes = RLP.readList(entry[1]);
        bytes[] memory n = _raw(nodes);
        bytes memory leaf = RLP.readBytes(nodes[nodes.length - 1]);
        n[nodes.length - 1] = RLP.encode(_flip(leaf, leaf.length - 1));
        bytes[] memory en = new bytes[](2);
        en[0] = entry[0].toBytes();
        en[1] = RLP.encode(n);
        e[2] = RLP.encode(en);
        apRaw[1] = RLP.encode(e);
        vm.expectRevert();
        mocked.verifyBundle(_with(1, RLP.encode(apRaw)), anchor, ctx);
    }

    function test_rejects_badAssertionProofShape() public {
        bytes[] memory one = new bytes[](1);
        one[0] = RLP.encode(new bytes[](0));
        vm.expectRevert(AP.InvalidAssertionProof.selector);
        mocked.verifyBundle(_with(1, RLP.encode(one)), anchor, ctx);
    }

    // ── negative: assertion → L2 header ─────────────────────────────────────
    function test_rejects_headerOfAnotherBlock() public {
        bytes memory h = vm.parseJsonBytes(json, ".confirmed.l2Header");
        bytes memory other = _flip(h, h.length - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AP.L2HeaderHashMismatch.selector, vm.parseJsonBytes32(json, ".confirmed.l2BlockHash"), keccak256(other)
            )
        );
        mocked.verifyBundle(_with(3, _bytesItem(other)), anchor, ctx);
    }

    // ── negative: L2 state → ClprService storage ────────────────────────────
    function test_rejects_wrongPinnedL2CodeHash() public {
        bytes memory bad = _flip(anchor, LC.ANCHOR_OFF_CODE_HASH);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        mocked.verifyBundle(bundle, bad, ctx);
    }

    function test_rejects_storageProofOfAnotherChannel() public {
        // Same proofs replayed for another channel: the slots it derives are not the proven ones.
        bytes memory bad = bytes.concat(anchor);
        bytes32 other = keccak256("another channel");
        for (uint256 i = 0; i < 32; i++) {
            bad[LC.ANCHOR_OFF_CHANNEL_ID + i] = other[i];
        }
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        mocked.verifyBundle(bundle, bad, ctx);
    }

    function test_rejects_tamperedL2StorageProof() public {
        Memory.Slice[] memory entries = RLP.decodeList(items[5]);
        bytes[] memory e = _raw(entries);
        Memory.Slice[] memory entry = RLP.readList(entries[0]);
        Memory.Slice[] memory nodes = RLP.readList(entry[1]);
        bytes[] memory n = _raw(nodes);
        n[0] = RLP.encode(_flip(RLP.readBytes(nodes[0]), 40)); // root node no longer hashes to storageRoot
        bytes[] memory en = new bytes[](2);
        en[0] = entry[0].toBytes();
        en[1] = RLP.encode(n);
        e[0] = RLP.encode(en);
        vm.expectRevert();
        mocked.verifyBundle(_with(5, RLP.encode(e)), anchor, ctx);
    }

    function test_rejects_otherServiceAddress() public {
        bytes memory badCtx = bytes.concat(ctx);
        badCtx[badCtx.length - 1] = badCtx[badCtx.length - 1] ^ 0x01;
        vm.expectRevert();
        mocked.verifyBundle(bundle, anchor, badCtx);
    }

    // ── shapes and deployment ───────────────────────────────────────────────
    function test_rejects_badShapes() public {
        vm.expectRevert(ArbitrumNitroVerifier.InvalidTrustAnchor.selector);
        mocked.verifyBundle(bundle, hex"00", ctx);
        bytes[] memory six = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            six[i] = items[i];
        }
        vm.expectRevert(ArbitrumNitroVerifier.InvalidPayloadShape.selector);
        mocked.verifyBundle(RLP.encode(six), anchor, ctx);
        bytes[] memory three = new bytes[](3);
        vm.expectRevert(ArbitrumNitroVerifier.InvalidPayloadShape.selector);
        mocked.verifyL2State(RLP.encode(three), anchor);
        vm.expectRevert(ArbitrumNitroVerifier.InvalidPayloadShape.selector);
        mocked.verifyConfig("", bytes32(0), "");
    }

    function test_constructor_rejectsIncompleteProfile() public {
        IEthL1StateVerifier m = new MockL1(bytes32(0));
        AP.Profile memory p = _profile();
        vm.expectRevert(ArbitrumNitroVerifier.InvalidDeployment.selector);
        new ArbitrumNitroVerifier(IEthL1StateVerifier(address(0)), p);
        p.rollup = address(0);
        vm.expectRevert(ArbitrumNitroVerifier.InvalidDeployment.selector);
        new ArbitrumNitroVerifier(m, p);
        p = _profile();
        p.rollupAdminLogic = address(0);
        vm.expectRevert(ArbitrumNitroVerifier.InvalidDeployment.selector);
        new ArbitrumNitroVerifier(m, p);
        p = _profile();
        p.layout.assertionStatusOffset = 32;
        vm.expectRevert(ArbitrumNitroVerifier.InvalidDeployment.selector);
        new ArbitrumNitroVerifier(m, p);
    }

    // ── rotation (validator-set change) on live data ────────────────────────
    /// The rotation update's attested block is up to a sync period (~27 h) old; L1 proofs there come from
    /// an archive RPC, and the L2 proofs are usually outside every public L2 RPC's window, so the
    /// rotation is checked through the confirmed L2 state root (the exact code verifyBundle runs).
    function test_live_rotation_toL2StateRoot() public {
        vm.skip(!vm.parseJsonBool(json, ".hasRotation"));
        (AP.ConfirmedState memory s, bytes memory newAnchor, bytes memory newAnchorId) =
            verifier.verifyL2State(vm.parseJsonBytes(json, ".rotation.confirmed.l2StateProof"), anchor);
        console.log("verifyL2State + rotation gas:", vm.lastCallGas().gasTotalUsed);
        assertEq(s.l2StateRoot, vm.parseJsonBytes32(json, ".rotation.confirmed.l2StateRoot"));
        _checkSuccessor(newAnchor, newAnchorId);
    }

    function test_live_rotation_fullBundle() public {
        vm.skip(!vm.parseJsonBool(json, ".hasRotationBundle"));
        bytes memory b = vm.parseJsonBytes(json, ".rotation.confirmed.bundle");
        (ClprTypes.QueueMetadata memory m,, bytes memory newAnchor, bytes memory newAnchorId,) =
            verifier.verifyBundle(b, anchor, ctx);
        console.log("verifyBundle + rotation gas:", vm.lastCallGas().gasTotalUsed, "calldata bytes:", b.length);
        assertEq(m.nextMessageId, 0);
        _checkSuccessor(newAnchor, newAnchorId);
    }

    function _checkSuccessor(bytes memory newAnchor, bytes memory newAnchorId) internal {
        assertEq(newAnchor.length, LC.TRUST_ANCHOR_LENGTH);
        assertEq(newAnchorId, LC.periodId(uint64(vm.parseUint(vm.parseJsonString(json, ".rotation.nextPeriod")))));
        // The successor keeps the channel binding and the pinned code hash …
        assertEq(_slice(newAnchor, LC.ANCHOR_OFF_CHANNEL_ID, 32), _slice(anchor, LC.ANCHOR_OFF_CHANNEL_ID, 32));
        assertEq(_slice(newAnchor, LC.ANCHOR_OFF_CODE_HASH, 32), _slice(anchor, LC.ANCHOR_OFF_CODE_HASH, 32));
        assertTrue(keccak256(newAnchor) != keccak256(anchor));
        // … and the current period's proof no longer verifies under it (stale anchor / replay across periods).
        vm.expectRevert();
        verifier.verifyBundle(bundle, newAnchor, ctx);
    }

    function _withIn(bytes memory list, uint256 idx, bytes memory item) internal pure returns (bytes memory) {
        bytes[] memory it = _raw(RLP.decodeList(list));
        it[idx] = item;
        return RLP.encode(it);
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[off + i];
        }
    }
}
