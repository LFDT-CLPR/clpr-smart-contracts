// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AuroraVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/AuroraVerifier.sol";
import {NearAnchoredVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearAnchoredVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";
import {MockEd25519, NearTonFixtures, NearTrieBuilder} from "./NearTonTestKit.sol";

/// @dev Exposes the NEAR trie exclusion proof for direct tests.
contract NearTrieHarness {
    function absent(bytes32 root, bytes memory key, bytes[] memory nodes) external pure {
        NearLightClient.verifyAbsent(root, key, nodes);
    }

    function present(bytes32 root, bytes memory key, bytes[] memory nodes, bytes memory value) external pure {
        NearLightClient.verifyValue(root, key, nodes, value);
    }
}

/// @notice Synthetic AuroraVerifier suite: the Solidity ClprService at SERVICE inside an aurora-engine
///         account "aurora" (EIP-155 chain 1313161554) on a 3-shard NEAR chain with 4 producers. The
///         engine trie holds the engine state, the service's storage generation (0 or 1), the
///         ClprService Channel slots (one of them zero, i.e. absent), the last message's running
///         hash, the manifest commitment, and unrelated keys. Covers verifyBundle / verifyConfig /
///         verifyEvmStorage, generation handling, exclusion proofs and the negative cases.
abstract contract AuroraVerifierFixture is Test {
    MockEd25519 internal ed;
    ClprEd25519SignatureCache internal cache;
    AuroraVerifier internal v;
    NearTrieHarness internal trie;

    bytes internal constant ENGINE = "aurora";
    uint256 internal constant EVM_CHAIN = 1313161554;
    string internal constant CHAIN = "eip155:1313161554";
    address internal constant SERVICE = address(0xC1C1c1c1C1C1C1c1c1C1C1C1c1C1C1C1c1C1c1c1);
    bytes32 internal constant CHANNEL = keccak256("channel-1");
    bytes32 internal constant E1 = keccak256("epoch-1");
    bytes32 internal constant E2 = keccak256("epoch-2");
    bytes32 internal constant E3 = keccak256("epoch-3");

    uint64 internal constant NEXT_ID = 7;
    uint64 internal constant RECV_ID = 5;

    bytes internal prodA;
    bytes internal prodB;
    bytes internal prodC;
    bytes32[4] internal keysA;
    bytes32[4] internal keysB;
    bytes internal manifest;
    bytes internal control;
    bytes32 internal sentHash = keccak256("sent");

    /// Built trie (per generation): root, all nodes, keys.
    struct World {
        uint32 gen;
        bytes32 root;
        bytes[] all;
    }

    function setUp() public virtual {
        ed = new MockEd25519();
        cache = new ClprEd25519SignatureCache(ed);
        trie = new NearTrieHarness();
        for (uint256 i = 0; i < 4; i++) {
            keysA[i] = keccak256(abi.encode("A", i));
            keysB[i] = keccak256(abi.encode("B", i));
        }
        prodA = _producers(keysA, "a");
        prodB = _producers(keysB, "b");
        bytes32[4] memory kc;
        for (uint256 i = 0; i < 4; i++) {
            kc[i] = keccak256(abi.encode("C", i));
        }
        prodC = _producers(kc, "c");
        v = new AuroraVerifier(CHAIN, _st(E1), ed, cache, ENGINE, EVM_CHAIN);
        manifest = NearTonFixtures.manifest(abi.encodePacked(SERVICE), 4);
        control = NearTonFixtures.controlMessage(CHAIN, abi.encodePacked(SERVICE));
    }

    // ── world ───────────────────────────────────────────────────────────────

    function _engineState(uint256 chainId) internal pure returns (bytes memory) {
        // BorshableEngineState::V3 { chain_id, owner_id: "aurora", upgrade_delay_blocks, is_paused, key_manager }
        return abi.encodePacked(uint8(2), bytes32(chainId), _le32(6), "aurora", _le64(0), uint8(0), uint8(0));
    }

    function _ek(bytes memory engineKey) internal pure returns (bytes memory) {
        return NearLightClient.contractDataKey(ENGINE, engineKey);
    }

    function _stateKey() internal pure returns (bytes memory) {
        return _ek(abi.encodePacked(uint8(7), uint8(0), "STATE"));
    }

    function _genKey(address a) internal pure returns (bytes memory) {
        return _ek(abi.encodePacked(uint8(7), uint8(7), a));
    }

    function _slotKey(address a, uint32 gen, bytes32 slot) internal view returns (bytes memory) {
        return _ek(v.storageKey(a, gen, slot));
    }

    /// Channel slot values (slot index 4 = endpointManifestVersion is zero, so absent).
    function _slotValues() internal view returns (bytes32[5] memory s) {
        s[0] = bytes32(uint256(NEXT_ID) << 168 | uint256(1) << 160 | uint256(uint160(address(0xBEEF))));
        s[1] = bytes32(uint256(RECV_ID) << 64 | uint256(3));
        s[2] = sentHash;
        s[3] = keccak256("recv");
        s[4] = bytes32(0);
    }

    function _slots() internal pure returns (bytes32[] memory s) {
        bytes32 cBase = keccak256(abi.encode(CHANNEL, uint256(15)));
        s = new bytes32[](5);
        s[0] = bytes32(uint256(cBase) + 1);
        s[1] = bytes32(uint256(cBase) + 2);
        s[2] = bytes32(uint256(cBase) + 4);
        s[3] = bytes32(uint256(cBase) + 5);
        s[4] = bytes32(uint256(cBase) + 16);
    }

    function _lastMsgSlot() internal pure returns (bytes32) {
        bytes32 qBase = keccak256(abi.encode(CHANNEL, uint256(1)));
        return bytes32(uint256(keccak256(abi.encode(uint64(NEXT_ID - 1), qBase))) + 1);
    }

    function _world(uint32 gen) internal view returns (World memory w) {
        w.gen = gen;
        bytes32[] memory sl = _slots();
        bytes32[5] memory vals = _slotValues();
        NearTrieBuilder.Entry[] memory e = new NearTrieBuilder.Entry[](12);
        uint256 n;
        e[n++] = _entry(_stateKey(), _engineState(EVM_CHAIN));
        for (uint256 i = 0; i < 4; i++) {
            e[n++] = _entry(_slotKey(SERVICE, gen, sl[i]), abi.encodePacked(vals[i]));
        }
        e[n++] = _entry(_slotKey(SERVICE, gen, _lastMsgSlot()), abi.encodePacked(keccak256("last")));
        e[n++] = _entry(_slotKey(SERVICE, gen, bytes32(uint256(18))), abi.encodePacked(keccak256(manifest)));
        if (gen != 0) {
            e[n++] = _entry(_genKey(SERVICE), abi.encodePacked(gen));
            // a stale slot of the previous generation (storage is reset, old keys may linger)
            e[n++] = _entry(_slotKey(SERVICE, 0, sl[0]), abi.encodePacked(keccak256("stale")));
        }
        // unrelated: another EVM contract, another NEAR account
        e[n++] = _entry(_slotKey(address(0xDEAD), 0, sl[0]), abi.encodePacked(bytes32(uint256(9))));
        e[n++] = _entry(NearLightClient.contractDataKey("other.near", "STATE"), hex"0102");
        NearTrieBuilder.Entry[] memory used = new NearTrieBuilder.Entry[](n);
        for (uint256 i = 0; i < n; i++) {
            used[i] = e[i];
        }
        (w.root, w.all) = NearTrieBuilder.buildAll(used);
    }

    function _entry(bytes memory key, bytes memory value) internal pure returns (NearTrieBuilder.Entry memory) {
        return NearTrieBuilder.Entry(NearTrieBuilder.nibblesOf(key), value);
    }

    function _path(World memory w, bytes memory key) internal pure returns (bytes[] memory) {
        return NearTrieBuilder.pathTo(w.root, key, w.all);
    }

    function _engine(World memory w) internal pure returns (AuroraVerifier.EngineProof memory e) {
        e.stateNodes = _path(w, _stateKey());
        e.state = _engineState(EVM_CHAIN);
        e.generationNodes = _path(w, _genKey(SERVICE));
        e.generation = w.gen;
    }

    function _slotProof(World memory w, bytes32 slot, bytes32 value)
        internal
        view
        returns (AuroraVerifier.SlotProof memory s)
    {
        s.nodes = _path(w, _slotKey(SERVICE, w.gen, slot));
        s.value = value;
    }

    function _bundle(World memory w, bool withLast, bool withManifest)
        internal
        view
        returns (AuroraVerifier.BundleProof memory p)
    {
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(2, 3));
        p.shards = _shards(w.root);
        p.engine = _engine(w);
        bytes32[] memory sl = _slots();
        bytes32[5] memory vals = _slotValues();
        p.slots = new AuroraVerifier.SlotProof[](withLast ? 6 : 5);
        for (uint256 i = 0; i < 5; i++) {
            p.slots[i] = _slotProof(w, sl[i], vals[i]);
        }
        if (withLast) p.slots[5] = _slotProof(w, _lastMsgSlot(), keccak256("last"));
        p.bundleContent = NearTonFixtures.bundleContent();
        if (withManifest) {
            p.manifestSlot = _slotProof(w, bytes32(uint256(18)), keccak256(manifest));
            p.manifestPreimage = manifest;
        }
    }

    // ── NEAR light-client helpers (as in NearVerifier.t.sol) ────────────────

    function _st(bytes32 e) internal view returns (NearLightClient.EpochState memory) {
        if (e == E1) return NearLightClient.EpochState(E1, E2, sha256(prodA), sha256(prodB));
        return NearLightClient.EpochState(E2, E3, sha256(prodB), sha256(prodC));
    }

    function _anchor(bytes32 e) internal view returns (bytes memory) {
        NearLightClient.EpochState memory st = _st(e);
        return abi.encodePacked(st.epochId, st.nextEpochId, st.epochBpHash, st.nextBpHash);
    }

    function _producers(bytes32[4] memory keys, bytes memory tag) internal pure returns (bytes memory out) {
        out = abi.encodePacked(_le32(4));
        for (uint256 i = 0; i < 4; i++) {
            bytes memory id = abi.encodePacked(tag, bytes1(uint8(0x30 + i)), ".near");
            out = abi.encodePacked(out, uint8(0), _le32(id.length), id, uint8(0), keys[i], _le128((i + 1) * 10e24));
        }
    }

    function _le32(uint256 x) internal pure returns (bytes4) {
        return bytes4(uint32((x & 0xff) << 24 | ((x >> 8) & 0xff) << 16 | ((x >> 16) & 0xff) << 8 | (x >> 24)));
    }

    function _le64(uint64 x) internal pure returns (bytes8) {
        return NearLightClient._le64(x);
    }

    function _le128(uint256 x) internal pure returns (bytes16 out) {
        uint128 r;
        for (uint256 i = 0; i < 16; i++) {
            r = (r << 8) | uint128((x >> (8 * i)) & 0xff);
        }
        out = bytes16(r);
    }

    function _shards(bytes32 root) internal pure returns (NearAnchoredVerifier.ShardRoots memory s) {
        s.roots = new bytes32[](3);
        s.roots[0] = keccak256("shard0");
        s.roots[1] = root;
        s.roots[2] = keccak256("shard2");
        s.index = 1;
    }

    function _merkle(bytes32 root) internal pure returns (bytes32) {
        return NearLightClient.merklize(_shards(root).roots);
    }

    function _block(
        bytes32 epoch,
        bytes32 nextEpoch,
        bytes32 nextBpHash,
        bytes memory producers,
        bytes32[4] memory keys,
        bytes32 prevStateRoot,
        uint256[] memory signers
    ) internal view returns (NearLightClient.Block memory b) {
        b.prevBlockHash = keccak256("prev");
        b.nextBlockInnerHash = keccak256("next-inner");
        b.innerLite = abi.encodePacked(
            _le64(1000),
            epoch,
            nextEpoch,
            prevStateRoot,
            keccak256("outcome"),
            _le64(1_790_000_000_000_000_000),
            nextBpHash,
            keccak256("merkle")
        );
        b.innerRestHash = keccak256("rest");
        b.producers = producers;
        b.signers = signers;
        b.signatures = new bytes[](signers.length);
        bytes memory msg_ = NearLightClient.approvalMessage(b, 1000);
        for (uint256 i = 0; i < signers.length; i++) {
            b.signatures[i] = ed.sign(keys[signers[i]], msg_);
        }
    }

    function _signers(uint256 a, uint256 b2) internal pure returns (uint256[] memory s) {
        s = new uint256[](2);
        s[0] = a;
        s[1] = b2;
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, abi.encodePacked(SERVICE)));
    }

    /// @dev Arguments are built before `expectRevert`: the sha256 precompile counts as a call.
    function _expectBundleRevert(AuroraVerifier.BundleProof memory p, bytes memory err) internal {
        _expectRevertOn(v, p, _anchor(E1), _ctx(), err);
    }

    function _expectRevertOn(
        AuroraVerifier target,
        AuroraVerifier.BundleProof memory p,
        bytes memory anchor,
        bytes memory ctx,
        bytes memory err
    ) internal {
        bytes memory proof = abi.encode(p);
        if (err.length == 0) vm.expectRevert(); // any revert: the failing trie node depends on key order
        else vm.expectRevert(err);
        target.verifyBundle(proof, anchor, ctx);
    }
}

contract AuroraVerifierTest is AuroraVerifierFixture {
    // ── happy paths ─────────────────────────────────────────────────────────

    function _checkMeta(ClprTypes.QueueMetadata memory m) internal pure {
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, NEXT_ID);
        assertEq(m.receivedMessageId, RECV_ID);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(m.endpointManifestVersion, 0); // proven absent = zero word
    }

    function test_verifyBundle_generation0() public view {
        World memory w = _world(0);
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyBundle(abi.encode(_bundle(w, true, false)), _anchor(E1), _ctx());
        _checkMeta(m);
        assertEq(payloads.length, 2);
        assertEq(na.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_generation1_withManifest() public view {
        World memory w = _world(1);
        (ClprTypes.QueueMetadata memory m,,,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyBundle(abi.encode(_bundle(w, true, true)), _anchor(E1), _ctx());
        _checkMeta(m);
        assertEq(man.version, 4);
        assertEq(man.serviceAddress, abi.encodePacked(SERVICE));
    }

    function test_verifyBundle_ackOnly() public view {
        World memory w = _world(0);
        (ClprTypes.QueueMetadata memory m,,,,) =
            v.verifyBundle(abi.encode(_bundle(w, false, false)), _anchor(E1), _ctx());
        _checkMeta(m);
    }

    function test_verifyBundle_epochRotation() public view {
        World memory w = _world(0);
        AuroraVerifier.BundleProof memory p = _bundle(w, true, false);
        p.blocks[0] = _block(E2, E3, sha256(prodC), prodB, keysB, _merkle(w.root), _signers(2, 3));
        (,, bytes memory na, bytes memory naId,) = v.verifyBundle(abi.encode(p), _anchor(E1), _ctx());
        assertEq(na, _anchor(E2));
        assertEq(naId, abi.encodePacked(E2));
    }

    function test_verifyConfig_withManifest() public view {
        World memory w = _world(1);
        AuroraVerifier.ConfigProof memory p;
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(2, 3));
        p.shards = _shards(w.root);
        p.engine = _engine(w);
        p.controlMessage = control;
        AuroraVerifier.ManifestProof memory mp =
            AuroraVerifier.ManifestProof(_slotProof(w, bytes32(uint256(18)), keccak256(manifest)), manifest);
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory svc,,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(abi.encode(p), CHANNEL, abi.encode(mp));
        assertEq(ctx, _ctx());
        assertEq(chainId, CHAIN);
        assertEq(svc, abi.encodePacked(SERVICE));
        assertEq(anchor, _anchor(E1));
        assertEq(anchorId, abi.encodePacked(E1));
        assertEq(man.version, 4);
    }

    function test_verifyEvmStorage() public view {
        World memory w = _world(1);
        AuroraVerifier.StorageProof memory p;
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(2, 3));
        p.shards = _shards(w.root);
        p.engine = _engine(w);
        p.account = SERVICE;
        p.slots = new bytes32[](2);
        p.slots[0] = bytes32(uint256(18));
        p.slots[1] = bytes32(uint256(19)); // never written: absent
        p.proofs = new AuroraVerifier.SlotProof[](2);
        p.proofs[0] = _slotProof(w, p.slots[0], keccak256(manifest));
        p.proofs[1] = _slotProof(w, p.slots[1], bytes32(0));
        (bytes32[] memory values, uint32 gen,, uint64 height, bytes memory na) =
            v.verifyEvmStorage(abi.encode(p), _anchor(E1));
        assertEq(values[0], keccak256(manifest));
        assertEq(values[1], bytes32(0));
        assertEq(gen, 1);
        assertEq(height, 1000);
        assertEq(na.length, 0);
    }

    function test_storageKey_layout() public view {
        bytes32 slot = bytes32(uint256(3));
        assertEq(v.storageKey(SERVICE, 0, slot), abi.encodePacked(hex"0704", SERVICE, slot));
        // generation is little-endian in the storage key (aurora-engine generation_storage_key)
        assertEq(v.storageKey(SERVICE, 1, slot), abi.encodePacked(hex"0704", SERVICE, hex"01000000", slot));
        assertEq(v.storageKey(SERVICE, 0x01020304, slot), abi.encodePacked(hex"0704", SERVICE, hex"04030201", slot));
    }

    // ── exclusion proofs (NearLightClient.verifyAbsent) ─────────────────────

    function test_trie_absentKeys() public view {
        World memory w = _world(1);
        // missing branch child / diverging leaf / prefix of an existing key / longer than a leaf key
        bytes[4] memory keys = [
            _slotKey(SERVICE, 1, bytes32(uint256(19))),
            _ek(hex"ff"),
            _ek(abi.encodePacked(uint8(7), uint8(0), "STAT")),
            _ek(abi.encodePacked(uint8(7), uint8(0), "STATE!"))
        ];
        for (uint256 i = 0; i < keys.length; i++) {
            trie.absent(w.root, keys[i], _path(w, keys[i]));
        }
    }

    function test_trie_rejects_absenceOfPresentKey() public {
        World memory w = _world(1);
        bytes memory k = _stateKey();
        bytes[] memory path = _path(w, k);
        vm.expectRevert(NearLightClient.TrieKeyPresent.selector);
        trie.absent(w.root, k, path);
    }

    function test_trie_rejects_truncatedAbsenceProof() public {
        World memory w = _world(1);
        bytes memory k = _slotKey(SERVICE, 1, bytes32(uint256(19)));
        bytes[] memory path = _path(w, k);
        bytes[] memory cut = new bytes[](path.length - 1);
        for (uint256 i = 0; i < cut.length; i++) {
            cut[i] = path[i];
        }
        vm.expectRevert(NearLightClient.TrieKeyNotFound.selector);
        trie.absent(w.root, k, cut);
    }

    function test_trie_rejects_extraNodeAfterValue() public {
        World memory w = _world(1);
        bytes memory k = _stateKey();
        bytes[] memory path = _path(w, k);
        bytes[] memory longer = new bytes[](path.length + 1);
        for (uint256 i = 0; i < path.length; i++) {
            longer[i] = path[i];
        }
        longer[path.length] = path[0];
        vm.expectRevert(NearLightClient.TrieProofTooLong.selector);
        trie.present(w.root, k, longer, _engineState(EVM_CHAIN));
    }

    // ── negative cases ──────────────────────────────────────────────────────

    function test_rejects_zeroClaimedForPresentSlot() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), true, false);
        p.slots[2].value = bytes32(0); // sentRunningHash claimed zero
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.TrieKeyPresent.selector));
    }

    function test_rejects_valueClaimedForAbsentSlot() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), true, false);
        p.slots[4].value = bytes32(uint256(9)); // endpointManifestVersion forged to 9
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.TrieKeyNotFound.selector));
    }

    function test_rejects_tamperedSlotValue() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), true, false);
        p.slots[0].value = bytes32(uint256(p.slots[0].value) + (uint256(1) << 168)); // nextMessageId + 1
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.TrieValueMismatch.selector));
    }

    function test_rejects_generationHidden() public {
        // generation 1 world, relayer claims generation 0 to read the stale generation-0 slot
        World memory w = _world(1);
        AuroraVerifier.BundleProof memory p = _bundle(w, false, false);
        p.engine.generation = 0;
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.TrieKeyPresent.selector));
    }

    function test_rejects_generationForged() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        p.engine.generation = 1;
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.TrieKeyNotFound.selector));
    }

    function test_rejects_wrongEngineChainId() public {
        AuroraVerifier other = new AuroraVerifier(CHAIN, _st(E1), ed, cache, ENGINE, 1313161555);
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        _expectRevertOn(
            other, p, _anchor(E1), _ctx(), abi.encodeWithSelector(AuroraVerifier.WrongEngineChainId.selector, EVM_CHAIN)
        );
    }

    function test_rejects_wrongEngineAccount() public {
        AuroraVerifier other = new AuroraVerifier(CHAIN, _st(E1), ed, cache, "aurora2", EVM_CHAIN);
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        _expectRevertOn(other, p, _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.TrieKeyNotFound.selector));
    }

    function test_rejects_wrongShard() public {
        // absence "proven" in a shard that does not hold the engine: the engine-state proof fails
        World memory w = _world(0);
        AuroraVerifier.BundleProof memory p = _bundle(w, false, false);
        p.shards.index = 0;
        _expectBundleRevert(p, abi.encodeWithSelector(NearLightClient.TrieNodeHashMismatch.selector, 0));
    }

    function test_rejects_wrongChannel() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), true, false);
        bytes memory ctx =
            ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(keccak256("other"), abi.encodePacked(SERVICE)));
        _expectRevertOn(v, p, _anchor(E1), ctx, abi.encodePacked(NearLightClient.TrieKeyNotFound.selector));
    }

    /// another contract's storage cannot stand in: every engine key embeds the service address
    function test_rejects_wrongService() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), true, false);
        bytes memory ctx =
            ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, abi.encodePacked(address(0xDEAD))));
        _expectRevertOn(v, p, _anchor(E1), ctx, "");
    }

    function test_rejects_badServiceAddressLength() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        bytes memory ctx = ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, "clpr.near"));
        _expectRevertOn(
            v, p, _anchor(E1), ctx, abi.encodePacked(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector)
        );
    }

    function test_rejects_badSlotCount() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        AuroraVerifier.SlotProof[] memory four = new AuroraVerifier.SlotProof[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = p.slots[i];
        }
        p.slots = four;
        _expectBundleRevert(p, abi.encodePacked(ClprEvmBundleVerifier.InvalidStorageProofShape.selector));
    }

    function test_rejects_belowThreshold() public {
        World memory w = _world(0);
        AuroraVerifier.BundleProof memory p = _bundle(w, false, false);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(1, 3));
        _expectBundleRevert(p, abi.encodeWithSelector(NearLightClient.InsufficientStake.selector, 60e24, 100e24));
    }

    function test_rejects_wrongValidatorSet() public {
        World memory w = _world(0);
        AuroraVerifier.BundleProof memory p = _bundle(w, false, false);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodB, keysB, _merkle(w.root), _signers(2, 3));
        _expectBundleRevert(p, abi.encodePacked(NearLightClient.ProducersHashMismatch.selector));
    }

    function test_rejects_staleBlockAfterRotation() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, false);
        _expectRevertOn(v, p, _anchor(E2), _ctx(), abi.encodeWithSelector(NearLightClient.EpochNotTrusted.selector, E1));
    }

    function test_rejects_manifestMismatch() public {
        AuroraVerifier.BundleProof memory p = _bundle(_world(0), false, true);
        p.manifestPreimage = NearTonFixtures.manifest(abi.encodePacked(SERVICE), 5);
        _expectBundleRevert(p, abi.encodePacked(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector));
    }

    function test_config_rejects_wrongChainId() public {
        World memory w = _world(0);
        AuroraVerifier.ConfigProof memory p;
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(2, 3));
        p.shards = _shards(w.root);
        p.engine = _engine(w);
        p.controlMessage = NearTonFixtures.controlMessage("eip155:1", abi.encodePacked(SERVICE));
        bytes memory proof = abi.encode(p);
        vm.expectRevert(ClprNearTonBundleVerifier.WrongChainId.selector);
        v.verifyConfig(proof, CHANNEL, "");
    }

    function test_constructor_rejectsBadEngineAccount() public {
        NearLightClient.EpochState memory st = _st(E1);
        vm.expectRevert(ClprNearTonBundleVerifier.InvalidServiceAddress.selector);
        new AuroraVerifier(CHAIN, st, ed, cache, "Aurora", EVM_CHAIN);
    }
}
