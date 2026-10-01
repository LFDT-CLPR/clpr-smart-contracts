// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {NearVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearVerifier.sol";
import {NearAnchoredVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearAnchoredVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";
import {MockEd25519, NearTonFixtures, NearTrieBuilder} from "./NearTonTestKit.sol";

/// @notice Synthetic NearVerifier suite: a CLPR Service at `clpr.near` on a 3-shard chain with
///         4 producers (stakes 10/20/30/40), the full verifyBundle / verifyConfig pipelines, epoch
///         rotation, and the negative cases.
abstract contract NearVerifierFixture is Test {
    MockEd25519 internal ed;
    ClprEd25519SignatureCache internal cache;
    NearVerifier internal v;

    bytes internal constant SERVICE = "clpr.near";
    string internal constant CHAIN = "near:testnet";
    bytes32 internal constant CHANNEL = keccak256("channel-1");
    bytes32 internal constant E1 = keccak256("epoch-1");
    bytes32 internal constant E2 = keccak256("epoch-2");
    bytes32 internal constant E3 = keccak256("epoch-3");

    bytes internal prodA; // epoch E1
    bytes internal prodB; // epoch E2
    bytes internal prodC; // epoch E3
    bytes32[4] internal keysA;
    bytes32[4] internal keysB;

    bytes internal record;
    bytes internal manifest;
    bytes internal control;

    function setUp() public virtual {
        ed = new MockEd25519();
        cache = new ClprEd25519SignatureCache(ed);
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
        v = new NearVerifier(CHAIN, _st(E1), ed, cache);

        record = abi.encodePacked(uint8(1), _le64(7), _le64(5), keccak256("sent"), keccak256("recv"), _le64(3));
        manifest = NearTonFixtures.manifest(SERVICE, 4);
        control = NearTonFixtures.controlMessage(CHAIN, SERVICE);
    }

    // ── builders ────────────────────────────────────────────────────────────

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

    function _key(bytes memory dataKey) internal pure returns (bytes memory) {
        return NearLightClient.contractDataKey(SERVICE, dataKey);
    }

    /// Shard trie with q‖channel, m, c; returns the root and the path to `target`.
    function _trie(bytes memory rec, uint256 target) internal view returns (bytes32 root, bytes[] memory path) {
        NearTrieBuilder.Entry[] memory e = new NearTrieBuilder.Entry[](4);
        e[0] = NearTrieBuilder.Entry(NearTrieBuilder.nibblesOf(_key(abi.encodePacked("q", CHANNEL))), rec);
        e[1] = NearTrieBuilder.Entry(NearTrieBuilder.nibblesOf(_key("m")), abi.encodePacked(keccak256(manifest)));
        e[2] = NearTrieBuilder.Entry(NearTrieBuilder.nibblesOf(_key("c")), abi.encodePacked(keccak256(control)));
        e[3] = NearTrieBuilder.Entry(
            NearTrieBuilder.nibblesOf(NearLightClient.contractDataKey("other.near", "STATE")), hex"0102"
        );
        return NearTrieBuilder.build(e, target);
    }

    function _shards(bytes32 root) internal pure returns (NearAnchoredVerifier.ShardRoots memory s) {
        s.roots = new bytes32[](3);
        s.roots[0] = keccak256("shard0");
        s.roots[1] = root;
        s.roots[2] = keccak256("shard2");
        s.index = 1;
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

    function _bundle(bool withManifest) internal view returns (NearVerifier.BundleProof memory p) {
        (bytes32 root, bytes[] memory qpath) = _trie(record, 0);
        p.blocks = new NearLightClient.Block[](1);
        // 30 + 40 = 70 of 100 > 2/3
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(2, 3));
        p.shards = _shards(root);
        p.queueNodes = qpath;
        p.queueRecord = record;
        p.bundleContent = NearTonFixtures.bundleContent();
        if (withManifest) {
            (, p.manifestNodes) = _trie(record, 1);
            p.manifestPreimage = manifest;
        }
    }

    function _merkle(bytes32 root) internal pure returns (bytes32) {
        return NearLightClient.merklize(_shards(root).roots);
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, SERVICE));
    }

    function _verify(NearVerifier.BundleProof memory p, bytes memory anchor)
        internal
        view
        returns (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,
            bytes memory naId,
            ClprTypes.ClprEndpointManifest memory man
        )
    {
        return v.verifyBundle(abi.encode(p), anchor, _ctx());
    }

    function _expectBundleRevert(bytes memory proof, bytes memory anchor, bytes memory ctx, bytes memory err) internal {
        vm.expectRevert(err);
        v.verifyBundle(proof, anchor, ctx);
    }

    function _expectConfigRevert(bytes memory proof, bytes32 channel, bytes memory mp, bytes memory err) internal {
        vm.expectRevert(err);
        v.verifyConfig(proof, channel, mp);
    }
}

contract NearVerifierTest is NearVerifierFixture {
    // ── happy paths ─────────────────────────────────────────────────────────

    function test_verifyBundle() public view {
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,,
            ClprTypes.ClprEndpointManifest memory man
        ) = _verify(_bundle(false), _anchor(E1));
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 7);
        assertEq(m.receivedMessageId, 5);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(m.endpointManifestVersion, 3);
        assertEq(payloads.length, 2);
        assertEq(na.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_withManifest() public view {
        (,,,, ClprTypes.ClprEndpointManifest memory man) = _verify(_bundle(true), _anchor(E1));
        assertEq(man.version, 4);
        assertEq(man.serviceAddress, SERVICE);
        assertEq(man.endpoints.length, 1);
    }

    function test_verifyBundle_epochRotation() public view {
        NearVerifier.BundleProof memory p = _bundle(false);
        (bytes32 root,) = _trie(record, 0);
        // a block of epoch E2, approved by E2's producers (keysB), carrying the E3 producer hash
        p.blocks[0] = _block(E2, E3, sha256(prodC), prodB, keysB, _merkle(root), _signers(2, 3));
        (,, bytes memory na, bytes memory naId,) = _verify(p, _anchor(E1));
        assertEq(na, _anchor(E2));
        assertEq(naId, abi.encodePacked(E2));
    }

    function test_verifyBundle_twoBlocks_hopThenSameEpoch() public view {
        NearVerifier.BundleProof memory p = _bundle(false);
        (bytes32 root,) = _trie(record, 0);
        NearLightClient.Block memory hop = _block(E2, E3, sha256(prodC), prodB, keysB, keccak256("x"), _signers(2, 3));
        // 20 + 30 + 40 of 100
        uint256[] memory s3 = new uint256[](3);
        (s3[0], s3[1], s3[2]) = (1, 2, 3);
        NearLightClient.Block memory last = _block(E2, E3, sha256(prodC), prodB, keysB, _merkle(root), s3);
        p.blocks = new NearLightClient.Block[](2);
        p.blocks[0] = hop;
        p.blocks[1] = last;
        (,, bytes memory na,,) = _verify(p, _anchor(E1));
        assertEq(na, _anchor(E2));
    }

    function test_verifyConfig() public view {
        NearVerifier.ConfigProof memory p;
        (bytes32 root, bytes[] memory cpath) = _trie(record, 2);
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(2, 3));
        p.shards = _shards(root);
        p.configNodes = cpath;
        p.controlMessage = control;
        (, bytes[] memory mpath) = _trie(record, 1);
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory svc,
            uint96 nanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(abi.encode(p), CHANNEL, abi.encode(NearVerifier.ManifestProof(mpath, manifest)));
        assertEq(ctx, _ctx());
        assertEq(chainId, CHAIN);
        assertEq(svc, SERVICE);
        assertEq(nanos, 1_790_000_000_000_000_123);
        assertEq(t.maxSyncBytes, 65536);
        assertEq(anchor, _anchor(E1));
        assertEq(anchorId, abi.encodePacked(E1));
        assertEq(man.version, 4);
    }

    function test_signatureCache_path() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        bytes memory msg_ = NearLightClient.approvalMessage(p.blocks[0], 1000);
        bytes32[] memory keys = new bytes32[](2);
        (keys[0], keys[1]) = (keysA[2], keysA[3]);
        cache.record(msg_, keys, bytes.concat(p.blocks[0].signatures[0], p.blocks[0].signatures[1]));
        p.blocks[0].signatures[0] = "";
        p.blocks[0].signatures[1] = "";
        _verify(p, _anchor(E1));
    }

    // ── negative cases ──────────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        p.blocks[0].signatures[1] = ed.sign(keysA[0], "wrong message");
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodeWithSelector(ClprEd25519Check.BadSignature.selector, 3)
        );
    }

    function test_rejects_belowThreshold() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        (bytes32 root,) = _trie(record, 0);
        // 20 + 40 = 60 of 100 is not > 2/3
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(1, 3));
        _expectBundleRevert(
            abi.encode(p),
            _anchor(E1),
            _ctx(),
            abi.encodeWithSelector(NearLightClient.InsufficientStake.selector, 60e24, 100e24)
        );
    }

    function test_rejects_wrongValidatorSet() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        (bytes32 root,) = _trie(record, 0);
        // producers of E2 presented for an E1 block
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodB, keysB, _merkle(root), _signers(2, 3));
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.ProducersHashMismatch.selector)
        );
    }

    function test_rejects_untrustedEpoch() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        (bytes32 root,) = _trie(record, 0);
        p.blocks[0] = _block(E3, keccak256("e4"), sha256(prodC), prodC, keysB, _merkle(root), _signers(2, 3));
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodeWithSelector(NearLightClient.EpochNotTrusted.selector, E3)
        );
    }

    function test_rejects_staleBlockAfterRotation() public {
        // the anchor already moved to E2/E3: a (replayed) E1 block is no longer accepted
        _expectBundleRevert(
            abi.encode(_bundle(false)),
            _anchor(E2),
            _ctx(),
            abi.encodeWithSelector(NearLightClient.EpochNotTrusted.selector, E1)
        );
    }

    function test_rejects_duplicateSigner() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        p.blocks[0].signers[0] = 3;
        p.blocks[0].signatures[0] = p.blocks[0].signatures[1];
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.SignersNotAscending.selector)
        );
    }

    function test_rejects_tamperedRecord() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        p.queueRecord[1] = 0x09; // next_message_id 7 → 9
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.TrieValueMismatch.selector)
        );
    }

    function test_rejects_wrongChannel() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(keccak256("other"), SERVICE));
        _expectBundleRevert(
            abi.encode(_bundle(false)), _anchor(E1), ctx, abi.encodePacked(NearLightClient.TrieKeyNotFound.selector)
        );
    }

    function test_rejects_wrongService() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, "evil.near"));
        _expectBundleRevert(
            abi.encode(_bundle(false)), _anchor(E1), ctx, abi.encodePacked(NearLightClient.TrieKeyNotFound.selector)
        );
    }

    function test_rejects_tamperedTrieNode() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        bytes memory n = p.queueNodes[1];
        n[n.length - 1] = 0x01; // memory_usage byte: the node hash changes
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodeWithSelector(NearLightClient.TrieNodeHashMismatch.selector, 1)
        );
    }

    function test_rejects_wrongShardRoots() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        p.shards.roots[0] = keccak256("forged shard");
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.StateRootMismatch.selector)
        );
    }

    function test_rejects_manifestPreimageMismatch() public {
        NearVerifier.BundleProof memory p = _bundle(true);
        p.manifestPreimage = NearTonFixtures.manifest(SERVICE, 5);
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodePacked(NearLightClient.TrieValueMismatch.selector)
        );
    }

    function test_rejects_uncachedEmptySignature() public {
        NearVerifier.BundleProof memory p = _bundle(false);
        p.blocks[0].signatures[0] = "";
        _expectBundleRevert(
            abi.encode(p), _anchor(E1), _ctx(), abi.encodeWithSelector(ClprEd25519Check.SignatureNotCached.selector, 2)
        );
    }

    function test_rejects_badAnchor() public {
        _expectBundleRevert(
            abi.encode(_bundle(false)), hex"00", _ctx(), abi.encodePacked(NearAnchoredVerifier.InvalidAnchor.selector)
        );
    }

    function test_config_rejects_wrongChainId() public {
        NearVerifier.ConfigProof memory p;
        bytes memory otherControl = NearTonFixtures.controlMessage("near:mainnet", SERVICE);
        (bytes32 root, bytes[] memory cpath) = _trie(record, 2);
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(2, 3));
        p.shards = _shards(root);
        p.configNodes = cpath;
        p.controlMessage = otherControl;
        _expectConfigRevert(
            abi.encode(p), CHANNEL, "", abi.encodePacked(ClprNearTonBundleVerifier.WrongChainId.selector)
        );
    }

    function test_config_rejects_unprovenConfig() public {
        NearVerifier.ConfigProof memory p;
        (bytes32 root, bytes[] memory cpath) = _trie(record, 2);
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(2, 3));
        p.shards = _shards(root);
        p.configNodes = cpath;
        // a configuration naming another account: its commitment is not in that account's storage
        p.controlMessage = NearTonFixtures.controlMessage(CHAIN, "clpr2.near");
        _expectConfigRevert(abi.encode(p), CHANNEL, "", abi.encodePacked(NearLightClient.TrieKeyNotFound.selector));
    }
}
