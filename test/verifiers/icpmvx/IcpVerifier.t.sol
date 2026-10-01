// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IcpBls} from "@hiero-ledger/clpr/libraries/proof/icp/IcpBls.sol";
import {IcpCertificate} from "@hiero-ledger/clpr/libraries/proof/icp/IcpCertificate.sol";
import {IcpHashTree} from "@hiero-ledger/clpr/libraries/proof/icp/IcpHashTree.sol";
import {IcpVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/IcpVerifier.sol";
import {IcpTestKit} from "@test/verifiers/icpmvx/IcpTestKit.sol";

/// @dev Exposes library internals for direct tests.
contract IcpHarness {
    function reconstruct(bytes memory t) external pure returns (bytes32) {
        return IcpHashTree.reconstruct(t);
    }

    function lookup(bytes memory t, bytes[] memory path) external pure returns (bytes memory) {
        return IcpHashTree.lookup(t, path);
    }

    function inRanges(bytes memory blob, bytes memory id) external pure returns (bool) {
        return IcpCertificate.inRanges(blob, id);
    }

    function leb128(bytes memory b) external pure returns (uint64) {
        return IcpHashTree.leb128(b);
    }

    function expand(bytes memory m, bytes memory dst, uint256 n) external pure returns (bytes memory) {
        return IcpBls.expandMessageXmd(m, dst, n);
    }
}

contract IcpVerifierTest is IcpTestKit {
    IcpHarness internal h;

    function setUp() public override {
        super.setUp();
        h = new IcpHarness();
    }

    function _verify(IcpVerifier.BundleProof memory p)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes[] memory payloads)
    {
        (m, payloads,,,) = v.verifyBundle(abi.encode(p), _anchor(), _ctx());
    }

    // ── happy paths ─────────────────────────────────────────────────────────

    function test_bundle_delegated() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        bytes memory proof = abi.encode(p);
        uint256 g = gasleft();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,
            bytes memory naId,
            ClprTypes.ClprEndpointManifest memory em
        ) = v.verifyBundle(proof, _anchor(), _ctx());
        emit log_named_uint("verifyBundle gas (2 messages)", g - gasleft());
        emit log_named_uint("proof bytes", proof.length);
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 7);
        assertEq(m.receivedMessageId, 5);
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(m.endpointManifestVersion, 3);
        assertEq(payloads.length, 2);
        assertEq(payloads[1], hex"0a0102");
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
        assertEq(em.version, 0);
    }

    function test_bundle_withManifest() public view {
        (,,,, ClprTypes.ClprEndpointManifest memory em) = v.verifyBundle(abi.encode(_bundle(true)), _anchor(), _ctx());
        assertEq(em.version, 2);
        assertEq(em.serviceAddress, CANISTER);
    }

    function test_bundle_rootSubnetCertificate() public view {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert = _rootCert(CANISTER, IcpHashTree.reconstruct(p.witness));
        (ClprTypes.QueueMetadata memory m,) = _verify(p);
        assertEq(m.nextMessageId, 7);
    }

    function test_bundle_shardedCanisterRanges() public view {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.delegationTree = _delegationTree(_der(subnetKey), _ranges(RANGE_START, RANGE_END), true);
        p.cert.rangesShard = RANGE_START;
        _resign(p.cert);
        (ClprTypes.QueueMetadata memory m,) = _verify(p);
        assertEq(m.nextMessageId, 7);
    }

    function test_bundle_witnessWithPrunedSiblings() public view {
        // the canister may prune everything except the queue record
        bytes memory queue = _labeled("queue", _labeled(abi.encodePacked(CHANNEL), _leaf(record)));
        bytes memory w = _labeled("clpr", _fork(_pruned(keccak256("cfg+manifest")), queue));
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.witness = w;
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(w));
        (ClprTypes.QueueMetadata memory m,) = _verify(p);
        assertEq(m.nextMessageId, 7);
    }

    function test_config_happy() public view {
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory service,
            uint96 nanos,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory em
        ) = v.verifyConfig(abi.encode(_configProofStruct()), CHANNEL, "");
        assertEq(chainId, CHAIN);
        assertEq(service, CANISTER);
        assertEq(nanos, 1_700_000_000_000_000_000);
        assertEq(anchor, _anchor());
        assertEq(anchorId, _anchor());
        assertEq(em.version, 0);
        assertEq(ClprTypes.decodeChannelContext(ctx).channelId, CHANNEL);
    }

    function test_config_withManifest() public view {
        (,,,,,,, ClprTypes.ClprEndpointManifest memory em) =
            v.verifyConfig(abi.encode(_configProofStruct()), CHANNEL, abi.encode(IcpVerifier.ManifestProof(manifest)));
        assertEq(em.version, 2);
    }

    // ── negative: signatures and keys ───────────────────────────────────────

    function test_rejects_badSubnetSignature() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.signature = _sign(SUBNET_SK + 1, IcpHashTree.reconstruct(p.cert.tree));
        vm.expectRevert(IcpBls.BadSignature.selector);
        _verify(p);
    }

    function test_rejects_delegationNotSignedByRoot() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.delegationSignature = _sign(SUBNET_SK, IcpHashTree.reconstruct(p.cert.delegationTree));
        vm.expectRevert(IcpBls.BadSignature.selector);
        _verify(p);
    }

    function test_rejects_certificateWithoutDelegationSignedBySubnet() public {
        // dropping the delegation makes the root key the signing key
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.subnetId = "";
        vm.expectRevert(IcpBls.BadSignature.selector);
        _verify(p);
    }

    function test_rejects_subnetKeyNotInDelegation() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.subnetKey = _pk(SUBNET_SK + 1);
        p.cert.signature = _sign(SUBNET_SK + 1, IcpHashTree.reconstruct(p.cert.tree));
        vm.expectRevert(IcpBls.KeyEncodingMismatch.selector);
        _verify(p);
    }

    function test_negatedSubnetKey_needsNegatedSignature() public {
        // −pk has the same x as pk. An honest signature does not verify under −pk; its negation does,
        // which is no forgery: it signs the same certified root.
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.subnetKey = _neg(subnetKey);
        vm.expectRevert(IcpBls.BadSignature.selector);
        _verify(p);
        p.cert.signature = _negG1(p.cert.signature);
        (ClprTypes.QueueMetadata memory m,) = _verify(p);
        assertEq(m.nextMessageId, 7);
    }

    function test_gas_tenMessages() public {
        bytes memory content;
        bytes32 hsh;
        for (uint256 i = 0; i < 10; i++) {
            bytes memory msg_ = new bytes(256);
            msg_[0] = bytes1(uint8(i));
            content = bytes.concat(content, hex"12", hex"8002", msg_); // field 2, length 256 (varint 0x80 0x02)
            hsh = sha256(abi.encodePacked(hsh, sha256(msg_)));
        }
        record = _record(1, 11, 0, hsh, bytes32(0), 1);
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.bundleContent = content;
        bytes memory proof = abi.encode(p);
        bytes memory cd = abi.encodeCall(IcpVerifier.verifyBundle, (proof, _anchor(), _ctx()));
        uint256 g = gasleft();
        (, bytes[] memory payloads,,,) = v.verifyBundle(proof, _anchor(), _ctx());
        emit log_named_uint("verifyBundle gas (10 x 256 B, synthetic)", g - gasleft());
        emit log_named_uint("calldata bytes", cd.length);
        assertEq(payloads.length, 10);
    }

    function test_rejects_wrongRootKeyDeployment() public {
        IcpVerifier other = new IcpVerifier(CHAIN, _der(_pk(99)), _pk(99), 0);
        bytes memory proof = abi.encode(_bundle(false));
        bytes memory anchor = abi.encodePacked(other.ROOT_KEY_ID());
        vm.expectRevert(IcpBls.BadSignature.selector);
        other.verifyBundle(proof, anchor, _ctx());
    }

    function test_rejects_badDerPrefix() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        bytes memory der = _der(subnetKey);
        der[3] = 0x31;
        p.cert.delegationTree = _delegationTree(der, _ranges(RANGE_START, RANGE_END), false);
        _resign(p.cert);
        vm.expectRevert(IcpCertificate.BadDerKey.selector);
        _verify(p);
    }

    function test_rejects_keyWithoutCompressionFlag() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        bytes memory der = _der(subnetKey);
        der[37] = bytes1(uint8(der[37]) & 0x7f);
        p.cert.delegationTree = _delegationTree(der, _ranges(RANGE_START, RANGE_END), false);
        _resign(p.cert);
        vm.expectRevert(IcpBls.KeyEncodingMismatch.selector);
        _verify(p);
    }

    function test_rejects_constructorKeyMismatch() public {
        bytes memory der = _der(_pk(5));
        bytes memory unc = _pk(6);
        vm.expectRevert(IcpBls.KeyEncodingMismatch.selector);
        new IcpVerifier(CHAIN, der, unc, 0);
    }

    // ── negative: scope, state and anchor ───────────────────────────────────

    function test_rejects_canisterOutsideRanges() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert.delegationTree = _delegationTree(_der(subnetKey), _ranges(RANGE_START, hex"00000000023000050101"), false);
        _resign(p.cert);
        vm.expectRevert(IcpCertificate.CanisterNotInRanges.selector);
        _verify(p);
    }

    function test_rejects_wrongStorage_tamperedRecord() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        record[8] = 0x09; // nextMessageId changed after certification
        p.witness = _witness();
        vm.expectRevert(IcpVerifier.CertifiedDataMismatch.selector);
        _verify(p);
    }

    function test_rejects_otherCanistersCertifiedData() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.cert = _cert(hex"00000000023000070101", IcpHashTree.reconstruct(p.witness));
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        _verify(p);
    }

    function test_rejects_otherChannel() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        p.witness = _witnessFor(keccak256("other"), record);
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(p.witness));
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        _verify(p);
    }

    function test_rejects_prunedQueueRecord() public {
        IcpVerifier.BundleProof memory p = _bundle(false);
        bytes memory queue = _labeled("queue", _pruned(keccak256("hidden")));
        p.witness = _labeled("clpr", _fork(_pruned(bytes32(0)), queue));
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(p.witness));
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        _verify(p);
    }

    function test_rejects_badQueueRecord() public {
        record = _record(6, 7, 5, bytes32(0), bytes32(0), 0); // status out of range
        IcpVerifier.BundleProof memory p = _bundle(false);
        vm.expectRevert(IcpVerifier.InvalidQueueRecord.selector);
        _verify(p);
        record = bytes.concat(record, hex"00"); // 90 bytes
        p = _bundle(false);
        vm.expectRevert(IcpVerifier.InvalidQueueRecord.selector);
        _verify(p);
    }

    function test_rejects_wrongTrustAnchor() public {
        bytes memory proof = abi.encode(_bundle(false));
        vm.expectRevert(IcpVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(proof, abi.encodePacked(keccak256("x")), _ctx());
        vm.expectRevert(IcpVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(proof, "", _ctx());
    }

    function test_rejects_badServiceAddress() public {
        bytes memory proof = abi.encode(_bundle(false));
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: new bytes(30)})
        );
        vm.expectRevert(IcpVerifier.InvalidServiceAddress.selector);
        v.verifyBundle(proof, _anchor(), ctx);
    }

    function test_rejects_staleDelegation() public {
        delegationTime = TIME - 2 days * 1e9;
        IcpVerifier.BundleProof memory p = _bundle(false);
        vm.expectRevert(IcpCertificate.DelegationTooOld.selector);
        _verify(p);
    }

    function test_replay_olderCertificateReturnsOlderState() public {
        // The verifier is stateless: an older certificate proves the older queue state. ClprService
        // rejects it (BundleLib NoProgress / ClprReplayDetected), see IntegrationIcp.t.sol.
        record = _record(1, 3, 1, bytes32(0), bytes32(0), 0);
        IcpVerifier.BundleProof memory old = _bundle(false);
        old.bundleContent = "";
        (ClprTypes.QueueMetadata memory m,) = _verify(old);
        assertEq(m.nextMessageId, 3);
    }

    function test_rejects_manifestMismatch() public {
        IcpVerifier.BundleProof memory p = _bundle(true);
        p.manifestPreimage = ClprProtobuf.encodeEndpointManifest(_manifest(9, CANISTER));
        vm.expectRevert(IcpVerifier.ManifestCommitmentMismatch.selector);
        _verify(p);
    }

    function test_rejects_configWrongChain() public {
        control = _control("icp:other", CANISTER);
        bytes memory proof = abi.encode(_configProofStruct());
        vm.expectRevert(IcpVerifier.WrongChainId.selector);
        v.verifyConfig(proof, CHANNEL, "");
    }

    function test_rejects_configNotCommitted() public {
        IcpVerifier.ConfigProof memory p = _configProofStruct();
        p.controlMessage = _control(CHAIN, hex"00000000023000060102"); // different canister
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        v.verifyConfig(abi.encode(p), CHANNEL, "");
        p = _configProofStruct();
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(control).config;
        lc.nanosSinceEpoch = 1;
        p.controlMessage = ClprProtobuf.encodeControlMessage(lc);
        vm.expectRevert(IcpVerifier.ConfigCommitmentMismatch.selector);
        v.verifyConfig(abi.encode(p), CHANNEL, "");
    }

    // ── hash tree and helpers ───────────────────────────────────────────────

    function test_tree_specExample() public view {
        // IC interface spec, "Certification", example tree: root hash eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0
        bytes memory t =
            hex"8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67";
        assertEq(
            t,
            _fork(
                _fork(
                    _labeled("a", _fork(_fork(_labeled("x", _leaf("hello")), _empty()), _labeled("y", _leaf("world")))),
                    _labeled("b", _leaf("good"))
                ),
                _fork(_labeled("c", _empty()), _labeled("d", _leaf("morning")))
            )
        );
        assertEq(h.reconstruct(t), 0xeb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0);
        bytes[] memory path = new bytes[](2);
        path[0] = "a";
        path[1] = "y";
        assertEq(h.lookup(t, path), "world");
    }

    function test_tree_rejectsMalformed() public {
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.reconstruct(hex"9f00ff"); // indefinite-length array
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.reconstruct(hex"820500"); // unknown node tag
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.reconstruct(bytes.concat(_empty(), hex"00")); // trailing bytes
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.reconstruct(hex"82044101"); // pruned hash of 1 byte
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.reconstruct(hex"8203"); // truncated leaf
    }

    function test_tree_rejectsTooDeep() public {
        bytes memory t = _empty();
        for (uint256 i = 0; i < 100; i++) {
            t = _fork(t, _empty());
        }
        vm.expectRevert(IcpHashTree.TreeTooDeep.selector);
        h.reconstruct(t);
    }

    function test_tree_lookupErrorsAreNotFound() public {
        bytes memory t = _labeled("a", _labeled("b", _leaf("v")));
        bytes[] memory path = new bytes[](1);
        path[0] = "a"; // ends at a labeled node: Error
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        h.lookup(t, path);
        path[0] = "z"; // absent
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        h.lookup(t, path);
    }

    function test_ranges() public view {
        bytes memory blob = bytes.concat(
            hex"d9d9f78282", _cbytes(hex"0001"), _cbytes(hex"0003"), hex"82", _cbytes(hex"0010"), _cbytes(hex"001001")
        );
        assertTrue(h.inRanges(blob, hex"0001"));
        assertTrue(h.inRanges(blob, hex"000200"));
        assertTrue(h.inRanges(blob, hex"0003"));
        assertFalse(h.inRanges(blob, hex"000300"));
        assertTrue(h.inRanges(blob, hex"001000ff"));
        assertFalse(h.inRanges(blob, hex"00100100"));
        assertFalse(h.inRanges(blob, hex"00"));
    }

    function test_leb128() public {
        assertEq(h.leb128(hex"8bb9859eb2c496ed18"), 1790842908803423371);
        assertEq(h.leb128(hex"00"), 0);
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.leb128(hex"80");
        vm.expectRevert(IcpHashTree.MalformedTree.selector);
        h.leb128(hex"0000");
    }

    function test_expandMessageXmd_rfc9380Vector() public view {
        // RFC 9380 K.1, expand_message_xmd(SHA-256), msg = "", len_in_bytes = 0x20
        bytes memory out = h.expand("", "QUUX-V01-CS02-with-expander-SHA256-128", 32);
        assertEq(out, hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
    }

    function test_hashToG1_rfc9380Vector() public view {
        // RFC 9380 J.9.1 BLS12381G1_XMD:SHA-256_SSWU_RO_, msg = "abc"
        bytes memory p = _hashWithDst("abc", "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_");
        assertEq(
            p,
            hex"0000000000000000000000000000000003567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903"
            hex"000000000000000000000000000000000b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"
        );
    }

    function _hashWithDst(bytes memory m, bytes memory dst) internal view returns (bytes memory) {
        bytes memory u = h.expand(m, dst, 128);
        bytes memory q0 = _map(_mod(u, 0));
        bytes memory q1 = _map(_mod(u, 64));
        (bool ok, bytes memory s) = address(0x0b).staticcall(bytes.concat(q0, q1));
        require(ok);
        return s;
    }

    function _mod(bytes memory u, uint256 off) internal view returns (bytes memory) {
        bytes memory b = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            b[i] = u[off + i];
        }
        (bool ok, bytes memory r) = address(0x05)
            .staticcall(abi.encodePacked(uint256(64), uint256(1), uint256(48), b, uint8(1), IcpBls.FIELD_MODULUS));
        require(ok);
        return bytes.concat(bytes16(0), r);
    }

    function _map(bytes memory fp) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x10).staticcall(fp);
        require(ok);
        return r;
    }

    function _negG1(bytes memory p) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = address(0x0c)
            .staticcall(
                abi.encodePacked(p, uint256(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000))
            );
        require(ok && out.length == 128);
        return out;
    }

    /// @dev −P for a G2 point via G2MSM with scalar r − 1.
    function _neg(bytes memory p) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = address(0x0e)
            .staticcall(
                abi.encodePacked(p, uint256(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000))
            );
        require(ok && out.length == 256);
        return out;
    }
}
