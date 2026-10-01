// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ArcMalachiteVerifier} from "@hiero-ledger/clpr/verifiers/evm/arc/ArcMalachiteVerifier.sol";
import {MptMultiProof} from "@hiero-ledger/clpr/libraries/proof/evm/MptMultiProof.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {ArcMalachiteVerifierHarness} from "./ArcMalachiteVerifierHarness.sol";

/// @notice ArcMalachiteVerifier on LIVE Arc testnet data (test/verifiers/evm/arc/fixtures, exported from
///         test/e2e/fixtures/arc-live by relay/exportArcForgeFixture.ts): real header, real registry
///         and ClprService-stand-in MPT proofs, real Ed25519 certificate. Threshold and malformed-input
///         cases swap in a synthetic validator set on the same real header with a stubbed Ed25519 check
///         (the only stubbed piece; see the harness).
contract ArcMalachiteVerifierTest is Test {
    struct Snap {
        uint64 height;
        uint32 round;
        bytes32 blockHash;
        bytes header;
        bytes parentHeader;
        bytes parentRegistryAccountProof;
        uint256[] sigIndices;
        bytes[] sigs;
        bytes registryAccountProof;
        bytes registrySetProof;
        bytes serviceAccountProof;
        bytes storageProof;
        bytes configSlotProof;
    }

    ArcMalachiteVerifier internal verifier; // production, real Ed25519
    ArcMalachiteVerifierHarness internal stub; // Ed25519 stubbed
    ArcMalachiteVerifierHarness internal real; // harness, real Ed25519

    string internal json;
    bytes32 internal setHash;
    bytes32 internal regRoot;
    bytes32 internal channelId;
    address internal target;
    bytes32[] internal pubkeys;
    uint256[] internal powers;
    Snap internal h1;
    Snap internal h2;

    bytes internal constant PAYLOAD = hex"c1a9c0ffee";
    bytes32 internal constant BOGUS_ROOT = bytes32(uint256(0x11));

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/arc/fixtures/arc-testnet.json"));
        setHash = vm.parseJsonBytes32(json, ".setHash");
        regRoot = vm.parseJsonBytes32(json, ".registryRoot");
        channelId = vm.parseJsonBytes32(json, ".channelId");
        target = vm.parseJsonAddress(json, ".target");
        pubkeys = vm.parseJsonBytes32Array(json, ".pubkeys");
        powers = vm.parseJsonUintArray(json, ".powers");
        _loadSnap(h1, ".h1");
        _loadSnap(h2, ".h2");

        Ed25519Verifier ed = new Ed25519Verifier();
        ArcMalachiteVerifier.Profile memory p = _profile(address(ed));
        verifier = new ArcMalachiteVerifier(p);
        stub = new ArcMalachiteVerifierHarness(p, true);
        real = new ArcMalachiteVerifierHarness(p, false);
    }

    function _profile(address ed) internal view returns (ArcMalachiteVerifier.Profile memory) {
        return ArcMalachiteVerifier.Profile({
            chainId: vm.parseJsonString(json, ".chainId"),
            ed25519Verifier: ed,
            registry: vm.parseJsonAddress(json, ".registry"),
            bootstrapSetHash: setHash,
            bootstrapRegistryRoot: regRoot,
            bootstrapHeight: h1.height
        });
    }

    function _loadSnap(Snap storage s, string memory k) internal {
        s.height = uint64(vm.parseJsonUint(json, string.concat(k, ".height")));
        s.round = uint32(vm.parseJsonUint(json, string.concat(k, ".round")));
        s.blockHash = vm.parseJsonBytes32(json, string.concat(k, ".blockHash"));
        s.header = vm.parseJsonBytes(json, string.concat(k, ".header"));
        s.parentHeader = vm.parseJsonBytes(json, string.concat(k, ".parentHeader"));
        s.parentRegistryAccountProof = vm.parseJsonBytes(json, string.concat(k, ".parentRegistryAccountProof"));
        uint256[] memory idx = vm.parseJsonUintArray(json, string.concat(k, ".sigIndices"));
        bytes[] memory sigs = vm.parseJsonBytesArray(json, string.concat(k, ".sigs"));
        for (uint256 i; i < idx.length; ++i) {
            s.sigIndices.push(idx[i]);
            s.sigs.push(sigs[i]);
        }
        s.registryAccountProof = vm.parseJsonBytes(json, string.concat(k, ".registryAccountProof"));
        s.registrySetProof = vm.parseJsonBytes(json, string.concat(k, ".registrySetProof"));
        s.serviceAccountProof = vm.parseJsonBytes(json, string.concat(k, ".serviceAccountProof"));
        s.storageProof = vm.parseJsonBytes(json, string.concat(k, ".storageProof"));
        s.configSlotProof = vm.parseJsonBytes(json, string.concat(k, ".configSlotProof"));
    }

    // ── Encoding helpers ─────────────────────────────────────────────────────

    function _anchor(bytes32 sh, bytes32 root, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(sh, root, height);
    }

    function _ctx() internal view returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(target)})
        );
    }

    function _list(bytes[] memory items) internal pure returns (bytes memory) {
        return RLP.encode(items);
    }

    function _emptyList() internal pure returns (bytes memory) {
        return _list(new bytes[](0));
    }

    function _sigList(uint256[] memory idx, bytes[] memory sigs) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](idx.length);
        for (uint256 i; i < idx.length; ++i) {
            bytes[] memory pair = new bytes[](2);
            pair[0] = RLP.encode(idx[i]);
            pair[1] = RLP.encode(sigs[i]);
            items[i] = _list(pair);
        }
        return _list(items);
    }

    function _valList(bytes32[] memory keys, uint256[] memory pw) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](keys.length);
        for (uint256 i; i < keys.length; ++i) {
            bytes[] memory pair = new bytes[](2);
            pair[0] = RLP.encode(abi.encodePacked(keys[i]));
            pair[1] = RLP.encode(pw[i]);
            items[i] = _list(pair);
        }
        return _list(items);
    }

    function _setHashOf(bytes32[] memory keys, uint256[] memory pw) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i; i < keys.length; ++i) {
            packed = abi.encodePacked(packed, keys[i], uint64(pw[i]));
        }
        return keccak256(packed);
    }

    function _step(
        bytes memory header,
        bytes memory parentHeader,
        uint32 round,
        bytes memory sigList,
        bytes memory valList,
        bytes memory parentRegAccount,
        bytes memory rotation
    ) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](7);
        f[0] = RLP.encode(header);
        f[1] = RLP.encode(parentHeader);
        f[2] = RLP.encode(uint256(round));
        f[3] = sigList;
        f[4] = valList;
        f[5] = parentRegAccount;
        f[6] = rotation;
        return _list(f);
    }

    function _rotation(Snap storage s) internal view returns (bytes memory) {
        bytes[] memory r = new bytes[](2);
        r[0] = s.registryAccountProof;
        r[1] = s.registrySetProof;
        return _list(r);
    }

    function _liveStep(Snap storage s, bool withRotation) internal view returns (bytes memory) {
        return _step(
            s.header,
            s.parentHeader,
            s.round,
            _sigList(s.sigIndices, s.sigs),
            _valList(pubkeys, powers),
            s.parentRegistryAccountProof,
            withRotation ? _rotation(s) : _emptyList()
        );
    }

    function _bundle(bytes memory step, bytes[] memory hops, Snap storage svc) internal view returns (bytes memory) {
        bytes[] memory f = new bytes[](5);
        f[0] = step;
        f[1] = _list(hops);
        f[2] = svc.serviceAccountProof;
        f[3] = svc.storageProof;
        f[4] = RLP.encode(abi.encodePacked(hex"12", uint8(PAYLOAD.length), PAYLOAD));
        return _list(f);
    }

    function _bundle(bytes memory step) internal view returns (bytes memory) {
        return _bundle(step, new bytes[](0), h2);
    }

    // ── Synthetic set on the real header (stubbed Ed25519) ────────────────────

    function _stubSig(bytes32 key, bytes memory message) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(key, message)), keccak256(abi.encodePacked(message, key)));
    }

    function _synthetic(uint256[] memory pw, uint256[] memory signers)
        internal
        view
        returns (bytes memory step, bytes32 sh)
    {
        bytes32[] memory keys = new bytes32[](pw.length);
        for (uint256 i; i < pw.length; ++i) {
            keys[i] = keccak256(abi.encode("arc-synthetic-validator", i));
        }
        bytes[] memory sigs = new bytes[](signers.length);
        for (uint256 i; i < signers.length; ++i) {
            bytes32 k = keys[signers[i]];
            bytes memory m =
                verifier.precommitSignBytes(h2.height, h2.round, h2.blockHash, bytes20(keccak256(abi.encodePacked(k))));
            sigs[i] = _stubSig(k, m);
        }
        sh = _setHashOf(keys, pw);
        step = _step(
            h2.header,
            h2.parentHeader,
            h2.round,
            _sigList(signers, sigs),
            _valList(keys, pw),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
    }

    function _u(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (a, b);
    }

    function _u(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256[] memory r) {
        r = new uint256[](4);
        (r[0], r[1], r[2], r[3]) = (a, b, c, d);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Live data, real Ed25519
    // ═════════════════════════════════════════════════════════════════════════

    function test_live_fixtureIsConsistent() public view {
        assertEq(keccak256(h2.header), h2.blockHash);
        assertEq(keccak256(h1.header), h1.blockHash);
        assertGt(h2.height, h1.height);
        assertEq(_setHashOf(pubkeys, powers), setHash);
    }

    function test_live_verifyBundle_realCertificate_noRotation() public view {
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory naId,) =
            verifier.verifyBundle(_bundle(_liveStep(h2, false)), _anchor(setHash, regRoot, h1.height), _ctx());
        assertEq(m.nextMessageId, 0);
        assertEq(payloads.length, 1);
        assertEq(payloads[0], PAYLOAD);
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    function test_live_rotation_rederivesSetFromRegistryStorage() public view {
        (,, bytes memory na, bytes memory naId,) =
            verifier.verifyBundle(_bundle(_liveStep(h2, true)), _anchor(setHash, regRoot, h1.height), _ctx());
        assertEq(na, _anchor(setHash, regRoot, h2.height + 1));
        assertEq(naId, na);
    }

    function test_live_hopThenBundle() public view {
        bytes[] memory hops = new bytes[](1);
        hops[0] = _liveStep(h1, true);
        (,, bytes memory na,,) =
            verifier.verifyBundle(_bundle(_liveStep(h2, false), hops, h2), _anchor(setHash, regRoot, h1.height), _ctx());
        assertEq(na, _anchor(setHash, regRoot, h1.height + 1));
    }

    function test_live_deriveSetHash_matchesActiveSet() public view {
        assertEq(stub.deriveSetHash(h2.registrySetProof, regRoot), setHash);
    }

    function test_live_rejects_flippedSignatureByte() public {
        bytes[] memory sigs = h2.sigs;
        bytes memory s0 = bytes.concat(sigs[0]);
        s0[7] ^= 0x01;
        sigs[0] = s0;
        bytes memory step = _step(
            h2.header,
            h2.parentHeader,
            h2.round,
            _sigList(h2.sigIndices, sigs),
            _valList(pubkeys, powers),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.InvalidSignature.selector);
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_live_rejects_certificateReplayedOnOtherHeader() public {
        bytes memory step = _step(
            h2.header,
            h2.parentHeader,
            h1.round,
            _sigList(h1.sigIndices, h1.sigs),
            _valList(pubkeys, powers),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.InvalidSignature.selector);
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_live_rejects_wrongRound() public {
        bytes memory step = _step(
            h2.header,
            h2.parentHeader,
            h2.round + 1,
            _sigList(h2.sigIndices, h2.sigs),
            _valList(pubkeys, powers),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.InvalidSignature.selector);
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Light client rules (real header + proofs, stubbed Ed25519)
    // ═════════════════════════════════════════════════════════════════════════

    function test_threshold_strictlyAboveTwoThirds() public view {
        // powers 40/30/20/10: {40,30} = 70 > 66.67 passes.
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 1));
        (bytes memory na,) = stub.step(step, _anchor(sh, regRoot, h1.height));
        assertEq(na, _anchor(sh, regRoot, h1.height)); // registry unchanged → same anchor
    }

    function test_threshold_rejects_below() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 2)); // 60
        vm.expectRevert(ArcMalachiteVerifier.QuorumNotMet.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function test_threshold_rejects_exactlyTwoThirds() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(2, 1), _singleton(0)); // 2 of 3: not > 2/3
        vm.expectRevert(ArcMalachiteVerifier.QuorumNotMet.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function _singleton(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function test_rejects_duplicateSigner() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 0));
        vm.expectRevert(ArcMalachiteVerifier.SignerIndexNotIncreasing.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function test_rejects_signerIndexOutOfRange() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 1));
        // Same set, but claim index 4.
        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = keccak256(abi.encode("arc-synthetic-validator", i));
        }
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = new bytes(64);
        step = _step(
            h2.header,
            h2.parentHeader,
            h2.round,
            _sigList(_singleton(4), sigs),
            _valList(keys, _u(40, 30, 20, 10)),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.SignerIndexOutOfRange.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function test_rejects_wrongValidatorSet() public {
        (bytes memory step,) = _synthetic(_u(40, 30, 20, 10), _u(0, 1));
        vm.expectRevert(ArcMalachiteVerifier.ValidatorSetHashMismatch.selector);
        stub.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_rejects_staleHeight() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 1));
        vm.expectRevert(ArcMalachiteVerifier.HeightTooOld.selector);
        stub.step(step, _anchor(sh, regRoot, h2.height + 1));
    }

    function test_rejects_tamperedHeader() public {
        bytes memory hdr = bytes.concat(h2.header);
        hdr[hdr.length - 1] ^= 0x01; // block hash changes → signatures were for another hash
        (, bytes32 sh) = _synthetic(_u(40, 30, 20, 10), _u(0, 1));
        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = keccak256(abi.encode("arc-synthetic-validator", i));
        }
        bytes[] memory sigs = new bytes[](2);
        for (uint256 i; i < 2; ++i) {
            sigs[i] = _stubSig(
                keys[i],
                verifier.precommitSignBytes(
                    h2.height, h2.round, h2.blockHash, bytes20(keccak256(abi.encodePacked(keys[i])))
                )
            );
        }
        bytes memory step = _step(
            hdr,
            h2.parentHeader,
            h2.round,
            _sigList(_u(0, 1), sigs),
            _valList(keys, _u(40, 30, 20, 10)),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.InvalidSignature.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function test_rejects_zeroPowerValidator() public {
        (bytes memory step, bytes32 sh) = _synthetic(_u(40, 0), _singleton(0));
        vm.expectRevert(ArcMalachiteVerifier.InvalidValidator.selector);
        stub.step(step, _anchor(sh, regRoot, h1.height));
    }

    function test_rejects_badAnchorLength() public {
        vm.expectRevert(ArcMalachiteVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(_bundle(_liveStep(h2, false)), abi.encodePacked(setHash, regRoot), _ctx());
    }

    // ── Registry tracking ─────────────────────────────────────────────────────

    function test_rejects_registryRootMismatch() public {
        // The anchor's registry root is not the registry at stateRoot(H-1): set not pinned.
        vm.expectRevert(ArcMalachiteVerifier.RegistryRootMismatch.selector);
        real.step(_liveStep(h2, false), _anchor(setHash, BOGUS_ROOT, h1.height));
    }

    function test_rejects_wrongParentHeader() public {
        bytes memory step = _step(
            h2.header,
            h1.parentHeader,
            h2.round,
            _sigList(h2.sigIndices, h2.sigs),
            _valList(pubkeys, powers),
            h2.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert(ArcMalachiteVerifier.ParentHeaderMismatch.selector);
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_rejects_parentRegistryProofFromOtherBlock() public {
        bytes memory step = _step(
            h2.header,
            h2.parentHeader,
            h2.round,
            _sigList(h2.sigIndices, h2.sigs),
            _valList(pubkeys, powers),
            h1.parentRegistryAccountProof,
            _emptyList()
        );
        vm.expectRevert();
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_rejects_malformedRotation() public {
        bytes[] memory r = new bytes[](1);
        r[0] = h2.registryAccountProof;
        bytes memory step = _step(
            h2.header,
            h2.parentHeader,
            h2.round,
            _sigList(h2.sigIndices, h2.sigs),
            _valList(pubkeys, powers),
            h2.parentRegistryAccountProof,
            _list(r)
        );
        vm.expectRevert(ArcMalachiteVerifier.InvalidPayloadShape.selector);
        real.step(step, _anchor(setHash, regRoot, h1.height));
    }

    function test_rejects_multiproofTrailingPathByte() public {
        (bytes memory nodes, bytes memory paths) = _splitMultiProof(h2.registrySetProof);
        bytes memory mp = _joinMultiProof(nodes, bytes.concat(paths, hex"00"));
        vm.expectRevert(MptMultiProof.MultiProofTrailingPath.selector);
        stub.deriveSetHash(mp, regRoot);
    }

    function test_rejects_multiproofWrongRoot() public {
        vm.expectRevert(MptMultiProof.MultiProofHashMismatch.selector);
        stub.deriveSetHash(h2.registrySetProof, BOGUS_ROOT);
    }

    function test_rejects_multiproofSwappedPath() public {
        (bytes memory nodes, bytes memory paths) = _splitMultiProof(h2.registrySetProof);
        // Point the first lookup's leaf at another node: its hash cannot match the parent.
        bytes memory p = bytes.concat(paths);
        uint256 count = uint8(p[0]);
        uint256 at = 1 + 2 * (count - 1);
        p[at + 1] = bytes1(uint8(p[at + 1]) ^ 0x01);
        vm.expectRevert(MptMultiProof.MultiProofHashMismatch.selector);
        stub.deriveSetHash(_joinMultiProof(nodes, p), regRoot);
    }

    function _splitMultiProof(bytes memory mp) internal pure returns (bytes memory nodesRlp, bytes memory paths) {
        (nodesRlp, paths) = MultiProofSplitter.split(mp);
    }

    function _joinMultiProof(bytes memory nodesRlp, bytes memory paths) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](2);
        f[0] = nodesRlp;
        f[1] = RLP.encode(paths);
        return RLP.encode(f);
    }

    // ── ClprService storage ───────────────────────────────────────────────────

    function test_rejects_storageProofFromOtherBlock() public {
        vm.expectRevert();
        verifier.verifyBundle(
            _bundle(_liveStep(h2, false), new bytes[](0), h1), _anchor(setHash, regRoot, h1.height), _ctx()
        );
    }

    function test_rejects_storageProofForOtherChannel() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: keccak256("other"), remoteServiceAddress: abi.encodePacked(target)})
        );
        vm.expectRevert();
        verifier.verifyBundle(_bundle(_liveStep(h2, false)), _anchor(setHash, regRoot, h1.height), ctx);
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    /// @dev ClprLedgerConfiguration{1: chain_id, 2: service_address(20)}.
    function _ledgerConfig(string memory chainId, address service) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"0a", uint8(bytes(chainId).length), chainId, hex"1214", service);
    }

    function _config(string memory chainId) internal view returns (bytes memory) {
        bytes[] memory f = new bytes[](5);
        f[0] = _liveStep(h2, false);
        f[1] = _emptyList();
        f[2] = h2.serviceAccountProof;
        f[3] = h2.configSlotProof;
        f[4] = RLP.encode(_ledgerConfig(chainId, target));
        return _list(f);
    }

    /// @dev The light-client and MPT path runs end to end on live data; the stand-in contract holds no
    ///      ClprService config, so the proven slot 25 cannot equal the declared address.
    function test_live_verifyConfig_provesSlot25_standInIsNotAClprService() public {
        vm.expectRevert(ArcMalachiteVerifier.ServiceAddressSlotMismatch.selector);
        verifier.verifyConfig(_config(vm.parseJsonString(json, ".chainId")), channelId, "");
    }

    function test_verifyConfig_rejects_otherChainId() public {
        vm.expectRevert(ArcMalachiteVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(_config("5042003"), channelId, "");
    }

    function test_precommitSignBytes_layout() public view {
        bytes memory b = verifier.precommitSignBytes(
            0x0102030405060708,
            0x0a0b0c0d,
            bytes32(0xabababababababababababababababababababababababababababababababab),
            bytes20(hex"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
        assertEq(
            b,
            hex"010807060504030201250000002a000000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd010d0c0b0a01abababababababababababababababababababababababababababababababab"
        );
    }
}

/// @dev Splits RLP([nodesList, pathsString]) into (raw nodes-list RLP, paths payload).
library MultiProofSplitter {
    function split(bytes memory mp) internal pure returns (bytes memory nodesRlp, bytes memory paths) {
        // Outer list header.
        uint256 off = _hdr(mp, 0);
        uint256 nodesStart = off;
        uint256 nodesEnd = off + _itemLen(mp, off);
        nodesRlp = _sub(mp, nodesStart, nodesEnd - nodesStart);
        paths = RLP.decodeBytes(_sub(mp, nodesEnd, mp.length - nodesEnd));
    }

    function _hdr(bytes memory b, uint256 at) private pure returns (uint256) {
        uint8 p = uint8(b[at]);
        if (p <= 0xf7) return at + 1;
        return at + 1 + (p - 0xf7);
    }

    function _itemLen(bytes memory b, uint256 at) private pure returns (uint256) {
        uint8 p = uint8(b[at]);
        if (p < 0x80) return 1;
        if (p <= 0xb7) return 1 + (p - 0x80);
        if (p <= 0xbf) return 1 + (p - 0xb7) + _be(b, at + 1, p - 0xb7);
        if (p <= 0xf7) return 1 + (p - 0xc0);
        return 1 + (p - 0xf7) + _be(b, at + 1, p - 0xf7);
    }

    function _be(bytes memory b, uint256 at, uint256 n) private pure returns (uint256 v) {
        for (uint256 i; i < n; ++i) {
            v = (v << 8) | uint8(b[at + i]);
        }
    }

    function _sub(bytes memory b, uint256 at, uint256 n) private pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) {
            r[i] = b[at + i];
        }
    }
}
