// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CosmosModuleVerifier} from "@hiero-ledger/clpr/verifiers/evm/dydx/CosmosModuleVerifier.sol";
import {CosmWasmVerifier} from "@hiero-ledger/clpr/verifiers/evm/provenance/CosmWasmVerifier.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CosmWasmSyntheticChain} from "@test/helpers/CosmWasmSyntheticChain.sol";

/// @notice CosmosModuleVerifier (native x/clpr store layout) on a synthetic CometBFT chain with
///         real secp256k1eth signatures and a real two-leaf IAVL-shaped `clpr` store. Golden
///         vectors are bytes the Go module (modules/x-clpr) wrote on its localnet; the live
///         Ed25519 path is covered by test/e2e/tests/verifiers/dydx-xclpr.spec.ts.
contract CosmosModuleVerifierTest is CosmWasmSyntheticChain {
    /// sha256("clpr")[:20]: Cosmos SDK authtypes.NewModuleAddress("clpr").
    bytes internal constant MODULE = hex"a88f550db4433c59b3322bca3a2c233cfdd69adc";

    // Golden vectors from modules/x-clpr localnet (test/e2e/fixtures/dydx-xclpr/localnet.json).
    bytes32 internal constant G_CHANNEL = 0x5296cb261aa9315e0fe0609334f2ed8fe13801ccd28bf5f84d7c0e79c678e741;
    bytes internal constant G_RECORD =
        hex"01010000000000000004000000000000000000000000000000010ea980c0d59c37f6ed426b37327537f65f874ff41ae666f2d49bfb515bb8700c0000000000000000000000000000000000000000000000000000000000000000";
    bytes internal constant G_MSG1_VALUE =
        hex"0a5d0a5b0a20c08c6acfff81cafe379f88061e6b71bfbf2e9b5c5fcba037f0ac69a6b896d41b1214000000000000000000000000000000000000abcd1a14e8721a574e9db5232daded88c68f9ebeef69efb3220b68656c6c6f20686965726f1220bc785cf7f4ee9d04f222e56a84d56ef462ef8ef5c2d39b45851a42a8159d93a4";
    bytes32 internal constant G_MSG1_HASH = 0xbc785cf7f4ee9d04f222e56a84d56ef462ef8ef5c2d39b45851a42a8159d93a4;
    bytes internal constant G_SENDER = hex"e8721a574e9db5232daded88c68f9ebeef69efb3";

    CometBftCommitAccumulator internal acc;
    CosmosModuleVerifier internal verifier;
    Val[] internal setA;
    Val[] internal setB;
    bytes32 internal hashA;
    bytes32 internal hashB;

    function _storeName() internal pure override returns (bytes memory) {
        return bytes("clpr");
    }

    function setUp() public {
        setA.push(_secpVal("a0", 40));
        setA.push(_secpVal("a1", 30));
        setA.push(_secpVal("a2", 20));
        setA.push(_secpVal("a3", 10));
        setB.push(_secpVal("b0", 50));
        setB.push(_secpVal("b1", 50));
        hashA = _setHash(setA);
        hashB = _setHash(setB);
        acc = new CometBftCommitAccumulator(CHAIN, CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        verifier = new CosmosModuleVerifier(
            CosmWasmVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("clpr"),
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
    }

    // ── module layout (modules/x-clpr/x/clpr/types/keys.go) ───────────────────

    function _mQueueKey(bytes32 ch) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x01), ch);
    }

    function _mMsgKey(bytes32 ch, uint64 id) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x02), ch, id);
    }

    function _mServiceKey() internal pure returns (bytes memory) {
        return hex"03";
    }

    function _mCtx(bytes32 ch) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(ClprTypes.ChannelContext({channelId: ch, remoteServiceAddress: MODULE}));
    }

    function _mManifest(uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = MODULE;
        m.endpoints = new ClprTypes.Endpoint[](0);
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    /// @dev Queue record (left) and service item (right) of channel `ch`.
    function _mState(bytes32 ch, bytes memory record, bytes32 commitment) internal pure returns (Tree memory) {
        return _tree(_mQueueKey(ch), record, _mServiceKey(), abi.encodePacked(MODULE, commitment));
    }

    function _proof(Tree memory t, bytes memory entry, Val[] memory vals, bytes32 next, uint256[] memory signers)
        internal
        pure
        returns (bytes memory)
    {
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, vals, next, signers);
        P memory p;
        p.headerRef = _inlineRef(vals, sh);
        p.multistore = ms;
        p.entry = entry;
        p.content = true;
        return _encode(p);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Layout and golden vectors
    // ═════════════════════════════════════════════════════════════════════════

    function test_layout_messageKeyMatchesGoModule() public view {
        assertEq(
            verifier.messageKey(G_CHANNEL, 1),
            hex"025296cb261aa9315e0fe0609334f2ed8fe13801ccd28bf5f84d7c0e79c678e7410000000000000001"
        );
        assertEq(_mQueueKey(G_CHANNEL), hex"015296cb261aa9315e0fe0609334f2ed8fe13801ccd28bf5f84d7c0e79c678e741");
        assertEq(MODULE, abi.encodePacked(bytes20(sha256("clpr"))));
    }

    /// @dev The payload the Go module serialized equals the Solidity ClprProtobuf encoding, and its
    ///      stored running hash is BundleLib's sha256(0 ‖ sha256(payload)).
    function test_golden_payloadEncodingAndRunningHash() public pure {
        bytes memory expected = ClprProtobuf.encodeDataMessage(
            sha256("connector"), hex"000000000000000000000000000000000000abcd", G_SENDER, bytes("hello hiero")
        );
        (bytes memory payload,) = PB.decodeLengthDelimited(G_MSG1_VALUE, 1);
        assertEq(payload, expected);
        assertEq(sha256(abi.encodePacked(bytes32(0), sha256(payload))), G_MSG1_HASH);
    }

    function test_golden_recordFromGoModuleDecodes() public view {
        Tree memory t = _mState(G_CHANNEL, G_RECORD, bytes32(0));
        (ClprTypes.QueueMetadata memory m,,,,) = verifier.verifyBundle(
            _proof(t, t.entryL, setA, hashA, _idx(0, 1)), _anchor(hashA, ANCHOR_HEIGHT), _mCtx(G_CHANNEL)
        );
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 4);
        assertEq(m.receivedMessageId, 0);
        assertEq(m.endpointManifestVersion, 1);
        assertEq(m.sentRunningHash, 0x0ea980c0d59c37f6ed426b37327537f65f874ff41ae666f2d49bfb515bb8700c);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Happy paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_bundle_absentRecord_readsZero() public view {
        Tree memory t = _tree(hex"00", hex"01", _mServiceKey(), abi.encodePacked(MODULE, bytes32(0)));
        (ClprTypes.QueueMetadata memory m,,,,) = verifier.verifyBundle(
            _proof(t, _absent(t, _mQueueKey(CHANNEL)), setA, hashA, _idx(0, 1)),
            _anchor(hashA, ANCHOR_HEIGHT),
            _mCtx(CHANNEL)
        );
        assertEq(m.nextMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
    }

    function test_bundle_rotationAndManifest() public view {
        bytes memory man = _mManifest(2);
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), keccak256(man));
        (bytes memory sh, bytes memory ms,) = _signed(t, 150, setA, hashB, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.serviceEntry = t.entryR;
        p.preimage = man;
        p.content = true;
        (,, bytes memory na,, ClprTypes.ClprEndpointManifest memory em) =
            verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
        assertEq(na, _anchor(hashB, 151));
        assertEq(em.version, 2);
        assertEq(em.serviceAddress, MODULE);
    }

    function test_verifyQueueMessage_existence() public view {
        Tree memory t =
            _tree(_mMsgKey(G_CHANNEL, 1), G_MSG1_VALUE, _mServiceKey(), abi.encodePacked(MODULE, bytes32(0)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        (bytes memory payload, bytes32 rh, uint64 h) =
            verifier.verifyQueueMessage(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), G_CHANNEL, 1);
        assertEq(rh, G_MSG1_HASH);
        assertEq(sha256(abi.encodePacked(bytes32(0), sha256(payload))), G_MSG1_HASH);
        assertEq(h, 120);
    }

    function test_verifyModuleEntry_absence() public view {
        Tree memory t = _tree(_mMsgKey(CHANNEL, 1), G_MSG1_VALUE, _mServiceKey(), abi.encodePacked(MODULE, bytes32(0)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = _absent(t, _mMsgKey(CHANNEL, 2));
        (bool ok, bytes memory v,) =
            verifier.verifyModuleEntry(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _mMsgKey(CHANNEL, 2));
        assertFalse(ok);
        assertEq(v.length, 0);
    }

    function test_verifyConfig_bindsModuleAddressAndManifest() public view {
        bytes memory man = _mManifest(1);
        Tree memory t = _mState(CHANNEL, _record(0, 0, 0, 0), keccak256(man));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryR;
        p.ledgerConfig = PB.encodeBytesField(2, MODULE);
        (bytes memory ctx,, bytes memory service,,, bytes memory anchor,, ClprTypes.ClprEndpointManifest memory m) =
            verifier.verifyConfig(_encode(p), CHANNEL, man);
        assertEq(ctx, _mCtx(CHANNEL));
        assertEq(service, MODULE);
        assertEq(anchor, _anchor(hashA, 121));
        assertEq(m.version, 1);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Negative cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_reverts_belowThreshold() public {
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), bytes32(0));
        bytes memory proof = _proof(t, t.entryL, setA, hashA, _idx(0, 2)); // 60/100
        vm.expectRevert(CometBftLightClient.QuorumNotMet.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
    }

    function test_reverts_badSignature() public {
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), bytes32(0));
        (,, Block memory b) = _signed(t, 120, setA, hashA, _idx(0, 1));
        bytes[] memory o = new bytes[](2);
        o[1] = _sign(setA[2], _signBytes(b, b.header.timeSeconds + 1));
        (bytes memory ms,) = _multistore(t.root);
        P memory p;
        p.headerRef = _inlineRef(setA, _signedHeader(b, setA, _idx(0, 1), o));
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CometBftLightClient.InvalidSignature.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
    }

    function test_reverts_wrongSetAndStale() public {
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), bytes32(0));
        bytes memory byB = _proof(t, t.entryL, setB, hashB, _idx(0, 1));
        vm.expectRevert(CometBftLightClient.ValidatorSetHashMismatch.selector);
        verifier.verifyBundle(byB, _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
        bytes memory byA = _proof(t, t.entryL, setA, hashA, _idx(0, 1));
        vm.expectRevert(CometBftLightClient.HeightTooOld.selector);
        verifier.verifyBundle(byA, _anchor(hashA, 121), _mCtx(CHANNEL));
    }

    /// @dev The CosmWasm layout (0x03 ‖ contract ‖ "clpr_queue" …) is not accepted as a module record.
    function test_reverts_cosmWasmKeyLayout() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0)); // wasm-style keys, in store "clpr"
        bytes memory proof = _proof(t, t.entryL, setA, hashA, _idx(0, 1));
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
    }

    function test_reverts_anotherChannelAndAddressLength() public {
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), bytes32(0));
        bytes memory proof = _proof(t, t.entryL, setA, hashA, _idx(0, 1));
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _mCtx(keccak256("channel-2")));
        bytes memory ctx32 = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: new bytes(32)})
        );
        vm.expectRevert(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), ctx32);
    }

    function test_reverts_serviceItemOfAnotherAddress() public {
        Tree memory t =
            _tree(_mQueueKey(CHANNEL), _record(0, 0, 0, 0), _mServiceKey(), abi.encodePacked(SERVICE, bytes32(0)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryR;
        p.ledgerConfig = PB.encodeBytesField(2, MODULE);
        vm.expectRevert(CosmWasmVerifier.InvalidServiceEntry.selector);
        verifier.verifyConfig(_encode(p), CHANNEL, "");
    }

    function test_reverts_queueMessageAbsentOrMalformed() public {
        Tree memory t = _tree(_mMsgKey(CHANNEL, 1), hex"0a0101", _mServiceKey(), abi.encodePacked(MODULE, bytes32(0)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL; // value lacks the running hash
        bytes memory bad = _encode(p);
        vm.expectRevert(CosmosModuleVerifier.InvalidMessageValue.selector);
        verifier.verifyQueueMessage(bad, _anchor(hashA, ANCHOR_HEIGHT), CHANNEL, 1);
        p.entry = _absent(t, _mMsgKey(CHANNEL, 2));
        bytes memory absent = _encode(p);
        vm.expectRevert(CosmWasmVerifier.EntryNotFound.selector);
        verifier.verifyQueueMessage(absent, _anchor(hashA, ANCHOR_HEIGHT), CHANNEL, 2);
        // A proof for message 1 does not answer for message 2.
        p.entry = t.entryL;
        bytes memory wrongId = _encode(p);
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyQueueMessage(wrongId, _anchor(hashA, ANCHOR_HEIGHT), CHANNEL, 2);
    }

    function test_reverts_wrongStoreKey() public {
        CosmosModuleVerifier wasmVerifier = new CosmosModuleVerifier(
            CosmWasmVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("wasm"),
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
        Tree memory t = _mState(CHANNEL, _record(1, 3, 7, 2), bytes32(0));
        bytes memory proof = _proof(t, t.entryL, setA, hashA, _idx(0, 1));
        vm.expectRevert(CosmWasmVerifier.InvalidStoreKey.selector);
        wasmVerifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _mCtx(CHANNEL));
    }
}
