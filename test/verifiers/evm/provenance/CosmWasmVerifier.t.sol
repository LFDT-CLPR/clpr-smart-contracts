// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CosmWasmVerifier} from "@hiero-ledger/clpr/verifiers/evm/provenance/CosmWasmVerifier.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CosmWasmSyntheticChain} from "@test/helpers/CosmWasmSyntheticChain.sol";

/// @notice CosmWasmVerifier + CometBftCommitAccumulator on a synthetic CometBFT chain with real
///         secp256k1eth signatures (`vm.sign`). The wasm store is a real two-leaf IAVL-shaped tree,
///         so existence and non-existence proofs run the production ICS-23 code. Ed25519 and the
///         real Provenance store layout are covered by the live fixture
///         (test/e2e/tests/verifiers/provenance-live.spec.ts).
contract CosmWasmVerifierTest is CosmWasmSyntheticChain {
    CometBftCommitAccumulator internal acc;
    CosmWasmVerifier internal verifier;

    Val[] internal setA; // powers 40/30/20/10 → validators 0+1 clear 2/3
    Val[] internal setB;
    bytes32 internal hashA;
    bytes32 internal hashB;

    function setUp() public {
        setA.push(_secpVal("a0", 40));
        setA.push(_secpVal("a1", 30));
        setA.push(_secpVal("a2", 20));
        setA.push(_secpVal("a3", 10));
        setB.push(_secpVal("b0", 50));
        setB.push(_secpVal("b1", 25));
        setB.push(_secpVal("b2", 25));
        hashA = _setHash(setA);
        hashB = _setHash(setB);
        acc = new CometBftCommitAccumulator(CHAIN, CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        verifier = new CosmWasmVerifier(
            CosmWasmVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("wasm"),
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory na, ClprTypes.ClprEndpointManifest memory man)
    {
        bytes[] memory payloads;
        (m, payloads, na,, man) = verifier.verifyBundle(proof, anchor, _ctx());
        assertEq(payloads.length, 1);
        assertEq(payloads[0], PAYLOAD);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Happy paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_bundle_existingQueueRecord_decodes() public view {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (ClprTypes.QueueMetadata memory m, bytes memory na, ClprTypes.ClprEndpointManifest memory man) =
            _verify(_bundle(t, 120, setA, hashA, t.entryL), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 7);
        assertEq(m.endpointManifestVersion, 2);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("received"));
        assertEq(na.length, 0, "no rotation");
        assertEq(man.version, 0, "no manifest update");
    }

    function test_bundle_absentQueueRecord_readsZero() public view {
        // CHANNEL's record is absent: its key sorts between the two leaves.
        Tree memory t =
            _tree(_queueKey(SERVICE, bytes32(0)), hex"01", _serviceKey(SERVICE), abi.encodePacked(SERVICE, bytes32(0)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = _absent(t, _queueKey(SERVICE, CHANNEL));
        p.content = true;
        (ClprTypes.QueueMetadata memory m,,) = _verify(_encode(p), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(m.nextMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
    }

    function test_bundle_rotationReturnsNewAnchor_thenNextSetSigns() public view {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (, bytes memory na,) = _verify(_bundle(t, 150, setA, hashB, t.entryL), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(na, _anchor(hashB, 151));
        (, bytes memory na2,) = _verify(_bundle(t, 160, setB, hashB, t.entryL), na);
        assertEq(na2.length, 0);
    }

    function test_bundle_inlineHopAcrossRotation() public view {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory hopSh,,) = _signed(t, 130, setA, hashB, _idx(0, 1));
        (bytes memory sh, bytes memory ms,) = _signed(t, 200, setB, hashB, _idx(0, 1));
        P memory p;
        p.hops = new bytes[](1);
        p.hops[0] = _inlineRef(setA, hopSh);
        p.headerRef = _inlineRef(setB, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        (, bytes memory na,) = _verify(_encode(p), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(na, _anchor(hashB, 201));
    }

    /// @dev The split: the commit is accumulated over two transactions (one signature each), then
    ///      the bundle references the header by hash and carries only the state proof.
    function test_split_accumulateInTwoTxs_thenBundleByHash() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh0, bytes memory ms, Block memory b) = _signed(t, 120, setA, hashA, _idx(0));
        (bytes memory sh1,,) = _signed(t, 120, setA, hashA, _idx(1));
        bytes32 hh = CometBftLib.headerHash(b.header);

        (bytes32 h0, bool f0) = acc.accumulate(_encodeSet(setA), sh0);
        assertEq(h0, hh);
        assertFalse(f0, "40/100 is not final");
        vm.expectRevert(CometBftCommitAccumulator.NotFinalized.selector);
        acc.finalizedHeader(hh);

        (, bool f1) = acc.accumulate(_encodeSet(setA), sh1);
        assertTrue(f1, "70/100 is final");
        assertTrue(acc.isCounted(hh, 0) && acc.isCounted(hh, 1) && !acc.isCounted(hh, 2));

        P memory p;
        p.headerRef = _hashRef(hh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        (ClprTypes.QueueMetadata memory m,,) = _verify(_encode(p), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(m.nextMessageId, 3);
    }

    function test_split_accumulatedHopThenInlineHeader() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory hopSh,, Block memory hb) = _signed(t, 130, setA, hashB, _idx(0, 1));
        acc.accumulate(_encodeSet(setA), hopSh);
        (bytes memory sh, bytes memory ms,) = _signed(t, 200, setB, hashB, _idx(0, 1));
        P memory p;
        p.hops = new bytes[](1);
        p.hops[0] = _hashRef(CometBftLib.headerHash(hb.header));
        p.headerRef = _inlineRef(setB, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        (, bytes memory na,) = _verify(_encode(p), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(na, _anchor(hashB, 201));
    }

    function test_accumulate_signerAlreadyCountedIsSkipped() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh0,, Block memory b) = _signed(t, 120, setA, hashA, _idx(0));
        (bytes memory sh012,,) = _signed(t, 120, setA, hashA, _idx(0, 1, 2));
        acc.accumulate(_encodeSet(setA), sh0);
        acc.accumulate(_encodeSet(setA), sh012);
        (,,, uint64 height, uint64 signed, uint64 total) = _rec(CometBftLib.headerHash(b.header));
        assertEq(height, 120);
        assertEq(signed, 90);
        assertEq(total, 100);
    }

    function _rec(bytes32 hh) internal view returns (bytes32, bytes32, bytes32, uint64, uint64, uint64) {
        (bytes32 v, bytes32 n, bytes32 a,, uint64 h, uint64 s, uint64 tot) = acc.records(hh);
        return (v, n, a, h, s, tot);
    }

    function test_bundle_manifestUpdate() public view {
        bytes memory man = _manifest(3);
        Tree memory t = _state(_record(1, 3, 7, 3), keccak256(man));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.serviceEntry = t.entryR;
        p.preimage = man;
        p.content = true;
        (,, ClprTypes.ClprEndpointManifest memory m) = _verify(_encode(p), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(m.version, 3);
        assertEq(m.serviceAddress, SERVICE);
    }

    function _ledgerConfig(bytes memory service) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes("pio-mainnet-1")),
            PB.encodeBytesField(2, service),
            PB.encodeVarintField(3, uint64(1_700_000_000_000_000_000)),
            PB.encodeBytesField(
                4, abi.encodePacked(PB.encodeVarintField(1, uint64(10)), PB.encodeVarintField(5, uint64(20_000)))
            )
        );
    }

    function _config(Tree memory t, bytes memory ledgerConfig) internal view returns (bytes memory) {
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashB, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryR;
        p.ledgerConfig = ledgerConfig;
        return _encode(p);
    }

    function test_verifyConfig_fromBootstrap_bindsServiceAndManifest() public view {
        bytes memory man = _manifest(1);
        Tree memory t = _state(_record(0, 0, 0, 0), keccak256(man));
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory service,
            uint96 nanos,
            ClprTypes.Throttles memory th,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory m
        ) = verifier.verifyConfig(_config(t, _ledgerConfig(SERVICE)), CHANNEL, man);
        assertEq(ctx, _ctx());
        assertEq(chainId, CHAIN);
        assertEq(service, SERVICE);
        assertEq(nanos, 1_700_000_000_000_000_000);
        assertEq(th.maxMessagesPerBundle, 10);
        assertEq(th.maxSyncBytes, 20_000);
        assertEq(anchor, _anchor(hashB, 121));
        assertEq(anchorId, anchor);
        assertEq(m.version, 1);
    }

    function test_verifyConfig_noManifest_uninitialized() public view {
        Tree memory t = _state(_record(0, 0, 0, 0), bytes32(0));
        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) =
            verifier.verifyConfig(_config(t, _ledgerConfig(SERVICE)), CHANNEL, "");
        assertEq(m.version, 0);
        assertEq(m.serviceAddress, SERVICE);
    }

    function test_verifyContractEntry_existenceAndAbsence() public view {
        bytes memory c = hex"1111111111111111111111111111111111111111";
        bytes memory k1 = abi.encodePacked(uint8(0x03), c, "contract_info");
        bytes memory k2 = abi.encodePacked(uint8(0x03), c, "zz");
        Tree memory t = _tree(k1, bytes('{"contract":"x","version":"1"}'), k2, hex"01");
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        (bool ok, bytes memory v, uint64 h) =
            verifier.verifyContractEntry(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), c, bytes("contract_info"));
        assertTrue(ok);
        assertEq(v, bytes('{"contract":"x","version":"1"}'));
        assertEq(h, 120);

        p.entry = _absent(t, abi.encodePacked(uint8(0x03), c, "owner"));
        (ok, v,) = verifier.verifyContractEntry(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), c, bytes("owner"));
        assertFalse(ok);
        assertEq(v.length, 0);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Negative cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_reverts_badSignature() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (,, Block memory b) = _signed(t, 120, setA, hashA, _idx(0, 1));
        bytes[] memory o = new bytes[](2);
        o[1] = _sign(setA[2], _signBytes(b, b.header.timeSeconds + 1)); // validator 2's key in slot 1
        bytes memory sh = _signedHeader(b, setA, _idx(0, 1), o);
        (bytes memory ms,) = _multistore(t.root);
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CometBftLightClient.InvalidSignature.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());

        vm.expectRevert(CometBftLightClient.InvalidSignature.selector);
        acc.accumulate(_encodeSet(setA), sh);
    }

    function test_reverts_belowThreshold() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 2)); // 60/100
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CometBftLightClient.QuorumNotMet.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_wrongValidatorSet() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory proof = _bundle(t, 120, setB, hashB, t.entryL); // signed by B, anchor trusts A
        vm.expectRevert(CometBftLightClient.ValidatorSetHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_staleHeader_inlineAndAccumulated() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory built0 = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CometBftLightClient.HeightTooOld.selector);
        verifier.verifyBundle(built0, _anchor(hashA, 121), _ctx());

        (bytes memory sh, bytes memory ms, Block memory b) = _signed(t, 120, setA, hashA, _idx(0, 1));
        acc.accumulate(_encodeSet(setA), sh);
        P memory p;
        p.headerRef = _hashRef(CometBftLib.headerHash(b.header));
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CosmWasmVerifier.HeightTooOld.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, 121), _ctx());
    }

    function test_reverts_accumulatedHeaderOfAnotherSet() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh, bytes memory ms, Block memory b) = _signed(t, 120, setB, hashB, _idx(0, 1));
        acc.accumulate(_encodeSet(setB), sh); // finalized by B, but the channel trusts A
        P memory p;
        p.headerRef = _hashRef(CometBftLib.headerHash(b.header));
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CosmWasmVerifier.ValidatorSetHashMismatch.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_accumulatedHeaderNotFinal() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh, bytes memory ms, Block memory b) = _signed(t, 120, setA, hashA, _idx(0));
        acc.accumulate(_encodeSet(setA), sh);
        P memory p;
        p.headerRef = _hashRef(CometBftLib.headerHash(b.header));
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CometBftCommitAccumulator.NotFinalized.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_accumulate_reverts_replayAndMixedRounds() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh0,, Block memory b) = _signed(t, 120, setA, hashA, _idx(0));
        acc.accumulate(_encodeSet(setA), sh0);
        vm.expectRevert(CometBftCommitAccumulator.NoNewSignatures.selector);
        acc.accumulate(_encodeSet(setA), sh0);

        b.round = 1; // a precommit from another round for the same block
        bytes memory shR1 = _signedHeader(b, setA, _idx(1));
        vm.expectRevert(CometBftCommitAccumulator.CommitMismatch.selector);
        acc.accumulate(_encodeSet(setA), shR1);
    }

    function test_accumulate_reverts_wrongChain() public {
        CometBftCommitAccumulator other =
            new CometBftCommitAccumulator("pio-testnet-1", CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh,,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        vm.expectRevert(CometBftLightClient.ChainIdMismatch.selector);
        other.accumulate(_encodeSet(setA), sh);
    }

    function test_reverts_tamperedStorageValue() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        // Same proof, record claims nextMessageId 4: the leaf hash no longer reaches the root.
        bytes memory forged = _encodeExistenceEntryWithPath(t.keyL, _record(1, 4, 7, 2), _pathOf(t.entryL));
        bytes memory built1 = _bundle(t, 120, setA, hashA, forged);
        vm.expectRevert(Ics23Lib.RootMismatch.selector);
        verifier.verifyBundle(built1, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function _pathOf(bytes memory entry) internal pure returns (Ics23Lib.InnerOp[] memory path) {
        bytes memory ep = _innerEp(entry);
        uint256 n;
        uint256 off;
        while (off < ep.length) {
            (uint64 fn_, uint8 wt, uint256 o2) = PB.decodeFieldKey(ep, off);
            if (fn_ == 4) ++n;
            off = PB.skipField(ep, o2, wt);
        }
        path = new Ics23Lib.InnerOp[](n);
        n = 0;
        off = 0;
        while (off < ep.length) {
            (uint64 fn_, uint8 wt, uint256 o2) = PB.decodeFieldKey(ep, off);
            if (fn_ == 4) {
                bytes memory op;
                (op, off) = PB.decodeLengthDelimited(ep, o2);
                path[n++] = _innerOp(op);
            } else {
                off = PB.skipField(ep, o2, wt);
            }
        }
    }

    function _innerOp(bytes memory op) internal pure returns (Ics23Lib.InnerOp memory r) {
        r.hashOp = 1;
        uint256 a;
        while (a < op.length) {
            (uint64 fn_, uint8 wt, uint256 a2) = PB.decodeFieldKey(op, a);
            if (fn_ == 2) (r.prefix, a) = PB.decodeLengthDelimited(op, a2);
            else if (fn_ == 3) (r.suffix, a) = PB.decodeLengthDelimited(op, a2);
            else a = PB.skipField(op, a2, wt);
        }
    }

    function test_reverts_anotherChannelsRecord() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory ctx2 = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: keccak256("channel-2"), remoteServiceAddress: SERVICE})
        );
        bytes memory proof = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), ctx2);
    }

    function test_reverts_serviceEntryAsQueueRecord() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory built2 = _bundle(t, 120, setA, hashA, t.entryR);
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(built2, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_badQueueRecord() public {
        Tree memory t = _state(abi.encodePacked(_record(1, 3, 7, 2), uint8(0)), bytes32(0)); // 91 bytes
        bytes memory built3 = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CosmWasmVerifier.InvalidQueueRecord.selector);
        verifier.verifyBundle(built3, _anchor(hashA, ANCHOR_HEIGHT), _ctx());

        t = _state(_record(9, 3, 7, 2), bytes32(0)); // status out of range
        bytes memory built4 = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CosmWasmVerifier.InvalidQueueRecord.selector);
        verifier.verifyBundle(built4, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_wrongStoreKey() public {
        CosmWasmVerifier bankVerifier = new CosmWasmVerifier(
            CosmWasmVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("bank"),
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory built5 = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CosmWasmVerifier.InvalidStoreKey.selector);
        bankVerifier.verifyBundle(built5, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_manifestPreimageMismatch() public {
        Tree memory t = _state(_record(1, 3, 7, 3), keccak256(_manifest(3)));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(setA, sh);
        p.multistore = ms;
        p.entry = t.entryL;
        p.serviceEntry = t.entryR;
        p.preimage = _manifest(4);
        p.content = true;
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());

        p.preimage = "";
        vm.expectRevert(CosmWasmVerifier.ManifestProofPairMismatch.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    function test_reverts_verifyConfig_serviceMismatch() public {
        Tree memory t = _state(_record(0, 0, 0, 0), bytes32(0));
        bytes memory other = hex"ee184aa5ecc3765b1aa6a6be3b530bfcee73f507adaa8442c4709cc4aa62fed6";
        bytes memory built6 = _config(t, _ledgerConfig(other));
        vm.expectRevert(CosmWasmVerifier.StorageKeyMismatch.selector);
        verifier.verifyConfig(built6, CHANNEL, "");
    }

    function test_reverts_verifyConfig_notFromBootstrap() public {
        Tree memory t = _state(_record(0, 0, 0, 0), bytes32(0));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setB, hashB, _idx(0, 1)); // B is not the bootstrap set
        P memory p;
        p.headerRef = _inlineRef(setB, sh);
        p.multistore = ms;
        p.entry = t.entryR;
        p.ledgerConfig = _ledgerConfig(SERVICE);
        vm.expectRevert(CometBftLightClient.ValidatorSetHashMismatch.selector);
        verifier.verifyConfig(_encode(p), CHANNEL, "");
    }

    function test_reverts_badAnchorAndAddress() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        bytes memory proof = _bundle(t, 120, setA, hashA, t.entryL);
        vm.expectRevert(CosmWasmVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(proof, hex"00", _ctx());
        bytes memory ctx21 = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: new bytes(21)})
        );
        vm.expectRevert(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector);
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), ctx21);
    }

    function test_reverts_headerRefBothForms() public {
        Tree memory t = _state(_record(1, 3, 7, 2), bytes32(0));
        (bytes memory sh, bytes memory ms,) = _signed(t, 120, setA, hashA, _idx(0, 1));
        P memory p;
        p.headerRef = abi.encodePacked(_inlineRef(setA, sh), _hashRef(bytes32(uint256(1))));
        p.multistore = ms;
        p.entry = t.entryL;
        p.content = true;
        vm.expectRevert(CosmWasmVerifier.InvalidHeaderRef.selector);
        verifier.verifyBundle(_encode(p), _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }
}
