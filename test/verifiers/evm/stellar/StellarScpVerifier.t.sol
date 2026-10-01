// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {StellarTestBuilder} from "@test/verifiers/evm/stellar/StellarTestBuilder.sol";
import {StellarScpVerifier} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarScpVerifier.sol";
import {StellarXdr} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarXdr.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @dev StellarScpVerifier over the synthetic fixture: real Ed25519 SCP signatures and real XDR for
///      headers, tx sets, result sets and Soroban success preimages. Live testnet/pubnet data is
///      covered by test/e2e/tests/verifiers/stellar-live.spec.ts.
contract StellarScpVerifierTest is StellarTestBuilder {
    StellarScpVerifier internal v;
    Ed25519Verifier internal ed;
    string internal constant CHAIN = "stellar:testnet";

    function setUp() public {
        _loadFixture();
        ed = new Ed25519Verifier();
        v = new StellarScpVerifier(ed, NETWORK_ID, CHAIN);
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────

    /// Anchor after config: Q1, slot 101, checkpoint = ledger 100.
    function _anchor0() internal view returns (bytes memory) {
        return _anchor(Q1_HASH, 101, 100, _headerHash(100), bytes32(0));
    }

    function _ctx() internal view returns (bytes memory) {
        return _context(CHANNEL, SERVICE);
    }

    /// SCP slot 105 + headers 104..103 + the queue event in 103.
    function _fullBundle() internal view returns (bytes memory) {
        return _bundle(Q1, _scpStd(105), _headers(104, 103), _attItem(_att("queue")), "", "", "");
    }

    function _withAtt(Att memory a) internal view returns (bytes memory) {
        return _bundle(Q1, _scpStd(105), _headers(104, 103), _attItem(a), "", "", "");
    }

    function _withScp(bytes memory scp) internal view returns (bytes memory) {
        return _bundle(Q1, scp, _headers(104, 103), _attItem(_att("queue")), "", "", "");
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory newAnchor)
    {
        (m,, newAnchor,,) = v.verifyBundle(proof, anchor, _ctx());
    }

    function _assertMeta(ClprTypes.QueueMetadata memory got, ClprTypes.QueueMetadata memory want) internal pure {
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(want)), "metadata");
    }

    // ── Happy paths ──────────────────────────────────────────────────────────

    function test_singleBundle_provesQueueEvent() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory a) = _verify(_fullBundle(), _anchor0());
        _assertMeta(m, _fixtureMeta());
        assertEq(a, _anchor(Q1_HASH, 105, 104, _headerHash(104), keccak256(abi.encode(m))));
    }

    function test_singleBundle_gas() public view {
        bytes memory proof = _fullBundle();
        bytes memory anchor = _anchor0();
        uint256 g = gasleft();
        v.verifyBundle(proof, anchor, _ctx());
        g -= gasleft();
        console.log("4-signature bundle gas:", g, "proof bytes:", proof.length);
        assertLt(g, 4_000_000);
    }

    /// Marginal cost of one more EXTERNALIZE signature (Ed25519 in Solidity over a ~280-byte message).
    function test_gas_perSignature() public view {
        bytes memory four = _bundle(Q1, _scpStd(105), _emptyList(), _emptyList(), "", "", "");
        bytes memory seven = _bundle(Q1, _scp(_envs("105"), _txSet(105), ""), _emptyList(), _emptyList(), "", "", "");
        (bytes memory anchor, bytes memory ctx) = (_anchor0(), _ctx());
        uint256 g4 = gasleft();
        v.verifyBundle(four, anchor, ctx);
        g4 -= gasleft();
        uint256 g7 = gasleft();
        v.verifyBundle(seven, anchor, ctx);
        g7 -= gasleft();
        uint256 perSig = (g7 - g4) / 3;
        console.log("checkpoint bundle, 4 signatures:", g4);
        console.log("checkpoint bundle, 7 signatures:", g7);
        console.log("marginal gas per signature:", perSig);
        console.log("signatures in 15M (execution only, no calldata):", (15_000_000 - (g4 - 4 * perSig)) / perSig);
        assertLt(perSig, 1_000_000);
    }

    function test_moreSignersThanNeeded_ok() public view {
        bytes memory scp = _scp(_envs("105"), _txSet(105), "");
        (ClprTypes.QueueMetadata memory m,) = _verify(_withScp(scp), _anchor0());
        _assertMeta(m, _fixtureMeta());
    }

    function test_twoStep_checkpointThenAttestation() public view {
        // Step 1: SCP only. Before any attestation the verifier returns the empty queue.
        bytes memory step1 = _bundle(Q1, _scpStd(105), _emptyList(), _emptyList(), "", "", "");
        (ClprTypes.QueueMetadata memory m1, bytes memory a1) = _verify(step1, _anchor0());
        assertEq(m1.nextMessageId, 1);
        assertEq(m1.receivedMessageId, 0);
        assertEq(uint8(m1.state), uint8(ClprTypes.ChannelStatus.PENDING));
        assertEq(a1, _anchor(Q1_HASH, 105, 104, _headerHash(104), bytes32(0)));

        // Step 2: headers back from the checkpoint and the event, no signatures.
        bytes memory step2 = _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", "", "");
        (ClprTypes.QueueMetadata memory m2, bytes memory a2) = _verify(step2, a1);
        _assertMeta(m2, _fixtureMeta());
        assertEq(a2, _anchor(Q1_HASH, 105, 104, _headerHash(104), keccak256(abi.encode(m2))));
    }

    function test_checkpointOnly_replaysLastProvenMetadata() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory a) = _verify(_fullBundle(), _anchor0());
        bytes memory step1 = _bundle(Q1, _scpStd(112), _emptyList(), _emptyList(), abi.encode(m), "", "");
        (ClprTypes.QueueMetadata memory again, bytes memory a2) = _verify(step1, a);
        _assertMeta(again, m);
        assertEq(a2, _anchor(Q1_HASH, 112, 111, _headerHash(111), keccak256(abi.encode(m))));
    }

    function test_laterAttestation_afterEarlierOne() public view {
        (, bytes memory a) = _verify(_fullBundle(), _anchor0());
        bytes memory later = _bundle(Q1, _scpStd(112), _headers(111, 110), _attItem(_att("queueLater")), "", "", "");
        (ClprTypes.QueueMetadata memory m, bytes memory a2) = _verify(later, a);
        _assertMeta(m, _fixtureMeta());
        assertEq(a2, _anchor(Q1_HASH, 112, 111, _headerHash(111), keccak256(abi.encode(m))));
    }

    function test_rotation_toDeclaredQuorumSet_thenFinalityUnderNewSet() public {
        bytes memory anchor = _anchor(Q1_HASH, 112, 0, bytes32(0), bytes32(0));
        bytes memory rot = _bundle(
            Q1,
            _scp(_pick("120", _names("A0", "A1", "B0", "B1")), _txSet(120), Q2),
            _emptyList(),
            _emptyList(),
            "",
            "",
            ""
        );
        (, bytes memory a) = _verify(rot, anchor);
        assertEq(a, _anchor(Q2_HASH, 120, 119, _headerHash(119), bytes32(0)));

        // Q2 = 3 of {A, B, C, D}: A, B and D sign slot 122.
        string[] memory n = new string[](6);
        (n[0], n[1], n[2], n[3], n[4], n[5]) = ("A0", "A1", "B0", "B1", "D0", "D1");
        bytes memory next = _bundle(Q2, _scp(_pick("122", n), _txSet(122), ""), _emptyList(), _emptyList(), "", "", "");
        (, bytes memory a2) = _verify(next, a);
        assertEq(a2, _anchor(Q2_HASH, 122, 121, _headerHash(121), bytes32(0)));

        // The old set's quorum set no longer matches the anchor.
        bytes memory old = _bundle(Q1, _scpStd(112), _emptyList(), _emptyList(), "", "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.QuorumSetMismatch.selector), old, a2, _ctx());
    }

    function test_rotation_gas() public view {
        bytes memory anchor = _anchor(Q1_HASH, 112, 0, bytes32(0), bytes32(0));
        bytes memory rot = _bundle(
            Q1,
            _scp(_pick("120", _names("A0", "A1", "B0", "B1")), _txSet(120), Q2),
            _emptyList(),
            _emptyList(),
            "",
            "",
            ""
        );
        uint256 g = gasleft();
        v.verifyBundle(rot, anchor, _ctx());
        g -= gasleft();
        console.log("4-signature rotation gas:", g, "proof bytes:", rot.length);
    }

    function test_verifyConfig_withManifestProof() public view {
        (bytes memory cfg, bytes memory manifestProof) = _config(CHAIN);
        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory manifest
        ) = v.verifyConfig(cfg, CHANNEL, manifestProof);
        assertEq(chainId, CHAIN);
        assertEq(serviceAddress, abi.encodePacked(SERVICE));
        assertEq(channelContext, _ctx());
        assertEq(anchor, _anchor0());
        assertEq(anchorId, abi.encodePacked(uint64(101), bytes32(0)));
        assertEq(manifest.version, 1);
        assertEq(manifest.serviceAddress, abi.encodePacked(SERVICE));
    }

    function test_verifyConfig_wrongChain_reverts() public {
        (bytes memory cfg,) = _config("stellar:pubnet");
        vm.expectRevert(abi.encodeWithSelector(StellarScpVerifier.WrongChain.selector, "stellar:pubnet"));
        v.verifyConfig(cfg, CHANNEL, "");
    }

    function _config(string memory chainId) internal view returns (bytes memory cfg, bytes memory manifestProof) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = 1_790_000_000 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        bytes[] memory items = new bytes[](3);
        items[0] = _str(Q1);
        items[1] = _scpStd(101);
        items[2] = _str(ClprProtobuf.encodeControlMessage(lc));
        cfg = _list(items);
        bytes[] memory mp = new bytes[](3);
        mp[0] = _headers(100, 100);
        mp[1] = _attItem(_att("manifest"));
        mp[2] = _str(vm.parseJsonBytes(fx, ".manifest"));
        manifestProof = _list(mp);
    }

    // ── Signatures and quorum ────────────────────────────────────────────────

    function test_badSignature_reverts() public {
        Env[] memory e = _pick("105", _names("A0", "A1", "B0", "B1"));
        e[2].signature[10] ^= bytes1(0x01);
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.BadSignature.selector, 2),
            _withScp(_scp(e, _txSet(105), "")),
            _anchor0(),
            _ctx()
        );
    }

    function test_tamperedStatement_reverts() public {
        Env[] memory e = _pick("105", _names("A0", "A1", "B0", "B1"));
        e[1].statement[e[1].statement.length - 33] ^= bytes1(0x01); // nH
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.BadSignature.selector, 1),
            _withScp(_scp(e, _txSet(105), "")),
            _anchor0(),
            _ctx()
        );
    }

    function test_wrongNetworkId_reverts() public {
        StellarScpVerifier other = new StellarScpVerifier(ed, keccak256("another network"), CHAIN);
        (bytes memory proof, bytes memory anchor, bytes memory ctx) = (_fullBundle(), _anchor0(), _ctx());
        vm.expectRevert(abi.encodeWithSelector(StellarScpVerifier.BadSignature.selector, 0));
        other.verifyBundle(proof, anchor, ctx);
    }

    function test_belowThreshold_oneOrganization_reverts() public {
        bytes memory scp = _scp(_pick("105", _names("A0", "A1", "A2", "")), _txSet(105), "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.QuorumNotSatisfied.selector), _withScp(scp), _anchor0(), _ctx()
        );
    }

    function test_belowThreshold_oneSignerPerOrganization_reverts() public {
        bytes memory scp = _scp(_pick("105", _names("A0", "B0", "C0", "")), _txSet(105), "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.QuorumNotSatisfied.selector), _withScp(scp), _anchor0(), _ctx()
        );
    }

    function test_unknownSigner_reverts() public {
        Env[] memory a = _pick("105", _names("A0", "A1", "B0", "B1"));
        Env[] memory d = _envs("105D");
        Env[] memory e = new Env[](5);
        for (uint256 i = 0; i < 4; ++i) {
            e[i] = a[i];
        }
        e[4] = d[0];
        // keep node-id order so the membership check is what fails
        _sortEnvs(e);
        _expectRevert(
            abi.encodeWithSelector(
                StellarScpVerifier.UnknownSigner.selector, vm.parseJsonBytes32(fx, ".validators.D0")
            ),
            _withScp(_scp(e, _txSet(105), "")),
            _anchor0(),
            _ctx()
        );
    }

    function test_duplicateSigner_reverts() public {
        Env[] memory a = _pick("105", _names("A0", "A1", "B0", "B1"));
        Env[] memory e = new Env[](5);
        for (uint256 i = 0; i < 4; ++i) {
            e[i] = a[i];
        }
        e[4] = a[3];
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.SignersNotSorted.selector, 4),
            _withScp(_scp(e, _txSet(105), "")),
            _anchor0(),
            _ctx()
        );
    }

    function test_wrongValidatorSet_reverts() public {
        bytes memory proof = _bundle(Q2, _scpStd(105), _headers(104, 103), _attItem(_att("queue")), "", "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.QuorumSetMismatch.selector), proof, _anchor0(), _ctx());
    }

    function test_mixedSlots_reverts() public {
        Env[] memory a = _pick("105", _names("A0", "A1", "", ""));
        Env[] memory b = _pick("112", _names("B0", "B1", "", ""));
        Env[] memory e = new Env[](4);
        (e[0], e[1], e[2], e[3]) = (a[0], a[1], b[0], b[1]);
        _sortEnvs(e);
        _expectAnyRevert(_withScp(_scp(e, _txSet(105), "")), _anchor0(), _ctx());
    }

    function test_conflictingValue_reverts() public {
        Env[] memory a = _pick("105", _names("A0", "A1", "B0", "B1"));
        Env[] memory c = _envs("105other"); // C2 signs ledger 106's value for slot 105
        Env[] memory e = new Env[](5);
        for (uint256 i = 0; i < 4; ++i) {
            e[i] = a[i];
        }
        e[4] = c[0];
        _sortEnvs(e);
        _expectAnyRevert(_withScp(_scp(e, _txSet(105), "")), _anchor0(), _ctx());
    }

    function test_wrongTxSet_reverts() public {
        bytes memory scp = _scp(_pick("105", _names("A0", "A1", "B0", "B1")), _txSet(106), "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.TxSetMismatch.selector), _withScp(scp), _anchor0(), _ctx()
        );
    }

    function test_staleSlot_reverts() public {
        bytes memory anchor = _anchor(Q1_HASH, 105, 100, _headerHash(100), bytes32(0));
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.StaleSlot.selector, 105, 105), _fullBundle(), anchor, _ctx()
        );
    }

    function test_replayedBundle_reverts() public {
        (, bytes memory a) = _verify(_fullBundle(), _anchor0());
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.StaleSlot.selector, 105, 105), _fullBundle(), a, _ctx());
    }

    /// Re-proving the last metadata from the same checkpoint advances nothing: no new anchor (the
    /// CLPR Service then rejects the bundle with NoProgress, see IntegrationStellar.t.sol).
    function test_sameAttestationAgain_returnsNoNewAnchor() public view {
        (, bytes memory a) = _verify(_fullBundle(), _anchor0());
        bytes memory again = _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", "", "");
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory naId,) =
            v.verifyBundle(again, a, _ctx());
        _assertMeta(m, _fixtureMeta());
        assertEq(payloads.length, 0);
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    // ── Rotation ─────────────────────────────────────────────────────────────

    function test_rotation_notEndorsedByQuorum_reverts() public {
        // A0, A1 declare Q2; C1, C2 still declare Q1. Finality holds (orgs A and C) but only one
        // organization endorses Q2.
        Env[] memory a = _pick("120", _names("A0", "A1", "", ""));
        Env[] memory c = _envs("120old");
        Env[] memory e = new Env[](4);
        (e[0], e[1], e[2], e[3]) = (a[0], a[1], c[0], c[1]);
        _sortEnvs(e);
        bytes memory anchor = _anchor(Q1_HASH, 112, 0, bytes32(0), bytes32(0));
        bytes memory rot = _bundle(Q1, _scp(e, _txSet(120), Q2), _emptyList(), _emptyList(), "", "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.RotationNotEndorsed.selector), rot, anchor, _ctx());
    }

    function test_rotation_toInsaneQuorumSet_reverts() public {
        bytes memory bad = bytes.concat(bytes4(0), bytes4(uint32(0)), bytes4(uint32(0))); // threshold 0, empty
        bytes memory anchor = _anchor(Q1_HASH, 112, 0, bytes32(0), bytes32(0));
        bytes memory rot = _bundle(
            Q1,
            _scp(_pick("120", _names("A0", "A1", "B0", "B1")), _txSet(120), bad),
            _emptyList(),
            _emptyList(),
            "",
            "",
            ""
        );
        _expectRevert(abi.encodeWithSelector(StellarXdr.QuorumSetInsane.selector), rot, anchor, _ctx());
    }

    function test_rotation_toUndeclaredQuorumSet_reverts() public {
        // Signers of slot 105 declare Q1; offering Q2 as the new set is not endorsed.
        bytes memory anchor = _anchor(Q1_HASH, 101, 0, bytes32(0), bytes32(0));
        bytes memory rot = _bundle(
            Q1,
            _scp(_pick("105", _names("A0", "A1", "B0", "B1")), _txSet(105), Q2),
            _emptyList(),
            _emptyList(),
            "",
            "",
            ""
        );
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.RotationNotEndorsed.selector), rot, anchor, _ctx());
    }

    // ── Headers ──────────────────────────────────────────────────────────────

    function test_brokenHeaderChain_reverts() public {
        bytes[] memory hs = new bytes[](2);
        hs[0] = _str(_header(104));
        hs[1] = _str(_header(102));
        bytes memory proof = _bundle(Q1, _scpStd(105), _list(hs), _attItem(_att("queue")), "", "", "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.HeaderChainBroken.selector, 1), proof, _anchor0(), _ctx()
        );
    }

    function test_tamperedHeader_reverts() public {
        bytes memory h = _header(104);
        h[h.length - 20] ^= bytes1(0x01);
        bytes[] memory hs = new bytes[](2);
        hs[0] = _str(h);
        hs[1] = _str(_header(103));
        bytes memory proof = _bundle(Q1, _scpStd(105), _list(hs), _attItem(_att("queue")), "", "", "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.HeaderChainBroken.selector, 0), proof, _anchor0(), _ctx()
        );
    }

    function test_noCheckpoint_reverts() public {
        bytes memory anchor = _anchor(Q1_HASH, 101, 0, bytes32(0), bytes32(0));
        bytes memory proof = _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.NoCheckpoint.selector), proof, anchor, _ctx());
    }

    function test_headersWithoutAttestation_reverts() public {
        bytes memory proof = _bundle(Q1, _scpStd(105), _headers(104, 103), _emptyList(), "", "", "");
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.InvalidPayloadShape.selector), proof, _anchor0(), _ctx()
        );
    }

    // ── Result set, transaction and event ("storage proof") ──────────────────

    function test_tamperedResultSet_reverts() public {
        Att memory a = _att("queue");
        a.resultSet[a.resultSet.length - 1] ^= bytes1(0x01);
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.ResultSetMismatch.selector), _withAtt(a), _anchor0(), _ctx()
        );
    }

    function test_wrongPairOffset_reverts() public {
        Att memory a = _att("queue");
        a.offset += 4;
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.TransactionNotInResultSet.selector),
            _withAtt(a),
            _anchor0(),
            _ctx()
        );
    }

    function test_otherTransactionPayload_reverts() public {
        Att memory a = _att("queue");
        a.txPayload = _att("wrongChannel").txPayload;
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.TransactionNotInResultSet.selector),
            _withAtt(a),
            _anchor0(),
            _ctx()
        );
    }

    function test_payloadForOtherNetwork_reverts() public {
        Att memory a = _att("queue");
        a.txPayload[0] ^= bytes1(0x01);
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.BadTransactionPayload.selector), _withAtt(a), _anchor0(), _ctx()
        );
    }

    function test_tamperedPreimage_reverts() public {
        Att memory a = _att("queue");
        a.preimage[a.preimage.length - 1] ^= bytes1(0x01);
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.SuccessPreimageMismatch.selector), _withAtt(a), _anchor0(), _ctx()
        );
    }

    function test_eventFromOtherContract_reverts() public {
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.WrongEmitter.selector, vm.parseJsonBytes32(fx, ".otherContract")),
            _withAtt(_att("wrongEmitter")),
            _anchor0(),
            _ctx()
        );
    }

    function test_eventForOtherChannel_reverts() public {
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.WrongAttestationEvent.selector),
            _withAtt(_att("wrongChannel")),
            _anchor0(),
            _ctx()
        );
    }

    function test_otherServiceEvent_reverts() public {
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.WrongAttestationEvent.selector),
            _withAtt(_att("otherEvent")),
            _anchor0(),
            _ctx()
        );
    }

    function test_invalidChannelStatus_reverts() public {
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.InvalidChannelStatus.selector, 9),
            _withAtt(_att("badStatus")),
            _anchor0(),
            _ctx()
        );
    }

    function test_wrongServiceAddressLength_reverts() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(address(1))})
        );
        _expectRevert(
            abi.encodeWithSelector(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector),
            _fullBundle(),
            _anchor0(),
            ctx
        );
    }

    // ── Checkpoint-only bundles ──────────────────────────────────────────────

    function test_checkpointOnly_wrongLastMetadata_reverts() public {
        (ClprTypes.QueueMetadata memory m, bytes memory a) = _verify(_fullBundle(), _anchor0());
        m.nextMessageId += 1;
        bytes memory step1 = _bundle(Q1, _scpStd(112), _emptyList(), _emptyList(), abi.encode(m), "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.LastMetadataMismatch.selector), step1, a, _ctx());
    }

    function test_nothingProven_reverts() public {
        bytes memory proof = _bundle(Q1, _emptyList(), _emptyList(), _emptyList(), "", "", "");
        _expectRevert(abi.encodeWithSelector(StellarScpVerifier.NothingProven.selector), proof, _anchor0(), _ctx());
    }

    function test_manifestWithoutAttestation_reverts() public {
        bytes memory proof =
            _bundle(Q1, _scpStd(105), _emptyList(), _emptyList(), "", "", vm.parseJsonBytes(fx, ".manifest"));
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.InvalidPayloadShape.selector), proof, _anchor0(), _ctx()
        );
    }

    // ── Malformed input ──────────────────────────────────────────────────────

    function test_badTrustAnchorLength_reverts() public {
        _expectRevert(
            abi.encodeWithSelector(StellarScpVerifier.InvalidTrustAnchor.selector), _fullBundle(), hex"00", _ctx()
        );
    }

    function test_emptyProof_reverts() public {
        _expectAnyRevert("", _anchor0(), _ctx());
        vm.expectRevert(StellarScpVerifier.InvalidPayloadShape.selector);
        v.verifyConfig("", CHANNEL, "");
    }

    /// Truncations of a valid proof must revert with an error, never a Panic.
    function test_truncatedProof_neverPanics() public view {
        bytes memory proof = _fullBundle();
        bytes memory anchor = _anchor0();
        bytes memory ctx = _ctx();
        for (uint256 len = 0; len < proof.length; len += 97) {
            bytes memory t = new bytes(len);
            for (uint256 i = 0; i < len; ++i) {
                t[i] = proof[i];
            }
            try v.verifyBundle(t, anchor, ctx) {
                revert("truncated proof accepted");
            } catch (bytes memory err) {
                assertTrue(err.length < 4 || bytes4(err) != bytes4(0x4e487b71), "panic");
            }
        }
    }

    function test_quorumSetParsing_strictRules() public {
        // threshold below the v-blocking size (1 of 3) is rejected in strict mode only
        bytes memory q = bytes.concat(
            bytes4(uint32(1)),
            bytes4(uint32(3)),
            bytes4(0),
            bytes32(uint256(1)),
            bytes4(0),
            bytes32(uint256(2)),
            bytes4(0),
            bytes32(uint256(3)),
            bytes4(0)
        );
        this.parseQset(q, false);
        vm.expectRevert(StellarXdr.QuorumSetInsane.selector);
        this.parseQset(q, true);
        // duplicate validator
        bytes memory dup = bytes.concat(
            bytes4(uint32(1)),
            bytes4(uint32(2)),
            bytes4(0),
            bytes32(uint256(1)),
            bytes4(0),
            bytes32(uint256(1)),
            bytes4(0)
        );
        vm.expectRevert(StellarXdr.QuorumSetInsane.selector);
        this.parseQset(dup, false);
    }

    function parseQset(bytes memory q, bool strict) external pure returns (uint32) {
        return StellarXdr.parseQuorumSet(q, strict).threshold;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Arguments are evaluated (fixture cheatcodes included) before the expectation is armed.
    function _expectRevert(bytes memory err, bytes memory proof, bytes memory anchor, bytes memory ctx) internal {
        vm.expectRevert(err);
        v.verifyBundle(proof, anchor, ctx);
    }

    function _expectAnyRevert(bytes memory proof, bytes memory anchor, bytes memory ctx) internal {
        vm.expectRevert();
        v.verifyBundle(proof, anchor, ctx);
    }

    function _sortEnvs(Env[] memory e) internal pure {
        for (uint256 i = 1; i < e.length; ++i) {
            Env memory x = e[i];
            uint256 j = i;
            while (j > 0 && _nodeOf(e[j - 1]) > _nodeOf(x)) {
                e[j] = e[j - 1];
                --j;
            }
            e[j] = x;
        }
    }

    function _nodeOf(Env memory e) internal pure returns (bytes32 k) {
        bytes memory s = e.statement;
        assembly ("memory-safe") {
            k := mload(add(s, 0x24))
        }
    }
}
