// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {GrandpaCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaCommitAccumulator.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";
import {GrandpaPalletVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaPalletVerifier.sol";
import {SubstrateVerifierErrors} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateVerifierErrors.sol";

/// @notice GrandpaPalletVerifier and GrandpaCommitAccumulator on the synthetic chain of
///         fixtures/synthetic.json (section `pallet`): a native `Clpr` pallet trie with Queues and
///         Service records (plus malformed records), real ed25519 justifications from 4-authority
///         sets, a set change with delay 0, and a weighted 5-authority set (weights 1,1,1,1,4;
///         threshold 6) whose precommits are accumulated in batches. Live Chainflip data is covered
///         by test/e2e/tests/verifiers/grandpa-live.spec.ts.
contract GrandpaPalletVerifierTest is Test {
    string internal json;
    GrandpaPalletVerifier internal v;
    GrandpaPalletVerifier internal vw; // bootstrapped on the weighted set, with the accumulator
    GrandpaCommitAccumulator internal acc;
    Ed25519Verifier internal ed;

    string internal constant CHAIN_ID = "polkadot:8cd2b6ea4bb3e6b1ff5ac8cab4e5b5f5";
    uint64 internal constant ROUND = 7;
    uint64 internal constant SET_W = 9;

    bytes16 internal pallet;
    bytes internal auth0;
    bytes internal auth1;
    bytes internal authW;
    bytes[] internal nodes;
    bytes internal service;
    bytes32 internal channelId;
    bytes internal ctx;

    function setUp() public {
        json = vm.readFile("test/verifiers/evm/grandpa/fixtures/synthetic.json");
        pallet = bytes16(vm.parseJsonBytes(json, ".pallet.pallet"));
        auth0 = vm.parseJsonBytes(json, ".pallet.authorities.set0");
        auth1 = vm.parseJsonBytes(json, ".pallet.authorities.set1");
        authW = vm.parseJsonBytes(json, ".pallet.authorities.setW");
        nodes = vm.parseJsonBytesArray(json, ".pallet.nodes");
        service = vm.parseJsonBytes(json, ".pallet.service");
        channelId = vm.parseJsonBytes32(json, ".channelId");
        ctx = abi.encodePacked(channelId, service);
        ed = new Ed25519Verifier();
        acc = new GrandpaCommitAccumulator(address(ed));
        v = new GrandpaPalletVerifier(address(ed), address(0), pallet, CHAIN_ID, 0, keccak256(auth0), 200);
        vw = new GrandpaPalletVerifier(address(ed), address(acc), pallet, CHAIN_ID, SET_W, keccak256(authW), 300);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, key);
    }

    function _anchor(uint64 setId, bytes memory authorities, uint32 minHeight) internal pure returns (bytes memory) {
        return abi.encodePacked(setId, keccak256(authorities), minHeight);
    }

    function _step(string memory blk, bytes memory votes, bytes memory authorities)
        internal
        view
        returns (GrandpaLightClient.Step memory s)
    {
        s.headers = new bytes[](1);
        s.headers[0] = _b(string.concat(".pallet.", blk, ".header"));
        s.round = ROUND;
        s.votes = votes;
        s.ancestry = new bytes[](0);
        s.authorities = authorities;
    }

    function _step(string memory blk, bytes memory authorities) internal view returns (GrandpaLightClient.Step memory) {
        return _step(blk, _b(string.concat(".pallet.", blk, ".votes")), authorities);
    }

    function _one(GrandpaLightClient.Step memory s) internal pure returns (GrandpaLightClient.Step[] memory steps) {
        steps = new GrandpaLightClient.Step[](1);
        steps[0] = s;
    }

    function _bundle(GrandpaLightClient.Step[] memory steps) internal view returns (bytes memory) {
        return abi.encode(GrandpaPalletVerifier.BundleProof(steps, nodes, "", ""));
    }

    function _typical() internal view returns (bytes memory) {
        return _bundle(_one(_step("p200", auth0)));
    }

    function _voteW(uint256 i) internal view returns (bytes memory) {
        return _b(string.concat(".pallet.p300.votesW[", vm.toString(i), "]"));
    }

    function _votesW(uint256[] memory idx) internal view returns (bytes memory out) {
        for (uint256 i; i < idx.length; ++i) {
            out = bytes.concat(out, _voteW(idx[i]));
        }
    }

    function _idx(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    function _idx(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _commitW(bytes memory votes) internal view returns (GrandpaLib.Commit memory c) {
        c = GrandpaLib.Commit({
            targetHash: vm.parseJsonBytes32(json, ".pallet.p300.hash"),
            targetNumber: 300,
            round: ROUND,
            setId: SET_W,
            votes: votes,
            ancestry: new bytes[](0)
        });
    }

    function _accumulate(uint256[] memory idx) internal returns (uint256 weight) {
        (, weight) = acc.accumulate(_commitW(_votesW(idx)), authW);
    }

    function _assertMetadata(ClprTypes.QueueMetadata memory m) internal pure {
        assertEq(m.nextMessageId, 3);
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.receivedMessageId, 2);
        assertEq(m.sentRunningHash, keccak256("sentRunningHash"));
        assertEq(m.receivedRunningHash, keccak256("receivedRunningHash"));
        assertEq(m.endpointManifestVersion, 1);
    }

    // ── happy paths ──────────────────────────────────────────────────────────

    function test_typicalBundle() public {
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory nid,) =
            v.verifyBundle(_typical(), _anchor(0, auth0, 200), ctx);
        _assertMetadata(m);
        assertEq(payloads.length, 0);
        assertEq(na.length, 0);
        assertEq(nid.length, 0);
        uint256 gasBefore = gasleft();
        v.verifyBundle(_typical(), _anchor(0, auth0, 200), ctx);
        emit log_named_uint("verifyBundle gas, 3 ed25519 precommits, pallet record", gasBefore - gasleft());
    }

    function test_queueKeyLayout() public view {
        bytes memory k = v.queueKey(channelId);
        assertEq(k.length, 80);
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes16(k), pallet);
        assertEq(v.serviceKey(), abi.encodePacked(pallet, bytes16(0x221b4c4483eae1aedca119452a71c709)));
    }

    function test_absentChannelReadsEmpty() public view {
        (ClprTypes.QueueMetadata memory m,,,,) =
            v.verifyBundle(_typical(), _anchor(0, auth0, 200), abi.encodePacked(bytes32(uint256(1)), service));
        assertEq(m.nextMessageId, 0);
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.PENDING));
        assertEq(m.sentRunningHash, bytes32(0));
    }

    function test_manifestAndPayloads() public view {
        bytes memory content = hex"1203616263120178";
        bytes memory p = abi.encode(
            GrandpaPalletVerifier.BundleProof(
                _one(_step("p200", auth0)), nodes, content, _b(".pallet.manifestPreimage")
            )
        );
        (, bytes[] memory payloads,,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyBundle(p, _anchor(0, auth0, 200), ctx);
        assertEq(payloads.length, 2);
        assertEq(payloads[1], bytes("x"));
        assertEq(man.version, 1);
        assertEq(man.serviceAddress, service);
    }

    function test_rotationDelayZero() public view {
        (,, bytes memory na, bytes memory nid,) =
            v.verifyBundle(_bundle(_one(_step("p220", auth0))), _anchor(0, auth0, 200), ctx);
        assertEq(na, _anchor(1, auth1, 221));
        assertEq(nid, abi.encodePacked(uint64(1)));
    }

    function test_rotationThenFinalStep() public view {
        GrandpaLightClient.Step[] memory steps = new GrandpaLightClient.Step[](2);
        steps[0] = _step("p220", auth0);
        steps[1] = _step("p230", auth1);
        (ClprTypes.QueueMetadata memory m,, bytes memory na,,) =
            v.verifyBundle(_bundle(steps), _anchor(0, auth0, 200), ctx);
        _assertMetadata(m);
        assertEq(na, _anchor(1, auth1, 221));
    }

    function test_verifyStorageEntry() public view {
        bytes memory p = abi.encode(GrandpaPalletVerifier.EntryProof(_one(_step("p200", auth0)), nodes));
        (bool exists, bytes memory value, uint32 number) =
            v.verifyStorageEntry(p, _anchor(0, auth0, 200), _b(".pallet.currentSetIdKey"));
        assertTrue(exists);
        assertEq(value, hex"0900000000000000");
        assertEq(number, 200);
        (exists, value,) = v.verifyStorageEntry(p, _anchor(0, auth0, 200), _b(".pallet.systemAccountKey"));
        assertTrue(exists);
        assertEq(value.length, 80);
        (exists,,) = v.verifyStorageEntry(p, _anchor(0, auth0, 200), v.queueKey(bytes32(uint256(7))));
        assertFalse(exists);
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function _ledgerConfig(string memory chainId, bytes memory svc, uint96 nanos) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = svc;
        lc.nanosSinceEpoch = nanos;
        lc.throttles = ClprTypes.Throttles(10, 1024, 1_000_000, 100, 4096, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(bytes memory ledger) internal view returns (bytes memory) {
        return abi.encode(GrandpaPalletVerifier.ConfigProof(_one(_step("p200", auth0)), nodes, ledger));
    }

    function _nanos() internal view returns (uint96) {
        return uint96(vm.parseJsonUint(json, ".configNanos"));
    }

    function test_verifyConfig() public view {
        (
            bytes memory cctx,
            string memory chainId,
            bytes memory svc,
            uint96 peerNanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(
            _config(_ledgerConfig(CHAIN_ID, service, _nanos())), channelId, _b(".pallet.manifestPreimage")
        );
        assertEq(cctx, ctx);
        assertEq(chainId, CHAIN_ID);
        assertEq(svc, service);
        assertEq(peerNanos, _nanos());
        assertEq(t.maxMessagesPerBundle, 10);
        assertEq(anchor, _anchor(0, auth0, 200));
        assertEq(anchorId, abi.encodePacked(uint64(0)));
        assertEq(man.version, 1);
    }

    function test_verifyConfig_withoutManifestIsUninitialized() public view {
        (,,,,,,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyConfig(_config(_ledgerConfig(CHAIN_ID, service, _nanos())), channelId, "");
        assertEq(man.version, 0);
        assertEq(man.serviceAddress, service);
    }

    function test_verifyConfig_wrongChainId() public {
        bytes memory p = _config(_ledgerConfig("eip155:1", service, _nanos()));
        vm.expectRevert(GrandpaPalletVerifier.ChainIdMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    function test_verifyConfig_wrongServiceAddress() public {
        bytes memory p = _config(_ledgerConfig(CHAIN_ID, abi.encodePacked(bytes32(uint256(0xdead))), _nanos()));
        vm.expectRevert(GrandpaPalletVerifier.ServiceAddressMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    function test_verifyConfig_wrongNanos() public {
        bytes memory p = _config(_ledgerConfig(CHAIN_ID, service, 1));
        vm.expectRevert(GrandpaPalletVerifier.ConfigNanosMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    function test_verifyConfig_serviceRecordMissing() public {
        // The EVM-trie chain of the `grandpa` section has no Clpr::Service record.
        GrandpaPalletVerifier v2 = new GrandpaPalletVerifier(
            address(ed), address(0), pallet, CHAIN_ID, 0, keccak256(_b(".grandpa.authorities.set0")), 100
        );
        GrandpaLightClient.Step memory s;
        s.headers = new bytes[](1);
        s.headers[0] = _b(".grandpa.b100.header");
        s.round = ROUND;
        s.votes = _b(".grandpa.b100.votes");
        s.ancestry = new bytes[](0);
        s.authorities = _b(".grandpa.authorities.set0");
        bytes memory p = abi.encode(
            GrandpaPalletVerifier.ConfigProof(
                _one(s), vm.parseJsonBytesArray(json, ".evm.nodes"), _ledgerConfig(CHAIN_ID, service, _nanos())
            )
        );
        vm.expectRevert(GrandpaPalletVerifier.ServiceRecordMissing.selector);
        v2.verifyConfig(p, channelId, "");
    }

    // ── accumulator ──────────────────────────────────────────────────────────

    function test_accumulatedCommitFinalizes() public {
        assertEq(_accumulate(_idx(0, 1)), 2);
        uint256 gasBefore = gasleft();
        assertEq(_accumulate(_idx(4)), 6); // weight 4
        emit log_named_uint("accumulate gas, 1 ed25519 precommit", gasBefore - gasleft());
        bytes memory p = _bundle(_one(_step("p300", "", authW)));
        (ClprTypes.QueueMetadata memory m,,,,) = vw.verifyBundle(p, _anchor(SET_W, authW, 300), ctx);
        _assertMetadata(m);
        bytes32 key = acc.commitKey(SET_W, keccak256(authW), ROUND, vm.parseJsonBytes32(json, ".pallet.p300.hash"), 300);
        assertTrue(acc.isCounted(key, 4));
        assertFalse(acc.isCounted(key, 2));
    }

    function test_inlineWeightedVotes() public view {
        // Indices 0 and 4 carry weight 1 + 4 = 5 < 6; adding index 1 reaches 6.
        uint256[] memory idx = new uint256[](3);
        (idx[0], idx[1], idx[2]) = (0, 1, 4);
        bytes memory p = _bundle(_one(_step("p300", _votesW(idx), authW)));
        (ClprTypes.QueueMetadata memory m,,,,) = vw.verifyBundle(p, _anchor(SET_W, authW, 300), ctx);
        _assertMetadata(m);
    }

    function test_rejects_inlineWeightedBelowThreshold() public {
        bytes memory p = _bundle(_one(_step("p300", _votesW(_idx(0, 4)), authW)));
        bytes memory a = _anchor(SET_W, authW, 300);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 5, 6));
        vw.verifyBundle(p, a, ctx);
    }

    function test_rejects_accumulatedBelowThreshold() public {
        uint256[] memory idx = new uint256[](3);
        (idx[0], idx[1], idx[2]) = (0, 1, 2);
        _accumulate(idx);
        bytes memory p = _bundle(_one(_step("p300", "", authW)));
        bytes memory a = _anchor(SET_W, authW, 300);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 3, 6));
        vw.verifyBundle(p, a, ctx);
    }

    function test_rejects_accumulatedForAnotherRound() public {
        _accumulate(_idx(0, 4));
        _accumulate(_idx(1));
        GrandpaLightClient.Step memory s = _step("p300", "", authW);
        s.round = ROUND + 1; // the record is keyed by round
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(SET_W, authW, 300);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 0, 6));
        vw.verifyBundle(p, a, ctx);
    }

    function test_rejects_accumulatedForAnotherSetId() public {
        _accumulate(_idx(0, 4));
        _accumulate(_idx(1));
        bytes memory p = _bundle(_one(_step("p300", "", authW)));
        bytes memory a = _anchor(SET_W + 1, authW, 300);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 0, 6));
        vw.verifyBundle(p, a, ctx);
    }

    function test_accumulator_rejectsDoubleCount() public {
        _accumulate(_idx(0, 1));
        GrandpaLib.Commit memory c = _commitW(_voteW(1));
        vm.expectRevert(abi.encodeWithSelector(GrandpaCommitAccumulator.AlreadyCounted.selector, 0, 2));
        acc.accumulate(c, authW);
    }

    function test_accumulator_rejectsBadSignature() public {
        bytes memory vote = _voteW(3);
        vote[40] ^= 0x01;
        GrandpaLib.Commit memory c = _commitW(vote);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 3));
        acc.accumulate(c, authW);
    }

    function test_accumulator_rejectsWrongSetIdSignature() public {
        GrandpaLib.Commit memory c = _commitW(_voteW(0));
        c.setId = SET_W + 1;
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 0));
        acc.accumulate(c, authW);
    }

    function test_accumulator_rejectsZeroVerifier() public {
        vm.expectRevert(GrandpaCommitAccumulator.InvalidProfile.selector);
        new GrandpaCommitAccumulator(address(0));
    }

    function test_rejects_emptyVotesWithoutAccumulator() public {
        bytes memory p = _bundle(_one(_step("p200", "", auth0)));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(GrandpaPalletVerifier.AccumulatorNotConfigured.selector);
        v.verifyBundle(p, a, ctx);
    }

    // ── negative: finality ───────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        GrandpaLightClient.Step memory s = _step("p200", auth0);
        s.votes[102 + 40] ^= 0x01;
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 1));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_belowThreshold() public {
        GrandpaLightClient.Step memory s = _step("p200", auth0);
        bytes memory two = new bytes(204);
        for (uint256 i; i < 204; ++i) {
            two[i] = s.votes[i];
        }
        s.votes = two;
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 2, 3));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_wrongValidatorSet() public {
        bytes memory p = _bundle(_one(_step("p200", auth1)));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(GrandpaLightClient.AuthoritySetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_replayedSetId() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(3, auth0, 200);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 0));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_staleBlock() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(0, auth0, 201);
        vm.expectRevert(SubstrateVerifierErrors.HeightTooOld.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_oldSetAfterRotation() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(1, auth1, 221);
        vm.expectRevert(GrandpaLightClient.AuthoritySetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    // ── negative: state ──────────────────────────────────────────────────────

    function test_rejects_tamperedTrieNode() public {
        bytes[] memory bad = nodes;
        bytes memory root = bad[bad.length - 1];
        root[root.length - 1] ^= 0x01;
        bytes memory p = abi.encode(GrandpaPalletVerifier.BundleProof(_one(_step("p200", auth0)), bad, "", ""));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_badRecordLength() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(0, auth0, 200);
        bytes memory c = abi.encodePacked(vm.parseJsonBytes32(json, ".pallet.badLengthChannel"), service);
        vm.expectRevert(GrandpaPalletVerifier.InvalidQueueRecord.selector);
        v.verifyBundle(p, a, c);
    }

    function test_rejects_badRecordStatus() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(0, auth0, 200);
        bytes memory c = abi.encodePacked(vm.parseJsonBytes32(json, ".pallet.badStatusChannel"), service);
        vm.expectRevert(GrandpaPalletVerifier.InvalidQueueRecord.selector);
        v.verifyBundle(p, a, c);
    }

    function test_rejects_wrongManifestPreimage() public {
        bytes memory p = abi.encode(GrandpaPalletVerifier.BundleProof(_one(_step("p200", auth0)), nodes, "", hex"0802"));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(bytes4(keccak256("ManifestCommitmentMismatch()")));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_manifestForOtherService() public {
        bytes memory p = abi.encode(
            GrandpaPalletVerifier.BundleProof(_one(_step("p200", auth0)), nodes, "", _b(".pallet.manifestPreimage"))
        );
        bytes memory a = _anchor(0, auth0, 200);
        bytes memory c = abi.encodePacked(channelId, bytes32(uint256(0xbeef)));
        vm.expectRevert(GrandpaPalletVerifier.ServiceAddressMismatch.selector);
        v.verifyBundle(p, a, c);
    }

    // ── negative: shapes / profile ───────────────────────────────────────────

    function test_rejects_badAnchorLength() public {
        bytes memory p = _typical();
        vm.expectRevert(GrandpaLightClient.InvalidTrustAnchor.selector);
        v.verifyBundle(p, hex"00", ctx);
    }

    function test_rejects_noSteps() public {
        bytes memory p = _bundle(new GrandpaLightClient.Step[](0));
        bytes memory a = _anchor(0, auth0, 200);
        vm.expectRevert(GrandpaLightClient.InvalidPayloadShape.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_constructor_rejectsBadProfile() public {
        vm.expectRevert(GrandpaLightClient.InvalidProfile.selector);
        new GrandpaPalletVerifier(address(0), address(0), pallet, CHAIN_ID, 0, keccak256(auth0), 200);
        vm.expectRevert(GrandpaLightClient.InvalidProfile.selector);
        new GrandpaPalletVerifier(address(ed), address(0), bytes16(0), CHAIN_ID, 0, keccak256(auth0), 200);
        vm.expectRevert(GrandpaLightClient.InvalidProfile.selector);
        new GrandpaPalletVerifier(address(ed), address(0), pallet, "", 0, keccak256(auth0), 200);
    }
}
