// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";
import {GrandpaVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaVerifier.sol";
import {SubstrateEvmVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateEvmVerifierBase.sol";
import {SubstrateVerifierErrors} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateVerifierErrors.sol";

/// @notice GrandpaVerifier on the synthetic GRANDPA chain of fixtures/synthetic.json: real ed25519
///         justifications from 4-authority sets (threshold 3), set changes with delay 0 and 2, a
///         descendant precommit with votes_ancestries, a ForcedChange, and a ClprService storage
///         trie. Live Bittensor data is covered by test/e2e/tests/verifiers/grandpa-live.spec.ts.
contract GrandpaVerifierTest is Test {
    string internal json;
    GrandpaVerifier internal v;
    Ed25519Verifier internal ed;

    bytes16 internal constant EVM = 0x1da53b775b270400e7e61ed5cbc5a146;
    string internal constant CHAIN_ID = "eip155:964";
    uint64 internal constant ROUND = 7;

    bytes internal auth0;
    bytes internal auth1;
    bytes internal auth2;
    bytes[] internal nodes;
    bytes internal ctx;
    address internal service;
    bytes32 internal channelId;

    function setUp() public {
        json = vm.readFile("test/verifiers/evm/grandpa/fixtures/synthetic.json");
        auth0 = vm.parseJsonBytes(json, ".grandpa.authorities.set0");
        auth1 = vm.parseJsonBytes(json, ".grandpa.authorities.set1");
        auth2 = vm.parseJsonBytes(json, ".grandpa.authorities.set2");
        nodes = vm.parseJsonBytesArray(json, ".evm.nodes");
        service = vm.parseJsonAddress(json, ".service");
        channelId = vm.parseJsonBytes32(json, ".channelId");
        ctx = abi.encodePacked(channelId, service);
        ed = new Ed25519Verifier();
        v = new GrandpaVerifier(address(ed), EVM, CHAIN_ID, 0, keccak256(auth0), 100);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, key);
    }

    function _anchor(uint64 setId, bytes memory authorities, uint32 minHeight) internal pure returns (bytes memory) {
        return abi.encodePacked(setId, keccak256(authorities), minHeight);
    }

    function _step(string memory blk, string memory votesKey, bytes memory authorities)
        internal
        view
        returns (GrandpaLightClient.Step memory s)
    {
        s.headers = new bytes[](1);
        s.headers[0] = _b(string.concat(".grandpa.", blk, ".header"));
        s.round = ROUND;
        s.votes = _b(string.concat(".grandpa.", blk, ".", votesKey));
        s.ancestry = new bytes[](0);
        s.authorities = authorities;
    }

    function _one(GrandpaLightClient.Step memory s) internal pure returns (GrandpaLightClient.Step[] memory steps) {
        steps = new GrandpaLightClient.Step[](1);
        steps[0] = s;
    }

    function _bundle(GrandpaLightClient.Step[] memory steps) internal view returns (bytes memory) {
        return abi.encode(GrandpaVerifier.BundleProof(steps, nodes, false, "", ""));
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory newAnchor, bytes memory newAnchorId)
    {
        (m,, newAnchor, newAnchorId,) = v.verifyBundle(proof, anchor, ctx);
    }

    function _assertServiceMetadata(ClprTypes.QueueMetadata memory m) internal pure {
        assertEq(m.nextMessageId, 3);
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.receivedMessageId, 2);
        assertEq(m.sentRunningHash, keccak256("sentRunningHash"));
        assertEq(m.receivedRunningHash, keccak256("receivedRunningHash"));
        assertEq(m.endpointManifestVersion, 1);
    }

    // ── happy paths ──────────────────────────────────────────────────────────

    function test_typicalBundle() public {
        (ClprTypes.QueueMetadata memory m, bytes memory na, bytes memory nid) =
            _verify(_bundle(_one(_step("b100", "votes", auth0))), _anchor(0, auth0, 100));
        _assertServiceMetadata(m);
        assertEq(na.length, 0);
        assertEq(nid.length, 0);
        uint256 gasBefore = gasleft();
        v.verifyBundle(_bundle(_one(_step("b100", "votes", auth0))), _anchor(0, auth0, 100), ctx);
        emit log_named_uint("verifyBundle gas, 3 ed25519 precommits", gasBefore - gasleft());
    }

    function test_allVotesAccepted() public view {
        (ClprTypes.QueueMetadata memory m,,) =
            _verify(_bundle(_one(_step("b100", "votesAll", auth0))), _anchor(0, auth0, 100));
        _assertServiceMetadata(m);
    }

    function test_manifestPayloadsAndLastMessageSlot() public view {
        bytes memory content = hex"1203616263120178"; // ClprBundleContent{2: "abc", 2: "x"}
        bytes memory proof = abi.encode(
            GrandpaVerifier.BundleProof(
                _one(_step("b100", "votes", auth0)), nodes, true, content, _b(".manifestPreimage")
            )
        );
        (, bytes[] memory payloads,,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyBundle(proof, _anchor(0, auth0, 100), ctx);
        assertEq(payloads.length, 2);
        assertEq(payloads[0], bytes("abc"));
        assertEq(man.version, 1);
        assertEq(man.serviceAddress, abi.encodePacked(service));
    }

    function test_descendantPrecommitWithAncestry() public view {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        s.votes = _b(".grandpa.b101.ancestryVotes");
        s.ancestry = new bytes[](1);
        s.ancestry[0] = _b(".grandpa.b101.header");
        (ClprTypes.QueueMetadata memory m,,) = _verify(_bundle(_one(s)), _anchor(0, auth0, 100));
        _assertServiceMetadata(m);
    }

    function test_rotationDelayZero() public view {
        (, bytes memory na, bytes memory nid) =
            _verify(_bundle(_one(_step("b120", "votes", auth0))), _anchor(0, auth0, 100));
        assertEq(na, _anchor(1, auth1, 121));
        assertEq(nid, abi.encodePacked(uint64(1)));
    }

    function test_rotationThenFinalStepInOneBundle() public view {
        GrandpaLightClient.Step[] memory steps = new GrandpaLightClient.Step[](2);
        steps[0] = _step("b120", "votes", auth0);
        steps[1] = _step("b130", "votes", auth1);
        (ClprTypes.QueueMetadata memory m, bytes memory na,) = _verify(_bundle(steps), _anchor(0, auth0, 100));
        _assertServiceMetadata(m);
        assertEq(na, _anchor(1, auth1, 121));
    }

    function test_rotationWithDelayUsesHeaderChain() public view {
        GrandpaLightClient.Step memory s = _step("b142", "votes", auth1);
        s.headers = new bytes[](3);
        s.headers[0] = _b(".grandpa.b142.header");
        s.headers[1] = _b(".grandpa.b141.header");
        s.headers[2] = _b(".grandpa.b140.header");
        (, bytes memory na,) = _verify(_bundle(_one(s)), _anchor(1, auth1, 121));
        // Signalled at #140 with delay 2 → enacted at #142 → set 2 from #143.
        assertEq(na, _anchor(2, auth2, 143));
        (ClprTypes.QueueMetadata memory m,,) = _verify(_bundle(_one(_step("b160", "votes", auth2))), na);
        _assertServiceMetadata(m);
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function _ledgerConfig(string memory chainId, address svc, uint96 nanos) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(svc);
        lc.nanosSinceEpoch = nanos;
        lc.throttles = ClprTypes.Throttles(10, 1024, 1_000_000, 100, 4096, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(bytes memory ledger) internal view returns (bytes memory) {
        return abi.encode(GrandpaVerifier.ConfigProof(_one(_step("b100", "votes", auth0)), nodes, ledger));
    }

    function test_verifyConfig() public view {
        uint96 nanos = uint96(vm.parseJsonUint(json, ".configNanos"));
        (
            bytes memory cctx,
            string memory chainId,
            bytes memory svc,
            uint96 peerNanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(_config(_ledgerConfig(CHAIN_ID, service, nanos)), channelId, _b(".manifestPreimage"));
        assertEq(cctx, ctx);
        assertEq(chainId, CHAIN_ID);
        assertEq(svc, abi.encodePacked(service));
        assertEq(peerNanos, nanos);
        assertEq(t.maxMessagesPerBundle, 10);
        assertEq(anchor, _anchor(0, auth0, 100));
        assertEq(anchorId, abi.encodePacked(uint64(0)));
        assertEq(man.version, 1);
    }

    function test_verifyConfig_withoutManifestIsUninitialized() public view {
        uint96 nanos = uint96(vm.parseJsonUint(json, ".configNanos"));
        (,,,,,,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyConfig(_config(_ledgerConfig(CHAIN_ID, service, nanos)), channelId, "");
        assertEq(man.version, 0);
    }

    function test_verifyConfig_wrongChainId() public {
        bytes memory p = _config(_ledgerConfig("eip155:1", service, uint96(vm.parseJsonUint(json, ".configNanos"))));
        vm.expectRevert(SubstrateEvmVerifierBase.ChainIdMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    function test_verifyConfig_wrongServiceAddress() public {
        bytes memory p =
            _config(_ledgerConfig(CHAIN_ID, address(0xdead), uint96(vm.parseJsonUint(json, ".configNanos"))));
        vm.expectRevert(SubstrateEvmVerifierBase.ServiceAddressSlotMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    function test_verifyConfig_wrongNanos() public {
        bytes memory p = _config(_ledgerConfig(CHAIN_ID, service, 1));
        vm.expectRevert(SubstrateEvmVerifierBase.ConfigNanosMismatch.selector);
        v.verifyConfig(p, channelId, "");
    }

    // ── negative: signatures / threshold / validator set ─────────────────────

    function test_rejects_badSignature() public {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        s.votes[102 + 40] ^= 0x01; // second vote's signature
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 1));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_belowThreshold() public {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        bytes memory two = new bytes(204);
        for (uint256 i; i < 204; ++i) {
            two[i] = s.votes[i];
        }
        s.votes = two;
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.GrandpaThresholdNotMet.selector, 2, 3));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_duplicateVote() public {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        bytes memory dup = abi.encodePacked(s.votes, _slice(s.votes, 204, 102)); // idx 2 twice
        s.votes = dup;
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLib.VotesNotSorted.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_authorityIndexOutOfRange() public {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        s.votes[204 + 1] = 0x09;
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLib.AuthorityIndexOutOfRange.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_wrongValidatorSet() public {
        bytes memory p = _bundle(_one(_step("b100", "votes", auth1)));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLightClient.AuthoritySetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_wrongSetIdReplay() public {
        // Same authorities, but the anchor claims set 5: the signed message binds set_id.
        bytes memory p = _bundle(_one(_step("b100", "votes", auth0)));
        bytes memory a = _anchor(5, auth0, 100);
        vm.expectRevert(abi.encodeWithSelector(GrandpaLib.InvalidGrandpaSignature.selector, 0));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_oldSetAfterRotation() public {
        // After 0 → 1 the anchor is set 1; a set-0 justification no longer matches.
        bytes memory p = _bundle(_one(_step("b100", "votes", auth0)));
        bytes memory a = _anchor(1, auth1, 121);
        vm.expectRevert(GrandpaLightClient.AuthoritySetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_staleBlock() public {
        bytes memory p = _bundle(_one(_step("b100", "votes", auth0)));
        bytes memory a = _anchor(0, auth0, 101);
        vm.expectRevert(SubstrateVerifierErrors.HeightTooOld.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_descendantVoteWithoutAncestry() public {
        GrandpaLightClient.Step memory s = _step("b100", "votes", auth0);
        s.votes = _b(".grandpa.b101.ancestryVotes");
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLib.InvalidPrecommitTarget.selector);
        v.verifyBundle(p, a, ctx);
    }

    // ── negative: header chain / set changes ─────────────────────────────────

    function test_rejects_forcedChange() public {
        bytes memory p = _bundle(_one(_step("b150", "votes", auth1)));
        bytes memory a = _anchor(1, auth1, 121);
        vm.expectRevert(SubstrateHeader.ForcedChangeUnsupported.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_brokenHeaderChain() public {
        GrandpaLightClient.Step memory s = _step("b142", "votes", auth1);
        s.headers = new bytes[](2);
        s.headers[0] = _b(".grandpa.b142.header");
        s.headers[1] = _b(".grandpa.b140.header");
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(1, auth1, 121);
        vm.expectRevert(GrandpaLightClient.BrokenHeaderChain.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_justifiedPastEnactment() public {
        GrandpaLightClient.Step memory s = _step("b143", "votes", auth1);
        s.headers = new bytes[](4);
        s.headers[0] = _b(".grandpa.b143.header");
        s.headers[1] = _b(".grandpa.b142.header");
        s.headers[2] = _b(".grandpa.b141.header");
        s.headers[3] = _b(".grandpa.b140.header");
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(1, auth1, 121);
        vm.expectRevert(GrandpaLightClient.JustifiedPastChange.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_chainWithoutChange() public {
        GrandpaLightClient.Step memory s = _step("b142", "votes", auth1);
        s.headers = new bytes[](2);
        s.headers[0] = _b(".grandpa.b142.header");
        s.headers[1] = _b(".grandpa.b141.header");
        bytes memory p = _bundle(_one(s));
        bytes memory a = _anchor(1, auth1, 121);
        vm.expectRevert(GrandpaLightClient.StepWithoutChange.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_intermediateStepWithoutChange() public {
        GrandpaLightClient.Step[] memory steps = new GrandpaLightClient.Step[](2);
        steps[0] = _step("b100", "votes", auth0);
        steps[1] = _step("b100", "votes", auth0);
        bytes memory p = _bundle(steps);
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLightClient.StepWithoutChange.selector);
        v.verifyBundle(p, a, ctx);
    }

    // ── negative: storage ────────────────────────────────────────────────────

    function test_rejects_tamperedStorageNode() public {
        bytes[] memory bad = nodes;
        bytes memory root = bad[bad.length - 1];
        root[root.length - 1] ^= 0x01;
        bytes memory p =
            abi.encode(GrandpaVerifier.BundleProof(_one(_step("b100", "votes", auth0)), bad, false, "", ""));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_otherChannelReadsEmpty() public view {
        // The slots come from channelId, never from the proof: another channel proves as empty.
        (ClprTypes.QueueMetadata memory m,,,,) = v.verifyBundle(
            _bundle(_one(_step("b100", "votes", auth0))),
            _anchor(0, auth0, 100),
            abi.encodePacked(bytes32(uint256(1)), service)
        );
        assertEq(m.nextMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
    }

    function test_rejects_wrongManifestPreimage() public {
        bytes memory p =
            abi.encode(GrandpaVerifier.BundleProof(_one(_step("b100", "votes", auth0)), nodes, false, "", hex"0802"));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(bytes4(keccak256("ManifestCommitmentMismatch()")));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_lastMessageSlotWithoutMessages() public {
        // Channel 1 has nextMessageId 0, so a 6th (last message) slot cannot exist.
        bytes memory p =
            abi.encode(GrandpaVerifier.BundleProof(_one(_step("b100", "votes", auth0)), nodes, true, "", ""));
        bytes memory a = _anchor(0, auth0, 100);
        bytes memory otherCtx = abi.encodePacked(bytes32(uint256(1)), service);
        vm.expectRevert(bytes4(keccak256("InvalidNextMessageId()")));
        v.verifyBundle(p, a, otherCtx);
    }

    // ── negative: shapes / profile ───────────────────────────────────────────

    function test_rejects_badAnchorLength() public {
        bytes memory p = _bundle(_one(_step("b100", "votes", auth0)));
        vm.expectRevert(GrandpaLightClient.InvalidTrustAnchor.selector);
        v.verifyBundle(p, hex"00", ctx);
    }

    function test_rejects_noSteps() public {
        bytes memory p = _bundle(new GrandpaLightClient.Step[](0));
        bytes memory a = _anchor(0, auth0, 100);
        vm.expectRevert(GrandpaLightClient.InvalidPayloadShape.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_constructor_rejectsBadProfile() public {
        vm.expectRevert(GrandpaLightClient.InvalidProfile.selector);
        new GrandpaVerifier(address(0), EVM, CHAIN_ID, 0, keccak256(auth0), 100);
        vm.expectRevert(SubstrateEvmVerifierBase.InvalidEvmProfile.selector);
        new GrandpaVerifier(address(ed), bytes16(0), CHAIN_ID, 0, keccak256(auth0), 100);
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[off + i];
        }
    }
}
