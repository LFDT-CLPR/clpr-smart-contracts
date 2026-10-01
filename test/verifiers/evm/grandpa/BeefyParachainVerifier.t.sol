// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BeefyLib} from "@hiero-ledger/clpr/libraries/proof/substrate/BeefyLib.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {BeefyParachainVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/BeefyParachainVerifier.sol";
import {SubstrateVerifierErrors} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateVerifierErrors.sol";

/// @notice BeefyParachainVerifier on the synthetic relay chain of fixtures/synthetic.json: 4-authority
///         BEEFY sets (secp256k1, threshold 3), multi-mountain MMRs, a relay header whose state holds
///         Paras::Heads(2034), and the parachain header above the ClprService trie. Live Polkadot →
///         Hydration data is covered by test/e2e/tests/verifiers/grandpa-live.spec.ts.
contract BeefyParachainVerifierTest is Test {
    string internal json;
    BeefyParachainVerifier internal v;

    bytes16 internal constant EVM = 0x1da53b775b270400e7e61ed5cbc5a146;
    string internal constant CHAIN_ID = "eip155:222222";
    uint32 internal constant PARA_ID = 2034;

    bytes[] internal relayProof;
    bytes[] internal paraProof;
    bytes internal ctx;
    address internal service;
    bytes32 internal channelId;
    BeefyLib.AuthoritySet internal set10;
    BeefyLib.AuthoritySet internal set11;
    BeefyLib.AuthoritySet internal set12;

    function setUp() public {
        json = vm.readFile("test/verifiers/evm/grandpa/fixtures/synthetic.json");
        relayProof = vm.parseJsonBytesArray(json, ".beefy.relayStateProof");
        paraProof = vm.parseJsonBytesArray(json, ".evm.nodes");
        service = vm.parseJsonAddress(json, ".service");
        channelId = vm.parseJsonBytes32(json, ".channelId");
        ctx = abi.encodePacked(channelId, service);
        set10 = _set("set10");
        set11 = _set("set11");
        set12 = _set("set12");
        v = new BeefyParachainVerifier(EVM, CHAIN_ID, PARA_ID, _b(".beefy.paraHeadKey"), _boot());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, key);
    }

    function _set(string memory name) internal view returns (BeefyLib.AuthoritySet memory s) {
        string memory p = string.concat(".beefy.sets.", name);
        s.id = uint64(vm.parseJsonUint(json, string.concat(p, ".id")));
        s.len = uint32(vm.parseJsonUint(json, string.concat(p, ".len")));
        s.root = vm.parseJsonBytes32(json, string.concat(p, ".root"));
    }

    function _boot() internal view returns (BeefyParachainVerifier.Anchor memory a) {
        a.current = set10;
        a.next = set11;
        a.minRelayBlock = 200;
    }

    function _anchor(BeefyLib.AuthoritySet memory c, BeefyLib.AuthoritySet memory n, uint32 minBlock)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(c.id, c.len, c.root, n.id, n.len, n.root, minBlock);
    }

    function _commit(string memory name, string memory addressesOf)
        internal
        view
        returns (BeefyParachainVerifier.Commit memory c)
    {
        string memory p = string.concat(".beefy.", name);
        c.commitment = _b(string.concat(p, ".commitment"));
        c.signers = _b(string.concat(p, ".signers"));
        c.signatures = _b(string.concat(p, ".signatures"));
        c.authorities = _b(string.concat(".beefy.addresses.", addressesOf));
        c.mmrLeaf = _b(string.concat(p, ".leaf"));
        c.mmrPath = vm.parseJsonBytes32Array(json, string.concat(p, ".path"));
        c.mmrPathSides = vm.parseJsonUint(json, string.concat(p, ".sides"));
    }

    function _one(BeefyParachainVerifier.Commit memory c)
        internal
        pure
        returns (BeefyParachainVerifier.Commit[] memory cs)
    {
        cs = new BeefyParachainVerifier.Commit[](1);
        cs[0] = c;
    }

    function _bundle(BeefyParachainVerifier.Commit[] memory cs, string memory relayHeader)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(BeefyParachainVerifier.BundleProof(cs, _b(relayHeader), relayProof, paraProof, false, "", ""));
    }

    function _typical() internal view returns (bytes memory) {
        return _bundle(_one(_commit("commitA", "set10")), ".beefy.relay205");
    }

    function _assertServiceMetadata(ClprTypes.QueueMetadata memory m) internal pure {
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 2);
        assertEq(m.sentRunningHash, keccak256("sentRunningHash"));
        assertEq(m.endpointManifestVersion, 1);
    }

    // ── happy paths ──────────────────────────────────────────────────────────

    function test_typicalBundle() public {
        bytes memory a = _anchor(set10, set11, 200);
        (ClprTypes.QueueMetadata memory m,, bytes memory na, bytes memory nid,) = v.verifyBundle(_typical(), a, ctx);
        _assertServiceMetadata(m);
        assertEq(na.length, 0);
        assertEq(nid.length, 0);
        uint256 g = gasleft();
        v.verifyBundle(_typical(), a, ctx);
        emit log_named_uint("verifyBundle gas, 3 BEEFY signatures", g - gasleft());
    }

    function test_rotationToNextSet() public view {
        (ClprTypes.QueueMetadata memory m,, bytes memory na, bytes memory nid,) = v.verifyBundle(
            _bundle(_one(_commit("commitB", "set11")), ".beefy.relay206"), _anchor(set10, set11, 200), ctx
        );
        _assertServiceMetadata(m);
        assertEq(na, _anchor(set11, set12, 207));
        assertEq(nid, abi.encodePacked(uint64(11)));
    }

    function test_rotationHopThenFinalCommit() public view {
        BeefyParachainVerifier.Commit[] memory cs = new BeefyParachainVerifier.Commit[](2);
        cs[0] = _commit("commitB", "set11"); // rotates 10 → 11
        cs[1] = _commit("commitB", "set11"); // now signed by the current set
        (,, bytes memory na,,) = v.verifyBundle(_bundle(cs, ".beefy.relay206"), _anchor(set10, set11, 200), ctx);
        assertEq(na, _anchor(set11, set12, 207));
    }

    function test_allSignaturesAccepted() public view {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signers = _b(".beefy.commitA.all.signers");
        c.signatures = _b(".beefy.commitA.all.signatures");
        (ClprTypes.QueueMetadata memory m,,,,) =
            v.verifyBundle(_bundle(_one(c), ".beefy.relay205"), _anchor(set10, set11, 200), ctx);
        _assertServiceMetadata(m);
    }

    function test_verifyConfig() public view {
        uint96 nanos = uint96(vm.parseJsonUint(json, ".configNanos"));
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = CHAIN_ID;
        lc.serviceAddress = abi.encodePacked(service);
        lc.nanosSinceEpoch = nanos;
        lc.throttles = ClprTypes.Throttles(10, 1024, 1_000_000, 100, 4096, 4, 4);
        bytes memory p = abi.encode(
            BeefyParachainVerifier.ConfigProof(
                _one(_commit("commitA", "set10")),
                _b(".beefy.relay205"),
                relayProof,
                paraProof,
                ClprProtobuf.encodeControlMessage(lc)
            )
        );
        (,, bytes memory svc, uint96 peerNanos,, bytes memory anchor,, ClprTypes.ClprEndpointManifest memory man) =
            v.verifyConfig(p, channelId, _b(".manifestPreimage"));
        assertEq(svc, abi.encodePacked(service));
        assertEq(peerNanos, nanos);
        assertEq(anchor, _anchor(set10, set11, 200));
        assertEq(man.version, 1);
    }

    // ── negative: signatures / sets ──────────────────────────────────────────

    function test_rejects_badSignature() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signatures[65 + 10] ^= 0x01;
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(abi.encodeWithSelector(BeefyLib.InvalidBeefySignature.selector, 1));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_signatureFromWrongSlot() public {
        // Claim the signature of validator 0 came from validator 3.
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signers = hex"70"; // 0111_0000: validators 1, 2, 3
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(abi.encodeWithSelector(BeefyLib.InvalidBeefySignature.selector, 1));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_belowThreshold() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signers = hex"c0"; // validators 0, 1
        bytes memory two = new bytes(130);
        for (uint256 i; i < 130; ++i) {
            two[i] = c.signatures[i];
        }
        c.signatures = two;
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(abi.encodeWithSelector(BeefyLib.BeefyThresholdNotMet.selector, 2, 3));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_signerBitPastSetLength() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signers = hex"e8"; // bit 4 set, set has 4 validators
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyLib.InvalidSignersBitfield.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_extraSignatures() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.signatures = abi.encodePacked(c.signatures, new bytes(65));
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyLib.InvalidSignaturesLength.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_wrongAuthorityList() public {
        bytes memory p = _bundle(_one(_commit("commitA", "set11")), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyLib.AuthoritySetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_unknownValidatorSet() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(set11, set12, 200);
        vm.expectRevert(abi.encodeWithSelector(BeefyParachainVerifier.UnknownValidatorSet.selector, 10));
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_staleCommitment() public {
        bytes memory p = _typical();
        bytes memory a = _anchor(set10, set11, 207);
        vm.expectRevert(SubstrateVerifierErrors.HeightTooOld.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_hopWithoutRotation() public {
        BeefyParachainVerifier.Commit[] memory cs = new BeefyParachainVerifier.Commit[](2);
        cs[0] = _commit("commitA", "set10");
        cs[1] = _commit("commitA", "set10");
        bytes memory p = _bundle(cs, ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyParachainVerifier.CommitWithoutRotation.selector);
        v.verifyBundle(p, a, ctx);
    }

    // ── negative: MMR / relay / para ─────────────────────────────────────────

    function test_rejects_tamperedLeaf() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.mmrLeaf[100] ^= 0x01;
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyLib.MmrProofMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_leafNotForCommitmentBlock() public {
        BeefyParachainVerifier.Commit memory c = _commit("commitA", "set10");
        c.mmrLeaf = _b(".beefy.mmrInner.leaf");
        c.mmrPath = vm.parseJsonBytes32Array(json, ".beefy.mmrInner.path");
        c.mmrPathSides = vm.parseJsonUint(json, ".beefy.mmrInner.sides");
        bytes memory p = _bundle(_one(c), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyParachainVerifier.LeafNotForCommitmentBlock.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_leafWithWrongNextSet() public {
        bytes memory p = _bundle(_one(_commit("commitC", "set10")), ".beefy.relay205");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyParachainVerifier.LeafNextSetMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_relayHeaderNotLeafParent() public {
        bytes memory p = _bundle(_one(_commit("commitA", "set10")), ".beefy.relay206");
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyParachainVerifier.RelayHeaderMismatch.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_paraHeadAbsent() public {
        BeefyParachainVerifier other =
            new BeefyParachainVerifier(EVM, CHAIN_ID, 1001, _b(".beefy.absentParaHeadKey"), _boot());
        bytes memory p = _typical();
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectRevert(BeefyParachainVerifier.ParaHeadNotFound.selector);
        other.verifyBundle(p, a, ctx);
    }

    function test_rejects_tamperedParaProof() public {
        bytes[] memory bad = paraProof;
        bytes memory root = bad[bad.length - 1];
        root[3] ^= 0x01;
        bytes memory p = abi.encode(
            BeefyParachainVerifier.BundleProof(
                _one(_commit("commitA", "set10")), _b(".beefy.relay205"), relayProof, bad, false, "", ""
            )
        );
        bytes memory a = _anchor(set10, set11, 200);
        vm.expectPartialRevert(SubstrateTrie.MissingProofNode.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_rejects_badAnchor() public {
        bytes memory p = _typical();
        // next.id must be current.id + 1
        bytes memory a = _anchor(set10, set12, 200);
        vm.expectRevert(BeefyParachainVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(p, a, ctx);
    }

    function test_constructor_rejectsKeyForOtherPara() public {
        bytes memory key = _b(".beefy.paraHeadKey");
        BeefyParachainVerifier.Anchor memory boot = _boot();
        vm.expectRevert(BeefyParachainVerifier.InvalidProfile.selector);
        new BeefyParachainVerifier(EVM, CHAIN_ID, 2035, key, boot);
    }
}
