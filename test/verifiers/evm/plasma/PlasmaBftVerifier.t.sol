// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {PlasmaBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/plasma/PlasmaBftVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @notice PlasmaBftVerifier on LIVE Plasma mainnet data (test/verifiers/evm/plasma/fixtures, exported
///         from test/e2e/fixtures/plasma-live by relay/exportPlasmaForgeFixture.ts): real PlasmaBFT
///         consensus blocks from gossip, real BLS quorum certificates (EIP-2537 pairing, nothing
///         stubbed) and real MPT proofs for the stand-in service contract.
contract PlasmaBftVerifierTest is Test {
    struct QcData {
        uint256 proposer;
        uint256 height;
        uint256[] votes;
        bytes sig96;
        bytes sig256;
    }

    PlasmaBftVerifier internal verifier;
    string internal json;

    bytes32 internal root;
    uint64 internal height;
    bytes32 internal channelId;
    address internal target;
    bytes internal committee;
    bytes internal headerB;
    bytes internal stateBranch;
    bytes internal headerB1;
    bytes internal headerB2;
    QcData internal qc1;
    QcData internal qc2;
    bytes internal serviceAccountProof;
    bytes internal storageProof;
    bytes internal configSlotProof;

    bytes internal constant PAYLOAD = hex"c1a9c0ffee";

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/plasma/fixtures/plasma-mainnet.json"));
        root = vm.parseJsonBytes32(json, ".committeeRoot");
        height = uint64(vm.parseJsonUint(json, ".height"));
        channelId = vm.parseJsonBytes32(json, ".channelId");
        target = vm.parseJsonAddress(json, ".target");
        committee = vm.parseJsonBytes(json, ".committee");
        headerB = vm.parseJsonBytes(json, ".headerB");
        stateBranch = vm.parseJsonBytes(json, ".stateBranch");
        headerB1 = vm.parseJsonBytes(json, ".headerB1");
        headerB2 = vm.parseJsonBytes(json, ".headerB2");
        _loadQc(qc1, ".qc1");
        _loadQc(qc2, ".qc2");
        serviceAccountProof = vm.parseJsonBytes(json, ".serviceAccountProof");
        storageProof = vm.parseJsonBytes(json, ".storageProof");
        configSlotProof = vm.parseJsonBytes(json, ".configSlotProof");
        verifier = new PlasmaBftVerifier(_profile());
    }

    function _profile() internal view returns (PlasmaBftVerifier.Profile memory) {
        return PlasmaBftVerifier.Profile({
            chainId: vm.parseJsonString(json, ".chainId"), bootstrapCommitteeRoot: root, bootstrapHeight: height
        });
    }

    function _loadQc(QcData storage q, string memory k) internal {
        q.proposer = vm.parseJsonUint(json, string.concat(k, ".proposer"));
        q.height = vm.parseJsonUint(json, string.concat(k, ".height"));
        uint256[] memory v = vm.parseJsonUintArray(json, string.concat(k, ".votes"));
        for (uint256 i; i < v.length; ++i) {
            q.votes.push(v[i]);
        }
        q.sig96 = vm.parseJsonBytes(json, string.concat(k, ".sig96"));
        q.sig256 = vm.parseJsonBytes(json, string.concat(k, ".sig256"));
    }

    // ── Encoding helpers ─────────────────────────────────────────────────────

    function _anchor(bytes32 r, uint64 h) internal pure returns (bytes memory) {
        return abi.encodePacked(r, h);
    }

    function _ctx() internal view returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(target)})
        );
    }

    function _qcItem(QcData memory q) internal pure returns (bytes memory) {
        bytes[] memory votes = new bytes[](q.votes.length);
        for (uint256 i; i < q.votes.length; ++i) {
            votes[i] = RLP.encode(q.votes[i]);
        }
        bytes[] memory f = new bytes[](5);
        f[0] = RLP.encode(q.proposer);
        f[1] = RLP.encode(q.height);
        f[2] = RLP.encode(votes);
        f[3] = RLP.encode(q.sig96);
        f[4] = RLP.encode(q.sig256);
        return RLP.encode(f);
    }

    function _finality(
        bytes memory keys,
        bytes memory hb,
        bytes memory branch,
        bytes memory hb1,
        QcData memory a,
        QcData memory b
    ) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](6);
        f[0] = RLP.encode(keys);
        f[1] = RLP.encode(hb);
        f[2] = RLP.encode(branch);
        f[3] = RLP.encode(hb1);
        f[4] = _qcItem(a);
        f[5] = _qcItem(b);
        return RLP.encode(f);
    }

    function _liveFinality() internal view returns (bytes memory) {
        return _finality(committee, headerB, stateBranch, headerB1, qc1, qc2);
    }

    function _bundle(bytes memory finality) internal view returns (bytes memory) {
        bytes[] memory f = new bytes[](4);
        f[0] = finality;
        f[1] = serviceAccountProof;
        f[2] = storageProof;
        f[3] = RLP.encode(abi.encodePacked(hex"12", uint8(PAYLOAD.length), PAYLOAD));
        return RLP.encode(f);
    }

    function _verify(bytes memory finality) internal view {
        verifier.verifyBundle(_bundle(finality), _anchor(root, height), _ctx());
    }

    function _copy(QcData storage s) internal pure returns (QcData memory q) {
        q = s;
    }

    function _without(uint256[] memory v, uint256 drop) internal pure returns (uint256[] memory r) {
        r = new uint256[](v.length - 1);
        for (uint256 i; i < r.length; ++i) {
            r[i] = v[i < drop ? i : i + 1];
        }
    }

    function _flip(bytes memory b, uint256 at) internal pure returns (bytes memory r) {
        r = bytes.concat(b);
        r[at] = bytes1(uint8(r[at]) ^ 0x01);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Live data, real BLS
    // ═════════════════════════════════════════════════════════════════════════

    function test_live_verifyBundle_twoQcs_zeroedMetadata() public view {
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory naId,) =
            verifier.verifyBundle(_bundle(_liveFinality()), _anchor(root, height), _ctx());
        assertEq(m.nextMessageId, 0);
        assertEq(payloads.length, 1);
        assertEq(payloads[0], PAYLOAD);
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    function test_live_acceptsOlderAnchorHeight() public view {
        verifier.verifyBundle(_bundle(_liveFinality()), _anchor(root, height - 1000), _ctx());
    }

    function test_live_qcChainIsConsistent() public view {
        assertEq(qc1.height, height);
        assertEq(qc2.height, uint256(height) + 1);
        assertGe(qc1.votes.length, 7);
        assertEq(committee.length / 128, 10);
    }

    // ── Signatures and quorum ─────────────────────────────────────────────────

    function test_rejects_qc2SignatureFromOtherQc() public {
        QcData memory b = _copy(qc2);
        (b.sig96, b.sig256) = (qc1.sig96, qc1.sig256);
        vm.expectRevert(PlasmaBftVerifier.BlsSignatureInvalid.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_qc2VoterSwapped() public {
        // Same count, one voter replaced by a non-signer: the aggregate no longer matches.
        QcData memory b = _copy(qc2);
        uint256[] memory v = b.votes;
        assertEq(v[v.length - 1], 8);
        v[v.length - 1] = 9;
        b.votes = v;
        vm.expectRevert(PlasmaBftVerifier.BlsSignatureInvalid.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_belowQuorum() public {
        QcData memory b = _copy(qc2);
        b.votes = _without(b.votes, 0);
        vm.expectRevert(PlasmaBftVerifier.QuorumNotMet.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_duplicateVoter() public {
        QcData memory b = _copy(qc2);
        b.votes[1] = b.votes[0];
        vm.expectRevert(PlasmaBftVerifier.VotesNotIncreasing.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_voterOutOfRange() public {
        QcData memory b = _copy(qc2);
        b.votes[b.votes.length - 1] = 10;
        vm.expectRevert(PlasmaBftVerifier.VoterOutOfRange.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_sig96NotTheSignaturePoint() public {
        QcData memory b = _copy(qc2);
        b.sig96 = qc1.sig96;
        vm.expectRevert(PlasmaBftVerifier.SignatureEncodingMismatch.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_sig96InfinityFlag() public {
        QcData memory b = _copy(qc2);
        b.sig96[0] = bytes1(uint8(b.sig96[0]) | 0x40);
        vm.expectRevert(PlasmaBftVerifier.SignatureEncodingMismatch.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc1, b));
    }

    function test_rejects_qc1NotTheOneCarriedByB1() public {
        // Dropping a voter from QC1 changes its SSZ root, which B+1's header commits to.
        QcData memory a = _copy(qc1);
        a.votes = _without(a.votes, 0);
        vm.expectRevert(PlasmaBftVerifier.QcRootMismatch.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, a, qc2));
    }

    function test_rejects_qcReplayedAsQc1() public {
        // QC on B+1 offered as the QC on B: height and root no longer line up.
        vm.expectRevert(PlasmaBftVerifier.QcRootMismatch.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB1, qc2, qc2));
    }

    // ── Committee ─────────────────────────────────────────────────────────────

    function test_rejects_wrongCommitteeAnchor() public {
        vm.expectRevert(PlasmaBftVerifier.CommitteeRootMismatch.selector);
        verifier.verifyBundle(_bundle(_liveFinality()), _anchor(keccak256("other committee"), height), _ctx());
    }

    function test_rejects_committeeMissingAKey() public {
        bytes memory short = new bytes(committee.length - 128);
        for (uint256 i; i < short.length; ++i) {
            short[i] = committee[i];
        }
        vm.expectRevert(PlasmaBftVerifier.CommitteeRootMismatch.selector);
        _verify(_finality(short, headerB, stateBranch, headerB1, qc1, qc2));
    }

    function test_rejects_committeeNotSorted() public {
        bytes memory swapped = bytes.concat(committee);
        for (uint256 i; i < 128; ++i) {
            (swapped[i], swapped[128 + i]) = (committee[128 + i], committee[i]);
        }
        vm.expectRevert(PlasmaBftVerifier.CommitteeNotSorted.selector);
        _verify(_finality(swapped, headerB, stateBranch, headerB1, qc1, qc2));
    }

    function test_rejects_emptyCommittee() public {
        vm.expectRevert(PlasmaBftVerifier.InvalidCommittee.selector);
        _verify(_finality("", headerB, stateBranch, headerB1, qc1, qc2));
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    function test_rejects_tamperedStateBranch() public {
        vm.expectRevert(PlasmaBftVerifier.StateRootBranchMismatch.selector);
        _verify(_finality(committee, headerB, _flip(stateBranch, 0), headerB1, qc1, qc2));
    }

    function test_rejects_b1NotChildOfB() public {
        vm.expectRevert(PlasmaBftVerifier.NotChildOfCertifiedBlock.selector);
        _verify(_finality(committee, headerB, stateBranch, headerB2, qc1, qc2));
    }

    function test_rejects_tamperedHeaderB() public {
        // Any change to B's leaves changes hash(B), which B+1 names as its parent.
        vm.expectRevert(PlasmaBftVerifier.NotChildOfCertifiedBlock.selector);
        _verify(_finality(committee, _flip(headerB, 64), stateBranch, headerB1, qc1, qc2));
    }

    function test_rejects_badHeaderLength() public {
        vm.expectRevert(PlasmaBftVerifier.InvalidHeader.selector);
        _verify(_finality(committee, bytes.concat(headerB, bytes1(0)), stateBranch, headerB1, qc1, qc2));
    }

    // ── Anchor and freshness ──────────────────────────────────────────────────

    function test_rejects_staleHeight() public {
        vm.expectRevert(PlasmaBftVerifier.HeightTooOld.selector);
        verifier.verifyBundle(_bundle(_liveFinality()), _anchor(root, height + 1), _ctx());
    }

    function test_rejects_badAnchorLength() public {
        vm.expectRevert(PlasmaBftVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(_bundle(_liveFinality()), abi.encodePacked(root), _ctx());
    }

    function test_rejects_badPayloadShape() public {
        bytes[] memory f = new bytes[](3);
        f[0] = _liveFinality();
        f[1] = serviceAccountProof;
        f[2] = storageProof;
        vm.expectRevert(PlasmaBftVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(RLP.encode(f), _anchor(root, height), _ctx());
    }

    // ── ClprService storage ───────────────────────────────────────────────────

    function test_rejects_storageProofForOtherChannel() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: keccak256("other"), remoteServiceAddress: abi.encodePacked(target)})
        );
        vm.expectRevert();
        verifier.verifyBundle(_bundle(_liveFinality()), _anchor(root, height), ctx);
    }

    function test_rejects_serviceAccountProofForOtherAddress() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(address(0xbeef))})
        );
        vm.expectRevert();
        verifier.verifyBundle(_bundle(_liveFinality()), _anchor(root, height), ctx);
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    /// @dev ClprLedgerConfiguration{1: chain_id, 2: service_address(20)}.
    function _ledgerConfig(string memory chainId, address service) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"0a", uint8(bytes(chainId).length), chainId, hex"1214", service);
    }

    function _config(string memory chainId) internal view returns (bytes memory) {
        bytes[] memory f = new bytes[](4);
        f[0] = _liveFinality();
        f[1] = serviceAccountProof;
        f[2] = configSlotProof;
        f[3] = RLP.encode(_ledgerConfig(chainId, target));
        return RLP.encode(f);
    }

    /// @dev The finality and MPT path runs end to end on live data; the stand-in contract holds no
    ///      ClprService config, so the proven slot 25 cannot equal the declared address.
    function test_live_verifyConfig_provesSlot25_standInIsNotAClprService() public {
        vm.expectRevert(PlasmaBftVerifier.ServiceAddressSlotMismatch.selector);
        verifier.verifyConfig(_config("9745"), channelId, "");
    }

    function test_verifyConfig_rejects_otherChainId() public {
        vm.expectRevert(PlasmaBftVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(_config("9746"), channelId, "");
    }

    function test_verifyConfig_rejects_empty() public {
        vm.expectRevert(PlasmaBftVerifier.InvalidPayloadShape.selector);
        verifier.verifyConfig("", channelId, "");
    }

    function test_constructor_rejects_invalidProfile() public {
        PlasmaBftVerifier.Profile memory p = _profile();
        p.bootstrapCommitteeRoot = bytes32(0);
        vm.expectRevert(PlasmaBftVerifier.InvalidProfile.selector);
        new PlasmaBftVerifier(p);
    }

    // ── Gas ───────────────────────────────────────────────────────────────────

    function test_gas_liveBundle() public view {
        bytes memory proof = _bundle(_liveFinality());
        uint256 g = gasleft();
        verifier.verifyBundle(proof, _anchor(root, height), _ctx());
        g -= gasleft();
        assertLt(g, 15_000_000);
        assertLt(proof.length, 128 * 1024);
    }
}
