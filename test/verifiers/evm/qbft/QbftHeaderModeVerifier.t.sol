// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftVerifierBase.sol";
import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {QbftValidators} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftHeaderModeProofBuilders} from "@test/verifiers/evm/qbft/QbftHeaderModeProofBuilders.sol";

contract QbftHeaderModeVerifierTest is QbftHeaderModeProofBuilders {
    QbftHeaderModeVerifier internal v;

    /// @dev The decoded header-mode anchor, read word by word (a tuple decode is too deep for the
    ///      --ir-minimum coverage build once the test's own locals are added).
    struct DecodedAnchor {
        uint8 mode;
        bytes32 setCommitment;
        bytes32 codeHash;
        uint64 anchorBlockNumber;
    }

    function setUp() public {
        v = new QbftHeaderModeVerifier();
    }

    // ── steady state ─────────────────────────────────────────────────────────

    function test_steadyState_noRotation() public view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("hm", 3);
        (ClprTypes.QueueMetadata memory meta,, bytes memory newAnchor, bytes memory newId,) =
            v.verifyBundle(proof, anchor, _syntheticChannelContext());
        assertEq(meta.nextMessageId, 0, "synthetic channel slots prove zero");
        assertEq(newAnchor.length, 0, "no rotation: anchor unchanged");
        assertEq(newId.length, 0);
    }

    function test_steadyState_singleValidator() public view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("one", 1);
        v.verifyBundle(proof, anchor, _syntheticChannelContext());
    }

    // ── the rotation rule: one change, sealed by the old set ─────────────────

    /// @dev {a, b} -> {a, b, c}, the change block sealed by a and c: quorum(2) - 1 = 1 old signer
    ///      plus the newcomer. This is the block Besu produces when c joins, and it is accepted.
    function test_addition_oneOldSignerAndNewcomer_rotates() public view {
        address[] memory old = _setN("ab", 2); // a = member 0, b = member 1
        address[] memory grown = _setN("ab", 3); // + c = member 2
        uint256[] memory aAndC = new uint256[](2);
        aAndC[0] = _pksN("ab", 3)[0];
        aAndC[1] = _pksN("ab", 3)[2];

        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(grown, aAndC, 300);
        HeaderBlock memory b = _currentBlock(grown, aAndC, 301);
        (,, bytes memory newAnchor, bytes memory newId,) =
            v.verifyBundle(_topProof(b, old, hops), _headerAnchor(old, 0), _syntheticChannelContext());
        DecodedAnchor memory a = _decodeAnchor(newAnchor);
        assertEq(a.setCommitment, _commit(grown), "commitment of the new set");
        assertEq(a.anchorBlockNumber, 301);
        assertEq(newId, abi.encodePacked(uint64(301)));
    }

    /// @dev {a, b, c} -> {a, b, c, d} sealed by a only: with d silent the full old quorum (2) is
    ///      required, and one old signer is not enough.
    function test_addition_newcomerSilent_oneOldSigner_reverts() public {
        address[] memory old = _setN("sil", 3);
        address[] memory grown = _setN("sil", 4);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(grown, _pksN("sil", 1), 300);
        HeaderBlock memory b = _currentBlock(grown, _pksN("sil", 3), 301);
        bytes memory proof = _topProof(b, old, hops);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TrustLinkNotReached.selector, 1, 2));
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev {a, b, c} -> {a, b, c, d} sealed by a, b, c: the newcomer is silent but a full old
    ///      quorum signed, and a, b, c are also quorum(4) of the new list.
    function test_addition_newcomerSilent_fullOldQuorum_rotates() public view {
        address[] memory old = _setN("full", 3);
        address[] memory grown = _setN("full", 4);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(grown, _pksN("full", 3), 300);
        HeaderBlock memory b = _currentBlock(grown, _pksN("full", 3), 301);
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_topProof(b, old, hops), _headerAnchor(old, 0), _syntheticChannelContext());
        assertEq(_decodeAnchor(newAnchor).setCommitment, _commit(grown));
    }

    /// @dev {a, b, c, d} -> {a, b, c} sealed by a and b: 2 = quorum(4) - 1 old signers, and a
    ///      quorum of the remaining three.
    function test_removal_quorumMinusOne_rotates() public view {
        address[] memory old = _setN("rm", 4);
        address[] memory shrunk = _setN("rm", 3);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(shrunk, _pksN("rm", 2), 300);
        HeaderBlock memory b = _currentBlock(shrunk, _pksN("rm", 2), 301);
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_topProof(b, old, hops), _headerAnchor(old, 0), _syntheticChannelContext());
        assertEq(_decodeAnchor(newAnchor).setCommitment, _commit(shrunk));
    }

    /// @dev {a, b, c} -> {a, b} sealed by a only: one old signer is enough for the old side, but the
    ///      remaining list needs quorum(2) = 2.
    function test_removal_listedQuorumNotReached_reverts() public {
        address[] memory old = _setN("rm2", 3);
        address[] memory shrunk = _setN("rm2", 2);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(shrunk, _pksN("rm2", 1), 300);
        HeaderBlock memory b = _currentBlock(shrunk, _pksN("rm2", 2), 301);
        bytes memory proof = _topProof(b, old, hops);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 1, 2));
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev {a} -> {a, b}: the single trusted validator must still sign (the floor of one signer).
    function test_addition_fromSingleValidator_rotates() public view {
        address[] memory old = _setN("one2", 1);
        address[] memory grown = _setN("one2", 2);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(grown, _pksN("one2", 2), 300);
        HeaderBlock memory b = _currentBlock(grown, _pksN("one2", 2), 301);
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_topProof(b, old, hops), _headerAnchor(old, 0), _syntheticChannelContext());
        assertEq(_decodeAnchor(newAnchor).setCommitment, _commit(grown));
    }

    /// @dev {a, b} -> {a, c, d}: two members joined and one left in a single header. Besu never
    ///      produces this, so the header is rejected before any seal is recovered.
    function test_twoChangesAtOnce_reverts() public {
        address[] memory old = _setN("acd", 2);
        address[] memory next = new address[](3);
        next[0] = old[0];
        next[1] = vm.addr(uint256(keccak256("c")));
        next[2] = vm.addr(uint256(keccak256("d")));
        uint256[] memory cAndD = new uint256[](2);
        cAndD[0] = uint256(keccak256("c"));
        cAndD[1] = uint256(keccak256("d"));

        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(next, cAndD, 300);
        HeaderBlock memory b = _currentBlock(next, cAndD, 301);
        bytes memory proof = _topProof(b, old, hops);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TooManySetChanges.selector, 2, 1));
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev {a, b, c} -> {a, b, d}: a swap is two changes.
    function test_swap_reverts() public {
        address[] memory old = _setN("swap", 3);
        address[] memory next = _setN("swap", 3);
        next[2] = vm.addr(uint256(keccak256("replacement")));
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(next, _pksN("swap", 2), 300);
        HeaderBlock memory b = _currentBlock(next, _pksN("swap", 2), 301);
        bytes memory proof = _topProof(b, old, hops);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TooManySetChanges.selector, 1, 1));
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev The current header itself may carry the one change: no hop is needed for a single
    ///      change block that is also the block being verified.
    function test_currentHeader_carriesTheChange_rotates() public view {
        address[] memory old = _setN("cur", 3);
        address[] memory grown = _setN("cur", 4);
        HeaderBlock memory b = _currentBlock(grown, _pksN("cur", 4), 301);
        (,, bytes memory newAnchor, bytes memory newId,) =
            v.verifyBundle(_topProof(b, old, new bytes[](0)), _headerAnchor(old, 0), _syntheticChannelContext());
        assertEq(_decodeAnchor(newAnchor).setCommitment, _commit(grown));
        assertEq(newId, abi.encodePacked(uint64(301)));
    }

    function test_currentHeader_ownQuorumNotReached_reverts() public {
        address[] memory set = _setN("q", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("q", 1), 10); // 1 of 3 sealed; quorum is 2
        bytes memory proof = _topProof(b, set, new bytes[](0));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 1, 2));
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev A hop sealed by a full quorum of a set the verifier never trusted: three members changed
    ///      at once, so an attacker-invented set cannot take over the channel.
    function test_hop_inventedSet_reverts() public {
        address[] memory trusted = _setN("real", 3);
        address[] memory fake = _setN("fake", 3);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(fake, _pksN("fake", 3), 300);
        HeaderBlock memory b = _currentBlock(fake, _pksN("fake", 3), 301);
        bytes memory proof = _topProof(b, trusted, hops);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.TooManySetChanges.selector, 3, 3));
        v.verifyBundle(proof, _headerAnchor(trusted, 0), _syntheticChannelContext());
    }

    // ── hops and anchors ─────────────────────────────────────────────────────

    function test_rotation_viaHop_updatesAnchor() public view {
        (bytes memory proof, bytes memory anchor) = _rotationScenario("rot", 3);
        (,, bytes memory newAnchor, bytes memory newId,) = v.verifyBundle(proof, anchor, _syntheticChannelContext());
        DecodedAnchor memory a = _decodeAnchor(newAnchor);
        assertEq(a.mode, 0);
        assertEq(a.setCommitment, _commit(_setN("rot", 4)), "commitment of the set the current header lists");
        assertEq(a.codeHash, SERVICE_CODE_HASH);
        assertEq(a.anchorBlockNumber, 301);
        assertEq(newId, abi.encodePacked(uint64(301)));
    }

    /// @dev Two hops in one bundle: 3 -> 4 -> 5, each change block sealed by a quorum of its own list
    ///      drawn from the previous set. Two changes need two hops.
    function test_rotation_twoHops() public view {
        address[] memory s3 = _setN("multi", 3);
        address[] memory s4 = _setN("multi", 4);
        address[] memory s5 = _setN("multi", 5);
        bytes[] memory hops = new bytes[](2);
        hops[0] = _hopHeader(s4, _pksN("multi", 3), 200);
        hops[1] = _hopHeader(s5, _pksN("multi", 4), 250);
        HeaderBlock memory b = _currentBlock(s5, _pksN("multi", 4), 260);
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_topProof(b, s3, hops), _headerAnchor(s3, 100), _syntheticChannelContext());
        assertEq(_decodeAnchor(newAnchor).setCommitment, _commit(s5));
    }

    /// @dev A hop that lists the same set again advances the anchor floor without changing the set.
    function test_hop_sameSet_advancesFloorOnly() public view {
        address[] memory set = _setN("floor", 3);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(set, _pksN("floor", 2), 200);
        HeaderBlock memory b = _currentBlock(set, _pksN("floor", 2), 400);
        (,, bytes memory newAnchor, bytes memory newId,) =
            v.verifyBundle(_topProof(b, set, hops), _headerAnchor(set, 100), _syntheticChannelContext());
        DecodedAnchor memory a = _decodeAnchor(newAnchor);
        assertEq(a.setCommitment, _commit(set), "commitment stays");
        assertEq(a.anchorBlockNumber, 400, "floor advanced");
        assertEq(newId, abi.encodePacked(uint64(400)));
    }

    function test_hop_notAscending_reverts() public {
        address[] memory set = _setN("asc", 3);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(set, _pksN("asc", 2), 100); // not after the anchor block 100
        HeaderBlock memory b = _currentBlock(set, _pksN("asc", 2), 101);
        bytes memory proof = _topProof(b, set, hops);
        vm.expectRevert(abi.encodeWithSelector(QbftVerifierBase.HandoffHeaderNotAscending.selector, 100, 100));
        v.verifyBundle(proof, _headerAnchor(set, 100), _syntheticChannelContext());
    }

    function test_currentHeader_behindWalk_reverts() public {
        address[] memory set = _setN("behind", 3);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(set, _pksN("behind", 2), 300);
        HeaderBlock memory b = _currentBlock(set, _pksN("behind", 2), 300); // not after the hop
        bytes memory proof = _topProof(b, set, hops);
        vm.expectRevert(abi.encodeWithSelector(QbftVerifierBase.CurrentHeaderBehindWalk.selector, 300, 300));
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    // ── the trusted set ──────────────────────────────────────────────────────

    /// @dev No rotation: the relay may send the trusted set as an empty list. The current header's
    ///      own list stands in for it and hashes to the anchor.
    function test_omittedTrustedSet_steadyState_accepted() public view {
        address[] memory set = _setN("omit", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("omit", 2), 10);
        (ClprTypes.QueueMetadata memory meta,, bytes memory newAnchor,,) = v.verifyBundle(
            _topProof(b, new address[](0), new bytes[](0)), _headerAnchor(set, 0), _syntheticChannelContext()
        );
        assertEq(meta.nextMessageId, 0);
        assertEq(newAnchor.length, 0, "no rotation");
    }

    /// @dev The header lists a changed set: the stand-in list does not hash to the anchor.
    function test_omittedTrustedSet_headerListsChangedSet_reverts() public {
        address[] memory old = _setN("omit2", 3);
        address[] memory grown = _setN("omit2", 4);
        HeaderBlock memory b = _currentBlock(grown, _pksN("omit2", 3), 10);
        bytes memory proof = _topProof(b, new address[](0), new bytes[](0));
        vm.expectRevert(
            abi.encodeWithSelector(QbftVerifierBase.WrongSetCommitment.selector, _commit(grown), _commit(old))
        );
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev Hops need the trusted set: with it omitted, the current header lists the post-rotation
    ///      set, which cannot hash to the anchor.
    function test_omittedTrustedSet_withHops_reverts() public {
        address[] memory old = _setN("omit3", 3);
        address[] memory grown = _setN("omit3", 4);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(grown, _pksN("omit3", 3), 300);
        HeaderBlock memory b = _currentBlock(grown, _pksN("omit3", 3), 301);
        bytes memory proof = _topProof(b, new address[](0), hops);
        vm.expectRevert(
            abi.encodeWithSelector(QbftVerifierBase.WrongSetCommitment.selector, _commit(grown), _commit(old))
        );
        v.verifyBundle(proof, _headerAnchor(old, 0), _syntheticChannelContext());
    }

    /// @dev Only an empty list is the shortcut; an empty byte string is a malformed trusted set.
    function test_trustedSetEmptyString_reverts() public {
        address[] memory set = _setN("omit4", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("omit4", 2), 10);
        bytes[] memory source = new bytes[](2);
        source[0] = RLP.encode(new bytes(0));
        source[1] = RLP.encode(new bytes[](0));
        bytes[] memory top = new bytes[](5);
        top[0] = b.header;
        top[1] = RLP.encode(source);
        top[2] = b.svcAccountProof;
        top[3] = b.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        vm.expectRevert(QbftVerifierBase.InvalidTrustedSet.selector);
        v.verifyBundle(RLP.encode(top), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_wrongSetCommitment_reverts() public {
        address[] memory set = _setN("wc", 3);
        address[] memory other = _setN("other", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("wc", 2), 10);
        bytes memory proof = _topProof(b, other, new bytes[](0));
        vm.expectRevert(
            abi.encodeWithSelector(QbftVerifierBase.WrongSetCommitment.selector, _commit(other), _commit(set))
        );
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_headerListsNoValidators_reverts() public {
        address[] memory set = _setN("empty", 3);
        HeaderBlock memory b = _currentBlock(new address[](0), _pksN("empty", 2), 10);
        bytes memory proof = _topProof(b, set, new bytes[](0));
        vm.expectRevert(ClprQbftQuorum.EmptyValidatorSet.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev A validator item that is not an address (a 4-byte string) makes the header invalid.
    function test_headerValidatorNotAnAddress_reverts() public {
        address[] memory set = _setN("badv", 2);
        bytes[] memory vItems = new bytes[](2);
        vItems[0] = RLP.encode(set[0]);
        vItems[1] = RLP.encode(bytes(hex"deadbeef"));
        bytes memory header = _sealedHeaderWithValidatorItems(10, RLP.encode(vItems), _pksN("badv", 2));
        bytes memory proof = _topWithHeader(header, set);
        vm.expectRevert(QbftVerifierBase.InvalidHeader.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev The RLP empty string is the zero address in transaction encoding, never a validator:
    ///      only the fixed 21-byte item is an address here.
    function test_headerValidatorEmptyString_reverts() public {
        address[] memory set = _setN("emptyv", 2);
        bytes[] memory vItems = new bytes[](2);
        vItems[0] = RLP.encode(set[0]);
        vItems[1] = hex"80";
        bytes memory header = _sealedHeaderWithValidatorItems(10, RLP.encode(vItems), _pksN("emptyv", 2));
        bytes memory proof = _topWithHeader(header, set);
        vm.expectRevert(QbftVerifierBase.InvalidHeader.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev A canonically encoded zero address is still not a validator: it can never seal, so a
    ///      list carrying it is rejected rather than trusted with an inflated quorum.
    function test_headerValidatorZeroAddress_reverts() public {
        address[] memory set = _setN("zerov", 2);
        address[] memory listed = new address[](3);
        listed[0] = set[0];
        listed[1] = address(0);
        listed[2] = set[1];
        HeaderBlock memory b = _currentBlock(listed, _pksN("zerov", 2), 10);
        bytes memory proof = _topProof(b, set, new bytes[](0));
        vm.expectRevert(QbftVerifierBase.InvalidHeader.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev Same two rules for the relay-supplied trusted set (field 1 item 0).
    function test_trustedSetMemberEmptyString_reverts() public {
        address[] memory set = _setN("emptyt", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("emptyt", 2), 10);
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(set[0]);
        items[1] = hex"80";
        items[2] = RLP.encode(set[2]);
        bytes[] memory source = new bytes[](2);
        source[0] = RLP.encode(items);
        source[1] = RLP.encode(new bytes[](0));
        bytes[] memory top = new bytes[](5);
        top[0] = b.header;
        top[1] = RLP.encode(source);
        top[2] = b.svcAccountProof;
        top[3] = b.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        vm.expectRevert(QbftVerifierBase.InvalidTrustedSet.selector);
        v.verifyBundle(RLP.encode(top), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_trustedSetMemberZeroAddress_reverts() public {
        address[] memory set = _setN("zerot", 2);
        address[] memory trusted = new address[](3);
        trusted[0] = set[0];
        trusted[1] = address(0);
        trusted[2] = set[1];
        HeaderBlock memory b = _currentBlock(set, _pksN("zerot", 2), 10);
        bytes memory proof = _topProof(b, trusted, new bytes[](0));
        vm.expectRevert(QbftVerifierBase.InvalidTrustedSet.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    // ── shapes ───────────────────────────────────────────────────────────────

    function test_payloadNotFiveOrSevenItems_reverts() public {
        address[] memory set = _setN("shape", 1);
        vm.expectRevert(QbftVerifierBase.InvalidPayloadShape.selector);
        v.verifyBundle(hex"c0", _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_sourceNotTwoItems_reverts() public {
        address[] memory set = _setN("src", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("src", 2), 10);
        bytes[] memory top = new bytes[](5);
        top[0] = b.header;
        top[1] = RLP.encode(_singleton(_memberListRlp(set))); // 1 item, hops missing
        top[2] = b.svcAccountProof;
        top[3] = b.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        vm.expectRevert(QbftVerifierBase.InvalidPayloadShape.selector);
        v.verifyBundle(RLP.encode(top), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_headerTooFewOrTooManyFields_reverts() public {
        address[] memory set = _setN("hf", 1);
        vm.expectRevert(QbftVerifierBase.InvalidHeader.selector);
        v.verifyBundle(_topWithHeader(_emptyHeader(14), set), _headerAnchor(set, 0), _syntheticChannelContext());
        vm.expectRevert(QbftVerifierBase.InvalidHeader.selector);
        v.verifyBundle(_topWithHeader(_emptyHeader(23), set), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_extraDataNotFiveItems_reverts() public {
        address[] memory set = _setN("ed", 1);
        bytes[] memory extra = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) {
            extra[i] = hex"80";
        }
        bytes memory header = _buildHeaderAtNumber(10, bytes32(0), RLP.encode(extra));
        vm.expectRevert(ClprQbftSeal.InvalidExtraData.selector);
        v.verifyBundle(_topWithHeader(header, set), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_noSeals_reverts() public {
        address[] memory set = _setN("ns", 1);
        bytes memory header = _buildListedSealedHeader(10, bytes32(0), set, new uint256[](0));
        vm.expectRevert(ClprQbftQuorum.EmptySeals.selector);
        v.verifyBundle(_topWithHeader(header, set), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    function test_sealWrongLength_reverts() public {
        address[] memory set = _setN("sl", 1);
        bytes[] memory seals = new bytes[](1);
        seals[0] = hex"0102030405";
        bytes memory header = _buildHeaderAtNumber(10, bytes32(0), _buildExtraDataListing(set, seals, 0));
        vm.expectRevert(abi.encodeWithSelector(ClprQbftSeal.SealLengthMismatch.selector, 5));
        v.verifyBundle(_topWithHeader(header, set), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    // ── the trust anchor ─────────────────────────────────────────────────────

    function test_trustAnchorWrongLength_reverts() public {
        vm.expectRevert(QbftVerifierBase.InvalidTrustAnchor.selector);
        v.verifyBundle(hex"c0", hex"deadbeef", _syntheticChannelContext());
        // A contract-mode anchor (224 bytes) is not this verifier's.
        vm.expectRevert(QbftVerifierBase.InvalidTrustAnchor.selector);
        v.verifyBundle(hex"c0", new bytes(224), _syntheticChannelContext());
    }

    function test_trustAnchorWrongMode_reverts() public {
        bytes memory anchor = abi.encode(uint8(1), bytes32(0), SERVICE_CODE_HASH, uint64(0));
        vm.expectRevert(abi.encodeWithSelector(QbftVerifierBase.UnknownValidatorMode.selector, 1));
        v.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    // ── the storage tail ─────────────────────────────────────────────────────

    function test_codeHashMismatch_reverts() public {
        address[] memory set = _setN("ch", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("ch", 2), 10);
        bytes memory proof = _topProof(b, set, new bytes[](0));
        bytes memory anchor = abi.encode(uint8(0), _commit(set), bytes32(uint256(0xBAD)), uint64(0));
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v.verifyBundle(proof, anchor, _syntheticChannelContext());
    }

    function test_storageProofForOtherChannel_reverts() public {
        address[] memory set = _setN("oc", 3);
        HeaderBlock memory b = _currentBlock(set, _pksN("oc", 2), 10);
        bytes memory proof = _topProof(b, set, new bytes[](0));
        bytes32 attackerId = bytes32(uint256(0xDEADBEEF));
        bytes memory attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attackerId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerId, uint256(15)))) + 1);
        vm.expectRevert(abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot));
        v.verifyBundle(proof, _headerAnchor(set, 0), attackerContext);
    }

    function test_storageCountWrong_reverts() public {
        address[] memory set = _setN("sc", 3);
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildZeroStorageProof(3);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes[] memory top = new bytes[](5);
        top[0] = _buildListedSealedHeader(10, stateRoot, set, _pksN("sc", 2));
        top[1] = _headerSourceField(set, new bytes[](0));
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));
        vm.expectRevert(ClprEvmBundleVerifier.InvalidStorageProofShape.selector);
        v.verifyBundle(RLP.encode(top), _headerAnchor(set, 0), _syntheticChannelContext());
    }

    /// @dev The 7-field shape: the manifest commitment slot is proven and the preimage returned.
    function test_manifestBundle_returnedAndBound() public view {
        address[] memory set = _setN("mf", 3);
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));
        (,,,, ClprTypes.ClprEndpointManifest memory m) =
            v.verifyBundle(_manifestBundle("mf", preimage), _headerAnchor(set, 0), _syntheticChannelContext());
        assertEq(m.version, 3);
        assertEq(m.endpoints.length, 1);
        assertEq(keccak256(m.serviceAddress), keccak256(abi.encodePacked(SERVICE_ADDR)));
    }

    function test_manifestBundle_wrongServiceAddress_reverts() public {
        address[] memory set = _setN("mf2", 3);
        bytes memory proof = _manifestBundle("mf2", _manifestPreimage(hex"BEEF"));
        vm.expectRevert(ClprEvmBundleVerifier.ManifestServiceAddressMismatch.selector);
        v.verifyBundle(proof, _headerAnchor(set, 0), _syntheticChannelContext());
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function test_verifyConfig_success_pinsListedSet() public view {
        address[] memory set = _setN("cfg", 3);
        bytes memory configProof = _configScenario("cfg");
        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
        ) = v.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, "");

        assertEq(chainId, "eip155:1");
        assertEq(serviceAddress, abi.encodePacked(SERVICE_ADDR));
        assertEq(peerConfigNanos, 0);
        assertEq(throttles.maxMessagesPerBundle, 0);
        DecodedAnchor memory a = _decodeAnchor(initialTrustAnchor);
        assertEq(a.mode, 0);
        assertEq(a.setCommitment, _commit(set), "the header's own list is the initial set");
        assertEq(a.codeHash, SERVICE_CODE_HASH);
        assertEq(a.anchorBlockNumber, 500);
        assertEq(initialTrustAnchorId, abi.encodePacked(uint64(500)));
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        assertEq(ctx.channelId, SYNTHETIC_CHANNEL_ID);
    }

    function test_verifyConfig_headerNotSealedByItsOwnList_reverts() public {
        address[] memory set = _setN("cfgq", 3);
        bytes memory header = _buildListedSealedHeader(500, bytes32(0), set, _pksN("cfgq", 1)); // 1 of 3
        bytes memory configProof = _buildHeaderModeConfigProof(header, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1");
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.QuorumNotReached.selector, 1, 2));
        v.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, "");
    }

    function test_verifyConfig_shapeErrors() public {
        vm.expectRevert(QbftVerifierBase.InvalidPayloadShape.selector);
        v.verifyConfig("", bytes32(0), "");
        vm.expectRevert(QbftVerifierBase.InvalidProofPayloadShape.selector);
        v.verifyConfig(hex"c180", bytes32(0), "");
    }

    function test_verifyConfig_headerTooShort_reverts() public {
        bytes memory configProof =
            _buildHeaderModeConfigProof(_emptyHeader(14), SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1");
        vm.expectRevert(QbftVerifierBase.InvalidConfigHeader.selector);
        v.verifyConfig(configProof, bytes32(0), "");
    }

    /// @dev The old 8-field layout (reserved field and epoch length appended) is not accepted.
    function test_verifyConfig_wrongFieldCount_reverts() public {
        Memory.Slice[] memory items = RLP.decodeList(_configScenario("cnt"));
        bytes[] memory eight = new bytes[](8);
        for (uint256 i = 0; i < 5; i++) {
            eight[i] = Memory.toBytes(items[i]);
        }
        eight[5] = RLP.encode(new bytes(0));
        eight[6] = Memory.toBytes(items[5]);
        eight[7] = RLP.encode(uint256(30000));
        vm.expectRevert(QbftVerifierBase.InvalidProofPayloadShape.selector);
        v.verifyConfig(RLP.encode(eight), bytes32(0), "");
    }

    function test_verifyConfig_descriptorErrors() public {
        bytes memory configProof = _configScenario("desc");

        bytes[] memory three = new bytes[](3);
        three[0] = RLP.encode(uint256(0));
        three[1] = RLP.encode(SERVICE_CODE_HASH);
        three[2] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        vm.expectRevert(QbftVerifierBase.InvalidTrustAnchorFields.selector);
        v.verifyConfig(_replaceConfigField(configProof, 4, RLP.encode(RLP.encode(three))), bytes32(0), "");

        bytes[] memory contractMode = _descriptor(1);
        vm.expectRevert(abi.encodeWithSelector(QbftVerifierBase.UnknownValidatorMode.selector, 1));
        v.verifyConfig(_replaceConfigField(configProof, 4, RLP.encode(RLP.encode(contractMode))), bytes32(0), "");
    }

    function test_verifyConfig_throttles() public {
        bytes memory configProof = _configScenario("thr");

        bytes[] memory six = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            six[i] = hex"80";
        }
        vm.expectRevert(QbftVerifierBase.InvalidConfigThrottleFieldCount.selector);
        v.verifyConfig(_replaceConfigField(configProof, 3, RLP.encode(six)), bytes32(0), "");

        bytes[] memory seven = new bytes[](7);
        for (uint256 i = 0; i < 5; i++) {
            seven[i] = hex"80";
        }
        seven[5] = RLP.encode(uint256(7));
        seven[6] = RLP.encode(uint256(9));
        (,,,, ClprTypes.Throttles memory t,,,) =
            v.verifyConfig(_replaceConfigField(configProof, 3, RLP.encode(seven)), bytes32(0), "");
        assertEq(t.maxLocalEndpoints, 7);
        assertEq(t.maxPeerEndpoints, 9);
    }

    function test_verifyConfig_manifestProof_verifiedAndReturned() public view {
        address[] memory set = _setN("cm", 3);
        bytes memory configProof = _configScenario("cm");
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));
        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) =
            v.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, _configManifestProof(set, _pksN("cm", 2), preimage));
        assertEq(m.version, 3);
    }

    function test_verifyConfig_manifestProof_sealedByOtherSet_reverts() public {
        bytes memory configProof = _configScenario("cm2");
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));
        bytes memory manifestProof = _configManifestProof(_setN("cm2", 3), _pksN("elsewhere", 2), preimage);
        vm.expectRevert();
        v.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, manifestProof);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes memory anchor) internal pure returns (DecodedAnchor memory a) {
        assertEq(anchor.length, 128, "header-mode anchor is 4 words");
        a.mode = uint8(uint256(_word(anchor, 0)));
        a.setCommitment = _word(anchor, 1);
        a.codeHash = _word(anchor, 2);
        a.anchorBlockNumber = uint64(uint256(_word(anchor, 3)));
    }

    function _word(bytes memory b, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), shl(5, i)))
        }
    }

    function _singleton(bytes memory item) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = item;
    }

    /// @dev A 5-field bundle around `header` with empty account/storage proofs: for tests that
    ///      revert before the storage tail.
    function _topWithHeader(bytes memory header, address[] memory trustedSet) internal pure returns (bytes memory) {
        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = _headerSourceField(trustedSet, new bytes[](0));
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    /// @dev A sealed header whose extraData validators item is `validatorListRlp` verbatim.
    function _sealedHeaderWithValidatorItems(uint256 blockNumber, bytes memory validatorListRlp, uint256[] memory pks)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory sealing =
            _buildHeaderAtNumber(blockNumber, bytes32(0), _buildExtraDataFull(validatorListRlp, new bytes[](0), 0));
        bytes32 sealHash = keccak256(sealing);
        bytes[] memory seals = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pks[i], sealHash);
            seals[i] = abi.encodePacked(r, s, uint8(vv - 27));
        }
        return _buildHeaderAtNumber(blockNumber, bytes32(0), _buildExtraDataFull(validatorListRlp, seals, 0));
    }

    function _descriptor(uint256 mode) internal pure returns (bytes[] memory ta) {
        ta = new bytes[](2);
        ta[0] = RLP.encode(mode);
        ta[1] = RLP.encode(SERVICE_CODE_HASH);
    }

    /// @dev Re-encode a config proof with field `index` replaced by `item` (already RLP-encoded).
    function _replaceConfigField(bytes memory configProof, uint256 index, bytes memory item)
        internal
        pure
        returns (bytes memory)
    {
        Memory.Slice[] memory items = RLP.decodeList(configProof);
        bytes[] memory out = new bytes[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            out[i] = i == index ? item : Memory.toBytes(items[i]);
        }
        return RLP.encode(out);
    }

    uint256 internal constant MANIFEST_COMMITMENT_SLOT = 18;

    function _manifestPreimage(bytes memory serviceAddress) internal pure returns (bytes memory) {
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](1);
        eps[0] = ClprTypes.Endpoint({ipAddress: "10.9.9.9", port: 50211, tlsCertificate: hex"DD", accountId: hex"0A"});
        return ClprProtobuf.encodeEndpointManifest(
            ClprTypes.ClprEndpointManifest({version: 3, serviceAddress: serviceAddress, endpoints: eps})
        );
    }

    /// @dev Storage trie anchored at the manifest-commitment slot with keccak256(preimage); the five
    ///      channel slots diverge in the same trie and prove zero.
    function _manifestAnchoredStorage(bytes memory preimage)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory connStorageProofRlp, bytes memory manifestStorageProofRlp)
    {
        bytes memory proofNodesRlp;
        (storageRoot, proofNodesRlp) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(MANIFEST_COMMITMENT_SLOT))), RLP.encode(uint256(keccak256(preimage)))
        );
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory connEntries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodesRlp;
            connEntries[i] = RLP.encode(entry);
        }
        connStorageProofRlp = RLP.encode(connEntries);
        bytes[] memory mEntry = new bytes[](2);
        mEntry[0] = RLP.encode(abi.encodePacked(bytes32(MANIFEST_COMMITMENT_SLOT)));
        mEntry[1] = proofNodesRlp;
        manifestStorageProofRlp = RLP.encode(_singleton(RLP.encode(mEntry)));
    }

    /// @dev A 7-field bundle over the 3-member set derived from `seed`, sealed by its quorum.
    function _manifestBundle(string memory seed, bytes memory preimage) internal pure returns (bytes memory) {
        address[] memory set = _setN(seed, 3);
        (bytes32 storageRoot, bytes memory connStorageProofRlp, bytes memory manifestStorageProofRlp) =
            _manifestAnchoredStorage(preimage);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes[] memory top = new bytes[](7);
        top[0] = _buildListedSealedHeader(1, stateRoot, set, _pksN(seed, 2));
        top[1] = _headerSourceField(set, new bytes[](0));
        top[2] = accountProofRlp;
        top[3] = connStorageProofRlp;
        top[4] = RLP.encode(new bytes(0));
        top[5] = manifestStorageProofRlp;
        top[6] = RLP.encode(preimage);
        return RLP.encode(top);
    }

    /// @dev RLP([sealedHeader, accountProof, manifestStorageProof, manifestPreimage]) for verifyConfig.
    function _configManifestProof(address[] memory set, uint256[] memory sealerPks, bytes memory preimage)
        internal
        pure
        returns (bytes memory)
    {
        (bytes32 storageRoot,, bytes memory manifestStorageProofRlp) = _manifestAnchoredStorage(preimage);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes[] memory p = new bytes[](4);
        p[0] = _buildListedSealedHeader(1, stateRoot, set, sealerPks);
        p[1] = accountProofRlp;
        p[2] = manifestStorageProofRlp;
        p[3] = RLP.encode(preimage);
        return RLP.encode(p);
    }
}
