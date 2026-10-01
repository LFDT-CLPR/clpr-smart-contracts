// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SignerReplaySynthetic} from "@test/helpers/SignerReplaySynthetic.sol";
import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";
import {SignerReplayProfiles} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayProfiles.sol";
import {ClprSignerReplay} from "@hiero-ledger/clpr/libraries/proof/signer/ClprSignerReplay.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev Synthetic tests for SignerReplayVerifier: the majority rule, boundary rotation, run linking,
///      anchor binding, profile variants (Congress 15-field seal, Bitkub 40-byte entries + trailer
///      signer) and verifyConfig.
contract SignerReplayVerifierTest is SignerReplaySynthetic {
    SignerReplayVerifier internal verifier;
    uint256[] internal pks;
    address[] internal set;
    bytes32 internal stateRoot;
    bytes internal accountProof;
    bytes internal storageProof;

    function setUp() public {
        verifier = new SignerReplayVerifier(_cliqueProfile());
        uint256[] memory k = _keys(3, "signer");
        for (uint256 i = 0; i < 3; i++) {
            pks.push(k[i]);
        }
        address[] memory s = _sortedAddrs(k);
        for (uint256 i = 0; i < s.length; i++) {
            set.push(s[i]);
        }
        (stateRoot, accountProof, storageProof) = _stateProofs();
    }

    function _pk(uint256 i) internal view returns (uint256) {
        return pks[i];
    }

    function _seq(uint256 a, uint256 b) internal view returns (uint256[] memory s) {
        s = new uint256[](2);
        s[0] = pks[a];
        s[1] = pks[b];
    }

    function _verify(bytes[] memory headers, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory newAnchor, bytes memory newId)
    {
        (m,, newAnchor, newId,) =
            verifier.verifyBundle(_bundle(set, headers, accountProof, storageProof), anchor, _ctx());
    }

    // ── Majority rule ─────────────────────────────────────────────────────────

    function test_acceptsRunSealedByMajority() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory newAnchor,) =
            _verify(_run(101, stateRoot, _seq(0, 1)), _anchor(set, 100));
        assertEq(m.nextMessageId, 0);
        assertEq(newAnchor.length, 0, "no boundary in run, no rotation");
    }

    function test_revertWhen_sameSignerTwice() public {
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.InsufficientSigners.selector, 1, 2));
        _verify(_run(101, stateRoot, _seq(0, 0)), _anchor(set, 100));
    }

    function test_revertWhen_signerOutsideSet() public {
        uint256[] memory s = new uint256[](2);
        s[0] = pks[0];
        s[1] = uint256(keccak256("outsider"));
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.InsufficientSigners.selector, 1, 2));
        _verify(_run(101, stateRoot, s), _anchor(set, 100));
    }

    function test_outsiderHeadersAllowedButNotCounted() public view {
        uint256[] memory s = new uint256[](3);
        s[0] = pks[0];
        s[1] = uint256(keccak256("outsider"));
        s[2] = pks[2];
        _verify(_run(101, stateRoot, s), _anchor(set, 100));
    }

    function test_revertWhen_runNotLinked() public {
        bytes[] memory hs = new bytes[](2);
        hs[0] = _simple(101, keccak256("p"), stateRoot, pks[0]).rlp;
        hs[1] = _simple(102, keccak256("not-the-parent"), bytes32(0), pks[1]).rlp;
        vm.expectRevert(abi.encodeWithSelector(ClprSignerReplay.HeaderChainBroken.selector, 1));
        _verify(hs, _anchor(set, 100));
    }

    function test_revertWhen_numberGap() public {
        Hdr memory a = _simple(101, keccak256("p"), stateRoot, pks[0]);
        bytes[] memory hs = new bytes[](2);
        hs[0] = a.rlp;
        hs[1] = _simple(103, a.hash, bytes32(0), pks[1]).rlp;
        vm.expectRevert(abi.encodeWithSelector(ClprSignerReplay.HeaderChainBroken.selector, 1));
        _verify(hs, _anchor(set, 100));
    }

    function test_revertWhen_tamperedSeal() public {
        bytes[] memory hs = _run(101, stateRoot, _seq(0, 1));
        // Flip a byte of the second header's seal r (its last 65 bytes of extra, before mixDigest/nonce).
        bytes memory h = hs[1];
        h[h.length - 1 - 42 - 64] ^= 0x01;
        vm.expectRevert();
        _verify(hs, _anchor(set, 100));
    }

    // ── Anchor binding ────────────────────────────────────────────────────────

    function test_revertWhen_signerSetBytesDoNotMatchAnchor() public {
        address[] memory other = new address[](3);
        other[0] = set[0];
        other[1] = set[1];
        other[2] = address(uint160(set[2]) + 1);
        bytes memory proof = _bundle(other, _run(101, stateRoot, _seq(0, 1)), accountProof, storageProof);
        vm.expectRevert(SignerReplayVerifier.SignerSetMismatch.selector);
        verifier.verifyBundle(proof, _anchor(set, 100), _ctx());
    }

    function test_revertWhen_headerOlderThanAnchor() public {
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.HeaderBeforeAnchor.selector, 101, 200));
        _verify(_run(101, stateRoot, _seq(0, 1)), _anchor(set, 200));
    }

    function test_revertWhen_codeHashNotPinned() public {
        bytes memory anchor = _anchor(set, 100);
        anchor[0] ^= 0x01;
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        _verify(_run(101, stateRoot, _seq(0, 1)), anchor);
    }

    function test_revertWhen_anchorLengthWrong() public {
        vm.expectRevert(SignerReplayVerifier.InvalidTrustAnchor.selector);
        _verify(_run(101, stateRoot, _seq(0, 1)), bytes.concat(_anchor(set, 100), hex"00"));
    }

    function test_revertWhen_wrongStateRoot() public {
        vm.expectRevert();
        _verify(_run(101, keccak256("other-root"), _seq(0, 1)), _anchor(set, 100));
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    function _newSet() internal pure returns (uint256[] memory k, address[] memory s) {
        k = _keys(5, "next-set");
        s = _sortedAddrs(k);
    }

    function test_rotatesAtNewerBoundary() public view {
        (, address[] memory next) = _newSet();
        // h_0 = state block 199, boundary 200 lists the new set, 201 sealed by another old signer.
        Hdr memory h0 = _simple(199, keccak256("p"), stateRoot, pks[0]);
        Hdr memory b = _hdr(200, h0.hash, bytes32(0), _packed(next), pks[1], 0, 0);
        Hdr memory h2 = _simple(201, b.hash, bytes32(0), pks[2]);
        bytes[] memory hs = new bytes[](3);
        hs[0] = h0.rlp;
        hs[1] = b.rlp;
        hs[2] = h2.rlp;
        (, bytes memory newAnchor, bytes memory newId) = _verify(hs, _anchor(set, 100));
        assertEq(newAnchor, _anchor(next, 200));
        assertEq(newId, abi.encodePacked(uint64(200)));
    }

    function test_revertWhen_majorityOnlyBeforeBoundary() public {
        (, address[] memory next) = _newSet();
        Hdr memory h0 = _simple(198, keccak256("p"), stateRoot, pks[0]);
        Hdr memory h1 = _simple(199, h0.hash, bytes32(0), pks[1]);
        Hdr memory b = _hdr(200, h1.hash, bytes32(0), _packed(next), uint256(keccak256("outsider")), 0, 0);
        bytes[] memory hs = new bytes[](3);
        hs[0] = h0.rlp;
        hs[1] = h1.rlp;
        hs[2] = b.rlp;
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.InsufficientSigners.selector, 0, 2));
        _verify(hs, _anchor(set, 100));
    }

    function test_boundaryNotNewerThanAnchorDoesNotRotate() public view {
        (, address[] memory next) = _newSet();
        Hdr memory b = _hdr(200, keccak256("p"), stateRoot, _packed(next), pks[0], 0, 0);
        Hdr memory h1 = _simple(201, b.hash, bytes32(0), pks[1]);
        bytes[] memory hs = new bytes[](2);
        hs[0] = b.rlp;
        hs[1] = h1.rlp;
        (, bytes memory newAnchor,) = _verify(hs, _anchor(set, 200));
        assertEq(newAnchor.length, 0);
    }

    function test_revertWhen_rotationReplayedOnRotatedAnchor() public {
        (, address[] memory next) = _newSet();
        Hdr memory h0 = _simple(199, keccak256("p"), stateRoot, pks[0]);
        Hdr memory b = _hdr(200, h0.hash, bytes32(0), _packed(next), pks[1], 0, 0);
        bytes[] memory hs = new bytes[](2);
        hs[0] = h0.rlp;
        hs[1] = b.rlp;
        // The old set's bytes no longer match the rotated anchor.
        bytes memory proof = _bundle(set, hs, accountProof, storageProof);
        vm.expectRevert(SignerReplayVerifier.SignerSetMismatch.selector);
        verifier.verifyBundle(proof, _anchor(next, 200), _ctx());
    }

    // ── Profiles ──────────────────────────────────────────────────────────────

    function test_congressProfile_sealCoversFirst15Fields() public {
        SignerReplayVerifier congress = new SignerReplayVerifier(SignerReplayProfiles.grx(TEST_CHAIN_ID));
        Hdr memory a = _hdr(201, keccak256("p"), stateRoot, "", pks[0], 1, 15);
        Hdr memory b = _hdr(202, a.hash, bytes32(0), "", pks[1], 1, 15);
        bytes[] memory hs = new bytes[](2);
        hs[0] = a.rlp;
        hs[1] = b.rlp;
        bytes memory proof = _bundle(set, hs, accountProof, storageProof);
        congress.verifyBundle(proof, _anchor(set, 200), _ctx());

        // The same headers sealed over all 16 fields recover other addresses under the 15-field rule.
        a = _hdr(201, keccak256("p"), stateRoot, "", pks[0], 1, 0);
        b = _hdr(202, a.hash, bytes32(0), "", pks[1], 1, 0);
        hs[0] = a.rlp;
        hs[1] = b.rlp;
        proof = _bundle(set, hs, accountProof, storageProof);
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.InsufficientSigners.selector, 0, 2));
        congress.verifyBundle(proof, _anchor(set, 200), _ctx());
    }

    function test_kubProfile_spanListWithPowersAndSuperNode() public {
        SignerReplayVerifier kub = new SignerReplayVerifier(SignerReplayProfiles.kub(TEST_CHAIN_ID));
        // Span schedule: 4 slots over 2 validators (with powers), then 3 system addresses; the third
        // (super node) is also a signer.
        address v1 = vm.addr(pks[0]);
        address v2 = vm.addr(pks[1]);
        address superNode = vm.addr(pks[2]);
        bytes memory body = bytes.concat(
            abi.encodePacked(v1, bytes20(uint160(5))),
            abi.encodePacked(v2, bytes20(uint160(3))),
            abi.encodePacked(v1, bytes20(uint160(5))),
            abi.encodePacked(v2, bytes20(uint160(3))),
            abi.encodePacked(address(0x1111), address(0x2222), superNode)
        );
        // Block 99 is a span-commit block: (99 + 1) % 50 == 0.
        (,,,,, bytes memory anchor, bytes memory anchorId,) = kub.verifyConfig(
            _replayConfig("eip155:777", _boundaryRun(99, body, pks[0], pks[1])), SYNTHETIC_CHANNEL_ID, ""
        );
        assertEq(anchor, _anchor(set, 99), "distinct schedule addresses + super node, sorted");
        assertEq(anchorId, abi.encodePacked(uint64(99)));
    }

    function test_revertWhen_invalidProfile() public {
        SignerReplayVerifier.Profile memory p = _cliqueProfile();
        p.boundaryOffset = p.epochLength;
        vm.expectRevert(SignerReplayVerifier.InvalidProfile.selector);
        new SignerReplayVerifier(p);
        p = _cliqueProfile();
        p.trailerSignerOffset = 0; // trailer is empty
        vm.expectRevert(SignerReplayVerifier.InvalidProfile.selector);
        new SignerReplayVerifier(p);
    }

    function test_revertWhen_anchorTooOld() public {
        SignerReplayVerifier.Profile memory p = _cliqueProfile();
        p.maxAnchorAge = 50;
        SignerReplayVerifier aged = new SignerReplayVerifier(p);
        bytes memory proof = _bundle(set, _run(151, stateRoot, _seq(0, 1)), accountProof, storageProof);
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.AnchorTooOld.selector, 151, 100));
        aged.verifyBundle(proof, _anchor(set, 100), _ctx());
        proof = _bundle(set, _run(150, stateRoot, _seq(0, 1)), accountProof, storageProof);
        aged.verifyBundle(proof, _anchor(set, 100), _ctx());
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function test_verifyConfig_bootstrapsFromBoundary() public view {
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor, bytes memory id,) = verifier.verifyConfig(
            _replayConfig("eip155:777", _boundaryRun(300, _packed(set), pks[0], pks[1])), SYNTHETIC_CHANNEL_ID, ""
        );
        assertEq(chainId, "eip155:777");
        assertEq(ctx, _ctx());
        assertEq(anchor, _anchor(set, 300));
        assertEq(id, abi.encodePacked(uint64(300)));
    }

    function test_verifyConfig_unsortedListIsCanonicalised() public view {
        address[] memory rev = new address[](3);
        rev[0] = set[2];
        rev[1] = set[0];
        rev[2] = set[1];
        bytes memory body = bytes.concat(_packed(rev), abi.encodePacked(set[0]));
        (,,,,, bytes memory anchor,,) = verifier.verifyConfig(
            _replayConfig("eip155:777", _boundaryRun(300, body, pks[0], pks[1])), SYNTHETIC_CHANNEL_ID, ""
        );
        assertEq(anchor, _anchor(set, 300));
    }

    function test_revertWhen_configNotBoundary() public {
        bytes memory cfg = _replayConfig("eip155:777", _boundaryRun(301, _packed(set), pks[0], pks[1]));
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.NotBoundaryBlock.selector, 301));
        verifier.verifyConfig(cfg, SYNTHETIC_CHANNEL_ID, "");
    }

    function test_revertWhen_configChainIdMismatch() public {
        bytes memory cfg = _replayConfig("eip155:1", _boundaryRun(300, _packed(set), pks[0], pks[1]));
        vm.expectRevert(SignerReplayVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(cfg, SYNTHETIC_CHANNEL_ID, "");
    }

    function test_revertWhen_configBoundaryHasNoList() public {
        bytes memory cfg = _replayConfig("eip155:777", _boundaryRun(300, "", pks[0], pks[1]));
        vm.expectRevert(ClprSignerReplay.InvalidSignerList.selector);
        verifier.verifyConfig(cfg, SYNTHETIC_CHANNEL_ID, "");
    }

    function test_revertWhen_configSetNeverSeals() public {
        // The boundary lists a set none of whose members sealed the run.
        (, address[] memory next) = _newSet();
        bytes memory cfg = _replayConfig("eip155:777", _boundaryRun(300, _packed(next), pks[0], pks[1]));
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.InsufficientSigners.selector, 0, 3));
        verifier.verifyConfig(cfg, SYNTHETIC_CHANNEL_ID, "");
    }
}
