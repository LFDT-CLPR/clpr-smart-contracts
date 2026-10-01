// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {KaiaSynthetic} from "@test/helpers/KaiaSynthetic.sol";
import {KaiaIstanbulVerifier} from "@hiero-ledger/clpr/verifiers/evm/kaia/KaiaIstanbulVerifier.sol";
import {ClprKaiaIstanbul} from "@hiero-ledger/clpr/libraries/proof/kaia/ClprKaiaIstanbul.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev Synthetic tests for KaiaIstanbulVerifier: block-hash reconstruction, the 2f+1 commit quorum,
///      distinct committers, set rotation (f+1 of the trusted set), ordering, anchor binding and
///      Kaia's account encoding.
contract KaiaIstanbulVerifierTest is KaiaSynthetic {
    KaiaIstanbulVerifier internal verifier;
    uint256[] internal pks; // 4 validators: f = 1, quorum 3
    address[] internal set;
    bytes32 internal stateRoot;
    bytes internal accountProof;
    bytes internal storageProof;

    function setUp() public {
        verifier = new KaiaIstanbulVerifier(TEST_CHAIN_ID);
        uint256[] memory k = _keys(4, "kaia");
        for (uint256 i = 0; i < 4; i++) {
            pks.push(k[i]);
        }
        address[] memory a = _addrs(k);
        for (uint256 i = 0; i < 4; i++) {
            set.push(a[i]);
        }
        (stateRoot, accountProof, storageProof) = _kaiaStateProofs(2);
    }

    function _one(KHdr memory h) internal pure returns (bytes[] memory hs) {
        hs = new bytes[](1);
        hs[0] = h.rlp;
    }

    function _verify(bytes[] memory hs, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory newAnchor, bytes memory newId)
    {
        (m,, newAnchor, newId,) =
            verifier.verifyBundle(_kaiaBundle(set, hs, accountProof, storageProof), anchor, _ctx());
    }

    // ── Quorum ────────────────────────────────────────────────────────────────

    function test_quorumMath() public pure {
        assertEq(ClprKaiaIstanbul.quorum(1), 1);
        assertEq(ClprKaiaIstanbul.quorum(4), 3);
        assertEq(ClprKaiaIstanbul.quorum(30), 19);
        assertEq(ClprKaiaIstanbul.quorum(31), 21); // Kaia mainnet, Oct 2026: 31 qualified, 21 seals
        assertEq(ClprKaiaIstanbul.faultBound(30), 9);
    }

    function test_acceptsQuorumOfCommittedSeals() public view {
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 3), 0);
        (ClprTypes.QueueMetadata memory m, bytes memory newAnchor,) = _verify(_one(h), _kaiaAnchor(set, 100));
        assertEq(m.nextMessageId, 0);
        assertEq(newAnchor.length, 0);
    }

    function test_roundByteDoesNotChangeBlockHash() public view {
        // Seals sign the round-0 hash; the header carries round 5.
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 3), 5);
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_revertWhen_belowQuorum() public {
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 2), 0);
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.InsufficientCommittedSeals.selector, 2, 3));
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_revertWhen_duplicateCommitter() public {
        uint256[] memory c = new uint256[](3);
        c[0] = pks[0];
        c[1] = pks[1];
        c[2] = pks[0];
        KHdr memory h = _kaiaHeader(101, stateRoot, set, c, 0);
        vm.expectRevert(abi.encodeWithSelector(ClprKaiaIstanbul.DuplicateCommitter.selector, vm.addr(pks[0])));
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_nonMemberSealsDoNotCount() public {
        uint256[] memory c = new uint256[](3);
        c[0] = pks[0];
        c[1] = pks[1];
        c[2] = uint256(keccak256("outsider"));
        KHdr memory h = _kaiaHeader(101, stateRoot, set, c, 0);
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.InsufficientCommittedSeals.selector, 2, 3));
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_revertWhen_tamperedHeader() public {
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 3), 0);
        bytes memory r = h.rlp;
        r[40] ^= 0x01; // inside parentHash: block hash changes, seals recover other addresses
        bytes[] memory hs = new bytes[](1);
        hs[0] = r;
        vm.expectRevert();
        _verify(hs, _kaiaAnchor(set, 100));
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    function test_rotatesWhenTrustedThirdVouches() public view {
        // New set: validator 3 replaced by a new key. Committers 0, 1, new → 2 of the old set ≥ f+1 = 2.
        uint256 fresh = uint256(keccak256("fresh"));
        uint256[] memory nk = new uint256[](4);
        nk[0] = pks[0];
        nk[1] = pks[1];
        nk[2] = pks[2];
        nk[3] = fresh;
        address[] memory next = _addrs(nk);
        uint256[] memory c = new uint256[](3);
        c[0] = pks[0];
        c[1] = pks[1];
        c[2] = fresh;
        KHdr memory h = _kaiaHeader(150, stateRoot, next, c, 0);
        (, bytes memory newAnchor, bytes memory newId) = _verify(_one(h), _kaiaAnchor(set, 100));
        assertEq(newAnchor, _kaiaAnchor(next, 150));
        assertEq(newId, abi.encodePacked(uint64(150)));
    }

    function test_revertWhen_rotationNotVouchedByTrustedSet() public {
        uint256[] memory nk = _keys(4, "attacker");
        KHdr memory h = _kaiaHeader(150, stateRoot, _addrs(nk), _prefix(nk, 3), 0);
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.InsufficientRotationSeals.selector, 0, 2));
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_rotationThenStateInOneRun() public view {
        uint256 fresh = uint256(keccak256("fresh"));
        uint256[] memory nk = new uint256[](4);
        nk[0] = pks[0];
        nk[1] = pks[1];
        nk[2] = fresh;
        nk[3] = pks[3];
        address[] memory next = _addrs(nk);
        bytes[] memory hs = new bytes[](2);
        hs[0] = _kaiaHeader(150, bytes32(0), next, _prefix(nk, 3), 0).rlp; // 0,1 old + fresh
        hs[1] = _kaiaHeader(160, stateRoot, next, _prefix(nk, 3), 0).rlp;
        (, bytes memory newAnchor,) = _verify(hs, _kaiaAnchor(set, 100));
        assertEq(newAnchor, _kaiaAnchor(next, 150));
    }

    // ── Ordering and anchor ───────────────────────────────────────────────────

    function test_revertWhen_headerOlderThanAnchor() public {
        KHdr memory h = _kaiaHeader(99, stateRoot, set, _prefix(pks, 3), 0);
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.HeaderOutOfOrder.selector, 99, 100));
        _verify(_one(h), _kaiaAnchor(set, 100));
    }

    function test_revertWhen_headersNotIncreasing() public {
        bytes[] memory hs = new bytes[](2);
        hs[0] = _kaiaHeader(120, bytes32(0), set, _prefix(pks, 3), 0).rlp;
        hs[1] = _kaiaHeader(120, stateRoot, set, _prefix(pks, 3), 0).rlp;
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.HeaderOutOfOrder.selector, 120, 120));
        _verify(hs, _kaiaAnchor(set, 100));
    }

    function test_revertWhen_anchorValidatorsMismatch() public {
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 3), 0);
        address[] memory other = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            other[i] = set[3 - i];
        }
        bytes memory proof = _kaiaBundle(other, _one(h), accountProof, storageProof);
        vm.expectRevert(KaiaIstanbulVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(proof, _kaiaAnchor(set, 100), _ctx());
    }

    function test_revertWhen_codeHashNotPinned() public {
        bytes memory anchor = _kaiaAnchor(set, 100);
        anchor[0] ^= 0x01;
        KHdr memory h = _kaiaHeader(101, stateRoot, set, _prefix(pks, 3), 0);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        _verify(_one(h), anchor);
    }

    function test_revertWhen_accountIsNotSmartContract() public {
        (bytes32 root, bytes memory acct, bytes memory st) = _kaiaStateProofs(1); // EOA type tag
        KHdr memory h = _kaiaHeader(101, root, set, _prefix(pks, 3), 0);
        bytes memory proof = _kaiaBundle(set, _one(h), acct, st);
        vm.expectRevert(KaiaIstanbulVerifier.InvalidKaiaAccount.selector);
        verifier.verifyBundle(proof, _kaiaAnchor(set, 100), _ctx());
    }

    function test_revertWhen_ethereumAccountEncoding() public {
        // A plain Ethereum account leaf does not decode as a Kaia account.
        (bytes32 storageRoot, bytes memory st) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 root, bytes memory acct) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        KHdr memory h = _kaiaHeader(101, root, set, _prefix(pks, 3), 0);
        vm.expectRevert(KaiaIstanbulVerifier.InvalidKaiaAccount.selector);
        verifier.verifyBundle(_kaiaBundle(set, _one(h), acct, st), _kaiaAnchor(set, 100), _ctx());
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function test_verifyConfig_bootstrapsFromHeader() public view {
        KHdr memory h = _kaiaHeader(500, bytes32(0), set, _prefix(pks, 3), 0);
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor, bytes memory id,) =
            verifier.verifyConfig(_kaiaConfig("eip155:777", h.rlp), SYNTHETIC_CHANNEL_ID, "");
        assertEq(chainId, "eip155:777");
        assertEq(ctx, _ctx());
        assertEq(anchor, _kaiaAnchor(set, 500));
        assertEq(id, abi.encodePacked(uint64(500)));
    }

    function test_revertWhen_configHeaderBelowQuorum() public {
        KHdr memory h = _kaiaHeader(500, bytes32(0), set, _prefix(pks, 2), 0);
        vm.expectRevert(abi.encodeWithSelector(KaiaIstanbulVerifier.InsufficientCommittedSeals.selector, 2, 3));
        verifier.verifyConfig(_kaiaConfig("eip155:777", h.rlp), SYNTHETIC_CHANNEL_ID, "");
    }

    function test_revertWhen_configChainIdMismatch() public {
        KHdr memory h = _kaiaHeader(500, bytes32(0), set, _prefix(pks, 3), 0);
        vm.expectRevert(KaiaIstanbulVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(_kaiaConfig("eip155:8217", h.rlp), SYNTHETIC_CHANNEL_ID, "");
    }
}
