// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {BscParliaVerifier} from "@hiero-ledger/clpr/verifiers/evm/bsc/BscParliaVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprParlia} from "@hiero-ledger/clpr/libraries/proof/parlia/ClprParlia.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {BscParliaFixtures} from "@test/verifiers/evm/bsc/BscParliaFixtures.sol";

/// @dev Synthetic-chain tests for BscParliaVerifier: real secp256k1 seals and real BLS12-381
///      attestations (EIP-2537), BSC-shaped headers, synthetic MPT state. Live Chapel/mainnet data is
///      covered by BscParliaLive.t.sol and test/e2e/tests/verifiers/bsc-live.spec.ts.
contract BscParliaVerifierTest is BscParliaFixtures {
    BscParliaVerifier internal verifier;

    Val[] internal setA; // anchor set, published in epoch block 1000, active from 1010
    Val[] internal setB; // next set, published in epoch block 1200
    uint64 internal constant E_A = 1000;
    uint64 internal constant ACTIVE_A = 1010;
    uint64 internal constant E_B = 1200;
    uint64 internal constant N = 9;

    bytes32 internal stateRoot;
    bytes internal accountProof;
    bytes internal storageProof;

    function setUp() public {
        verifier = new BscParliaVerifier();
        Val[] memory a = _makeSet(N, "A");
        Val[] memory b = _makeSet(N, "B");
        for (uint256 i = 0; i < N; i++) {
            setA.push(a[i]);
            setB.push(b[i]);
        }
        (stateRoot, accountProof, storageProof) = _serviceState();
    }

    // ── Builders ──────────────────────────────────────────────────────────────

    function _activeB() internal pure returns (uint64) {
        return E_B + _checkLen(N, TURN_LENGTH) + 1; // 1220
    }

    function _stateHeader(uint64 number, Val[] memory sealers) internal view returns (Hdr memory) {
        return
            _header(number, keccak256(abi.encode("parent", number)), stateRoot, _plainExtraBody(), sealers[0].ecdsaPk);
    }

    function _finality(Val[] memory vals, uint64 bits, Hdr memory h) internal view returns (bytes memory) {
        return _pair(_chain(h), _finalize(vals, bits, h));
    }

    function _plainBundle(Val[] memory vals, uint64 number, uint64 bits) internal view returns (bytes memory) {
        Hdr memory h = _stateHeader(number, vals);
        return _bundle(_emptyList(), _entries(vals), _finality(vals, bits, h), accountProof, storageProof);
    }

    function _rotationStep(Val[] memory outgoing, Val[] memory incoming, uint64 epochNumber, bool withKeys)
        internal
        view
        returns (bytes memory)
    {
        Hdr memory e = _header(
            epochNumber,
            keccak256(abi.encode("parent", epochNumber)),
            bytes32(uint256(epochNumber)),
            _epochExtraBody(incoming, TURN_LENGTH),
            outgoing[1].ecdsaPk
        );
        return _triple(
            _chain(e), _finalize(outgoing, _allBits(outgoing.length), e), withKeys ? _keysList(incoming) : _noKeys()
        );
    }

    function _anchorA() internal view returns (bytes memory) {
        return _anchor(setA, E_A, ACTIVE_A);
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_verifyBundle_finalizedState_noRotation() public view {
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(_plainBundle(setA, 1100, _allBits(N)), _anchorA(), _channelContext());
        assertEq(m.nextMessageId, 1, "proven nextMessageId");
        assertEq(msgs.length, 0);
        assertEq(newAnchor.length, 0, "no rotation, no new anchor");
        assertEq(newId.length, 0);
    }

    function test_verifyBundle_exactQuorum_succeeds() public view {
        // ceil(2·9/3) = 6 votes.
        verifier.verifyBundle(_plainBundle(setA, 1100, 0x3f), _anchorA(), _channelContext());
    }

    function test_verifyBundle_rotation_changesSet() public view {
        Hdr memory s = _stateHeader(1230, setB);
        bytes memory bundle = _bundle(
            _list1(_rotationStep(setA, setB, E_B, true)),
            _entries(setA),
            _finality(setB, _allBits(N), s),
            accountProof,
            storageProof
        );
        (,, bytes memory newAnchor, bytes memory newId,) = verifier.verifyBundle(bundle, _anchorA(), _channelContext());
        assertEq(newAnchor, _anchor(setB, E_B, _activeB()), "successor anchor");
        assertEq(newId, abi.encodePacked(E_B), "anchor id = epoch block");
    }

    function test_verifyBundle_rotation_unchangedSet_withoutKeys() public view {
        Hdr memory s = _stateHeader(1230, setA);
        bytes memory bundle = _bundle(
            _list1(_rotationStep(setA, setA, E_B, false)),
            _entries(setA),
            _finality(setA, _allBits(N), s),
            accountProof,
            storageProof
        );
        (,, bytes memory newAnchor,,) = verifier.verifyBundle(bundle, _anchorA(), _channelContext());
        assertEq(newAnchor, _anchor(setA, E_B, _activeB()));
    }

    function test_verifyBundle_twoRotations() public view {
        Val[] memory c = _makeSet(7, "C");
        bytes[] memory steps = new bytes[](2);
        steps[0] = _rotationStep(setA, setB, E_B, true);
        steps[1] = _rotationStep(setB, c, E_B + EPOCH_LENGTH, true);
        uint64 activeC = E_B + EPOCH_LENGTH + _checkLen(N, TURN_LENGTH) + 1;
        Hdr memory s = _stateHeader(activeC + 5, c);
        bytes memory bundle =
            _bundle(RLP.encode(steps), _entries(setA), _finality(c, _allBits(7), s), accountProof, storageProof);
        (,, bytes memory newAnchor,,) = verifier.verifyBundle(bundle, _anchorA(), _channelContext());
        assertEq(newAnchor, _anchor(c, E_B + EPOCH_LENGTH, activeC));
    }

    function test_verifyBundle_headerChain_finalizesAncestor() public view {
        Hdr memory h0 = _stateHeader(1100, setA);
        Hdr memory h1 = _header(1101, h0.hash, bytes32(uint256(1)), _plainExtraBody(), setA[1].ecdsaPk);
        Hdr memory h2 = _header(1102, h1.hash, bytes32(uint256(2)), _plainExtraBody(), setA[2].ecdsaPk);
        bytes[] memory chain = new bytes[](3);
        chain[0] = h0.rlp;
        chain[1] = h1.rlp;
        chain[2] = h2.rlp;
        bytes memory fin = _pair(RLP.encode(chain), _finalize(setA, _allBits(N), h2));
        verifier.verifyBundle(
            _bundle(_emptyList(), _entries(setA), fin, accountProof, storageProof), _anchorA(), _channelContext()
        );
    }

    // ── BLS / quorum ──────────────────────────────────────────────────────────

    function test_revertWhen_badSignature() public {
        Hdr memory h = _stateHeader(1100, setA);
        bytes32 tgtHash = keccak256("child");
        // Signed over a different target hash than the one carried.
        bytes memory sig = _sign(setA, _allBits(N), _voteHash(h.number, h.hash, h.number + 1, keccak256("other")));
        bytes memory att = _attestationRaw(_allBits(N), sig, h.number, h.hash, h.number + 1, tgtHash);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(
            _bundle(_emptyList(), _entries(setA), _pair(_chain(h), att), accountProof, storageProof),
            _anchorA(),
            _channelContext()
        );
    }

    function test_revertWhen_belowThreshold() public {
        bytes memory bundle = _plainBundle(setA, 1100, 0x1f);
        vm.expectRevert(abi.encodeWithSelector(ClprParlia.InsufficientVotes.selector, 5, 9));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_bitsetOverclaimsSigners() public {
        Hdr memory h = _stateHeader(1100, setA);
        bytes32 tgtHash = keccak256(abi.encode("child", h.hash));
        bytes memory sig = _sign(setA, 0xff, _voteHash(h.number, h.hash, h.number + 1, tgtHash)); // 8 signed
        bytes memory att = _attestationRaw(_allBits(N), sig, h.number, h.hash, h.number + 1, tgtHash); // claims 9
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(
            _bundle(_emptyList(), _entries(setA), _pair(_chain(h), att), accountProof, storageProof),
            _anchorA(),
            _channelContext()
        );
    }

    function test_revertWhen_voteBitBeyondSet() public {
        bytes memory bundle = _plainBundle(setA, 1100, _allBits(N) | uint64(1 << 9));
        vm.expectRevert(ClprParlia.VoteBitOutOfRange.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_wrongValidatorSetSupplied() public {
        Hdr memory h = _stateHeader(1100, setB);
        bytes memory bundle =
            _bundle(_emptyList(), _entries(setB), _finality(setB, _allBits(N), h), accountProof, storageProof);
        vm.expectRevert(BscParliaVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_signedByOtherSet() public {
        // Anchor set's keys supplied (commitment holds) but the attestation is by another set.
        Hdr memory h = _stateHeader(1100, setA);
        bytes memory bundle =
            _bundle(_emptyList(), _entries(setA), _finality(setB, _allBits(N), h), accountProof, storageProof);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    // ── Finality rule / header chain ──────────────────────────────────────────

    function test_revertWhen_attestationNotFinalizing() public {
        Hdr memory h = _stateHeader(1100, setA);
        bytes32 tgtHash = keccak256("grandchild");
        bytes memory sig = _sign(setA, _allBits(N), _voteHash(h.number, h.hash, h.number + 2, tgtHash));
        bytes memory att = _attestationRaw(_allBits(N), sig, h.number, h.hash, h.number + 2, tgtHash);
        vm.expectRevert(ClprParlia.AttestationNotFinalizing.selector);
        verifier.verifyBundle(
            _bundle(_emptyList(), _entries(setA), _pair(_chain(h), att), accountProof, storageProof),
            _anchorA(),
            _channelContext()
        );
    }

    function test_revertWhen_attestationForOtherBlock() public {
        Hdr memory h = _stateHeader(1100, setA);
        Hdr memory other = _header(1100, keccak256("fork"), stateRoot, _plainExtraBody(), setA[0].ecdsaPk);
        bytes memory bundle = _bundle(
            _emptyList(),
            _entries(setA),
            _pair(_chain(h), _finalize(setA, _allBits(N), other)),
            accountProof,
            storageProof
        );
        vm.expectRevert(ClprParlia.AttestationSourceMismatch.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_headerChainBroken() public {
        Hdr memory h0 = _stateHeader(1100, setA);
        Hdr memory h1 = _header(1101, keccak256("not h0"), bytes32(uint256(1)), _plainExtraBody(), setA[1].ecdsaPk);
        bytes[] memory chain = new bytes[](2);
        chain[0] = h0.rlp;
        chain[1] = h1.rlp;
        bytes memory fin = _pair(RLP.encode(chain), _finalize(setA, _allBits(N), h1));
        vm.expectRevert(abi.encodeWithSelector(ClprParlia.HeaderChainBroken.selector, 1));
        verifier.verifyBundle(
            _bundle(_emptyList(), _entries(setA), fin, accountProof, storageProof), _anchorA(), _channelContext()
        );
    }

    function test_revertWhen_sealedByNonValidator() public {
        Hdr memory h = _stateHeader(1100, setB); // sealed by a set-B key
        bytes memory bundle =
            _bundle(_emptyList(), _entries(setA), _finality(setA, _allBits(N), h), accountProof, storageProof);
        vm.expectPartialRevert(ClprParlia.UnauthorizedSealer.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_sealedForOtherChainId() public {
        // Same validators, but the header is sealed for chain 56: recovery yields a foreign address.
        Hdr memory h = _headerForChain(
            56, 1100, keccak256(abi.encode("parent", uint64(1100))), stateRoot, _plainExtraBody(), setA[0].ecdsaPk
        );
        bytes memory bundle =
            _bundle(_emptyList(), _entries(setA), _finality(setA, _allBits(N), h), accountProof, storageProof);
        vm.expectPartialRevert(ClprParlia.UnauthorizedSealer.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    // ── Tenure window (stale / replayed / not-yet-rotated) ────────────────────

    function test_revertWhen_sourceBeforeActiveFrom() public {
        bytes memory bundle = _plainBundle(setA, 1005, _allBits(N));
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.StaleAttestation.selector, 1005, ACTIVE_A));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_targetBeyondTenure() public {
        // Set A's last target is E_B + checkLen = 1219; source 1219 → target 1220 belongs to set B.
        bytes memory bundle = _plainBundle(setA, 1219, _allBits(N));
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.AttestationBeyondTenure.selector, 1220, 1219));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_oldSetAttestationReplayedAfterRotation() public {
        // After rotating to B, a (genuine) bundle finalized by set A is stale.
        bytes memory oldBundle = _plainBundle(setA, 1100, _allBits(N));
        bytes memory anchorB = _anchor(setB, E_B, _activeB());
        vm.expectRevert(BscParliaVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(oldBundle, anchorB, _channelContext());
        // Even re-supplying set B's keys, the old source block precedes B's tenure.
        Hdr memory h = _stateHeader(1100, setB);
        bytes memory b2 =
            _bundle(_emptyList(), _entries(setB), _finality(setB, _allBits(N), h), accountProof, storageProof);
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.StaleAttestation.selector, 1100, _activeB()));
        verifier.verifyBundle(b2, anchorB, _channelContext());
    }

    function test_revertWhen_rotationReplayed() public {
        bytes memory anchorB = _anchor(setB, E_B, _activeB());
        Hdr memory s = _stateHeader(1230, setB);
        bytes memory bundle = _bundle(
            _list1(_rotationStep(setA, setB, E_B, true)),
            _entries(setB),
            _finality(setB, _allBits(N), s),
            accountProof,
            storageProof
        );
        // Replaying the already-applied rotation: its epoch block precedes the current set's tenure.
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.StaleAttestation.selector, E_B, _activeB()));
        verifier.verifyBundle(bundle, anchorB, _channelContext());
    }

    function test_revertWhen_rotationSkipsEpoch() public {
        bytes memory step = _rotationStep(setA, setB, E_B + EPOCH_LENGTH, true);
        Hdr memory s = _stateHeader(1100, setA);
        bytes memory bundle =
            _bundle(_list1(step), _entries(setA), _finality(setA, _allBits(N), s), accountProof, storageProof);
        // Epoch 1400 is outside set A's tenure (its attestation target 1401 > 1219) — rejected before
        // the sequence check; an in-tenure non-successor epoch block is covered below.
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.AttestationBeyondTenure.selector, 1401, 1219));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_rotationEpochOutOfSequence() public {
        // A block inside A's tenure presented as the next epoch block.
        bytes memory step = _rotationStep(setA, setB, E_B - 50, true);
        Hdr memory s = _stateHeader(1100, setA);
        bytes memory bundle =
            _bundle(_list1(step), _entries(setA), _finality(setA, _allBits(N), s), accountProof, storageProof);
        vm.expectRevert(abi.encodeWithSelector(BscParliaVerifier.EpochOutOfSequence.selector, E_B, E_B - 50));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_rotationKeysDoNotMatchEpochBlock() public {
        Hdr memory e = _header(E_B, keccak256("p"), bytes32(0), _epochExtraBody(setB, TURN_LENGTH), setA[1].ecdsaPk);
        bytes memory step = _triple(_chain(e), _finalize(setA, _allBits(N), e), _keysList(setA)); // wrong keys
        Hdr memory s = _stateHeader(1230, setB);
        bytes memory bundle =
            _bundle(_list1(step), _entries(setA), _finality(setB, _allBits(N), s), accountProof, storageProof);
        vm.expectRevert(abi.encodeWithSelector(ClprParlia.InvalidValidatorKey.selector, 0));
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_rotationClaimsUnchangedSet() public {
        Hdr memory s = _stateHeader(1230, setB);
        bytes memory bundle = _bundle(
            _list1(_rotationStep(setA, setB, E_B, false)),
            _entries(setA),
            _finality(setB, _allBits(N), s),
            accountProof,
            storageProof
        );
        vm.expectRevert(BscParliaVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_rotationNotSignedByOutgoingSet() public {
        Hdr memory e = _header(E_B, keccak256("p"), bytes32(0), _epochExtraBody(setB, TURN_LENGTH), setA[1].ecdsaPk);
        // Incoming set self-certifies its own epoch block.
        bytes memory step = _triple(_chain(e), _finalize(setB, _allBits(N), e), _keysList(setB));
        Hdr memory s = _stateHeader(1230, setB);
        bytes memory bundle =
            _bundle(_list1(step), _entries(setA), _finality(setB, _allBits(N), s), accountProof, storageProof);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_epochValidatorsUnsorted() public {
        Val[] memory unsorted = _makeSet(N, "B");
        (unsorted[0], unsorted[1]) = (unsorted[1], unsorted[0]);
        bytes memory step = _rotationStep(setA, unsorted, E_B, true);
        Hdr memory s = _stateHeader(1100, setA);
        bytes memory bundle =
            _bundle(_list1(step), _entries(setA), _finality(setA, _allBits(N), s), accountProof, storageProof);
        vm.expectRevert(ClprParlia.ValidatorsNotSorted.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    // ── Storage proof / anchor binding ────────────────────────────────────────

    function test_revertWhen_storageProofForOtherChannel() public {
        (bytes32 sr, bytes memory sp) = _buildChannelStorageProof6(bytes32(uint256(0xDEAD)));
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(SERVICE_ADDR, sr, SERVICE_CODE_HASH);
        Hdr memory h = _header(1100, keccak256("p"), root, _plainExtraBody(), setA[0].ecdsaPk);
        bytes memory bundle = _bundle(_emptyList(), _entries(setA), _finality(setA, _allBits(N), h), ap, sp);
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_codeHashMismatch() public {
        bytes memory anchor = _anchorFull(setA, E_A, ACTIVE_A, CHAIN_ID, keccak256("other code"));
        bytes memory bundle = _plainBundle(setA, 1100, _allBits(N));
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(bundle, anchor, _channelContext());
    }

    function test_revertWhen_stateRootNotInHeader() public {
        Hdr memory h = _header(1100, keccak256("p"), keccak256("other root"), _plainExtraBody(), setA[0].ecdsaPk);
        bytes memory bundle =
            _bundle(_emptyList(), _entries(setA), _finality(setA, _allBits(N), h), accountProof, storageProof);
        vm.expectRevert();
        verifier.verifyBundle(bundle, _anchorA(), _channelContext());
    }

    function test_revertWhen_anchorMalformed() public {
        bytes memory bundle = _plainBundle(setA, 1100, _allBits(N));
        vm.expectRevert(BscParliaVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(bundle, hex"00", _channelContext());
        bytes memory zeroTurn = _anchorA();
        zeroTurn[160] = 0x00;
        vm.expectRevert(BscParliaVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(bundle, zeroTurn, _channelContext());
    }

    function test_revertWhen_payloadShapeWrong() public {
        vm.expectRevert(BscParliaVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(_list1(hex"80"), _anchorA(), _channelContext());
    }

    // ── Endpoint manifest ─────────────────────────────────────────────────────

    function _manifestState(bytes memory preimage)
        internal
        pure
        returns (bytes32 root, bytes memory ap, bytes memory channelSp, bytes memory manifestSp)
    {
        bytes memory nodes;
        bytes32 sr;
        (sr, nodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(uint256(18)))), RLP.encode(uint256(keccak256(preimage)))
        );
        bytes32 cBase = keccak256(abi.encode(CHANNEL_ID, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            entries[i] = _pair(RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i]))), nodes);
        }
        channelSp = RLP.encode(entries);
        manifestSp = _list1(_pair(RLP.encode(abi.encodePacked(bytes32(uint256(18)))), nodes));
        (root, ap) = _buildSyntheticAccountProof(SERVICE_ADDR, sr, SERVICE_CODE_HASH);
    }

    function _manifest() internal pure returns (bytes memory) {
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](1);
        eps[0] = ClprTypes.Endpoint({ipAddress: "10.1.2.3", port: 50211, tlsCertificate: hex"AA", accountId: hex"01"});
        return ClprProtobuf.encodeEndpointManifest(
            ClprTypes.ClprEndpointManifest({version: 2, serviceAddress: abi.encodePacked(SERVICE_ADDR), endpoints: eps})
        );
    }

    function test_verifyBundle_endpointManifest() public view {
        bytes memory preimage = _manifest();
        (bytes32 root, bytes memory ap, bytes memory csp, bytes memory msp) = _manifestState(preimage);
        Hdr memory h = _header(1100, keccak256("p"), root, _plainExtraBody(), setA[0].ecdsaPk);
        bytes[] memory top = new bytes[](8);
        top[0] = _emptyList();
        top[1] = _entries(setA);
        top[2] = _finality(setA, _allBits(N), h);
        top[3] = ap;
        top[4] = csp;
        top[5] = RLP.encode(new bytes(0));
        top[6] = msp;
        top[7] = RLP.encode(preimage);
        (,,,, ClprTypes.ClprEndpointManifest memory m) =
            verifier.verifyBundle(RLP.encode(top), _anchorA(), _channelContext());
        assertEq(m.version, 2);
        assertEq(m.endpoints.length, 1);
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function _epochA() internal view returns (Hdr memory) {
        return _header(E_A, keccak256("p"), bytes32(0), _epochExtraBody(setA, TURN_LENGTH), setA[0].ecdsaPk);
    }

    function test_verifyConfig_bootstrapsAnchor() public view {
        bytes memory cfg = _configProof("eip155:97", CHAIN_ID, _epochA(), ACTIVE_A, setA, SERVICE_CODE_HASH);
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory svc,,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory m
        ) = verifier.verifyConfig(cfg, CHANNEL_ID, "");
        assertEq(ctx, _channelContext());
        assertEq(chainId, "eip155:97");
        assertEq(svc, abi.encodePacked(SERVICE_ADDR));
        assertEq(anchor, _anchorA(), "bootstrapped anchor");
        assertEq(anchorId, abi.encodePacked(E_A));
        assertEq(m.version, 0, "no manifest proof: uninitialized");
        // The bootstrapped anchor verifies a real bundle.
        verifier.verifyBundle(_plainBundle(setA, 1100, _allBits(N)), anchor, ctx);
    }

    function test_verifyConfig_withManifestProof() public view {
        bytes memory preimage = _manifest();
        (bytes32 root, bytes memory ap,, bytes memory msp) = _manifestState(preimage);
        Hdr memory h = _header(1100, keccak256("p"), root, _plainExtraBody(), setA[0].ecdsaPk);
        bytes[] memory p = new bytes[](4);
        p[0] = _finality(setA, _allBits(N), h);
        p[1] = ap;
        p[2] = msp;
        p[3] = RLP.encode(preimage);
        bytes memory cfg = _configProof("eip155:97", CHAIN_ID, _epochA(), ACTIVE_A, setA, SERVICE_CODE_HASH);
        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) = verifier.verifyConfig(cfg, CHANNEL_ID, RLP.encode(p));
        assertEq(m.version, 2);
    }

    function test_revertWhen_verifyConfig_chainIdMismatch() public {
        bytes memory cfg = _configProof("eip155:56", CHAIN_ID, _epochA(), ACTIVE_A, setA, SERVICE_CODE_HASH);
        vm.expectRevert(BscParliaVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revertWhen_verifyConfig_activeFromOutOfRange() public {
        bytes memory cfg = _configProof("eip155:97", CHAIN_ID, _epochA(), E_A, setA, SERVICE_CODE_HASH);
        vm.expectRevert(BscParliaVerifier.InvalidConfigPayload.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
        cfg = _configProof("eip155:97", CHAIN_ID, _epochA(), E_A + EPOCH_LENGTH + 1, setA, SERVICE_CODE_HASH);
        vm.expectRevert(BscParliaVerifier.InvalidConfigPayload.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revertWhen_verifyConfig_notEpochBlock() public {
        Hdr memory e = _header(E_A + 1, keccak256("p"), bytes32(0), _epochExtraBody(setA, TURN_LENGTH), setA[0].ecdsaPk);
        bytes memory cfg = _configProof("eip155:97", CHAIN_ID, e, ACTIVE_A, setA, SERVICE_CODE_HASH);
        vm.expectRevert(BscParliaVerifier.InvalidConfigPayload.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revertWhen_verifyConfig_keysDoNotMatch() public {
        bytes memory cfg = _configProof("eip155:97", CHAIN_ID, _epochA(), ACTIVE_A, setB, SERVICE_CODE_HASH);
        vm.expectRevert(abi.encodeWithSelector(ClprParlia.InvalidValidatorKey.selector, 0));
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revertWhen_verifyConfig_empty() public {
        vm.expectRevert(BscParliaVerifier.InvalidPayloadShape.selector);
        verifier.verifyConfig("", CHANNEL_ID, "");
    }
}
