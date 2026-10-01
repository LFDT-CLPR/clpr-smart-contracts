// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AvalancheWarpFixtures} from "@test/verifiers/evm/avalanche/AvalancheWarpFixtures.sol";
import {AvalancheWarpVerifier} from "@hiero-ledger/clpr/verifiers/evm/avalanche/AvalancheWarpVerifier.sol";
import {ClprAvalancheWarp as Warp} from "@hiero-ledger/clpr/libraries/proof/avalanche/ClprAvalancheWarp.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Harness exposing library internals.
contract AvalancheWarpLibHarness {
    function message(uint32 n, bytes32 c, bytes32 h) external pure returns (bytes memory) {
        return Warp.blockHashMessage(n, c, h);
    }

    function aggregate(bytes memory set, bytes memory signers) external view returns (bytes memory, uint256) {
        return Warp.aggregateSigners(set, signers);
    }

    function validate(bytes memory set, uint256 total) external view {
        Warp.validate(set, total);
    }
}

contract AvalancheWarpVerifierTest is AvalancheWarpFixtures {
    AvalancheWarpVerifier internal verifier;
    AvalancheWarpLibHarness internal lib;
    Set internal set4;

    function setUp() public {
        verifier = new AvalancheWarpVerifier();
        lib = new AvalancheWarpLibHarness();
        _setupAttestors();
        Set memory s = _equalSet(4, "set4");
        _store(s);
    }

    function _store(Set memory s) internal {
        delete set4.vals;
        for (uint256 i = 0; i < s.vals.length; i++) {
            set4.vals.push(s.vals[i]);
        }
        set4.packed = s.packed;
        set4.totalWeight = s.totalWeight;
    }

    function _s() internal view returns (Set memory) {
        return set4;
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory newAnchor, bytes memory newId)
    {
        (m,, newAnchor, newId,) = verifier.verifyBundle(proof, anchor, _channelContext());
    }

    // ── Wire format ───────────────────────────────────────────────────────────

    /// The 80-byte UnsignedMessage matches avalanchego's codec byte for byte (vector: the Fuji
    /// message the public ACP-118 aggregator signed during capture, block 0x80364bce…).
    function test_blockHashMessage_matchesAvalanchegoCodec() public view {
        bytes memory m = lib.message(5, C_CHAIN_ID, 0x80364bce71cba1a6bbe52f7578c67d7eccdb62c327f9e80cd1d2518d2fccdc93);
        assertEq(
            m,
            hex"0000000000057fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d50000002600000000000080364bce71cba1a6bbe52f7578c67d7eccdb62c327f9e80cd1d2518d2fccdc93"
        );
    }

    function test_bits_bigEndianMinimal() public pure {
        uint256[] memory idx = new uint256[](2);
        idx[0] = 0;
        idx[1] = 9;
        assertEq(_bits(idx), hex"0201"); // bit 9 → byte 0 bit 1, bit 0 → last byte bit 0
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_verifyBundle_allSigners() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory a, bytes memory id) =
            _verify(_signedBundle(_s(), _range(0, 4), _noRotation()), _anchor(_s(), P_HEIGHT, P_TIME));
        assertEq(m.nextMessageId, 1);
        assertEq(a.length, 0);
        assertEq(id.length, 0);
    }

    /// 3 of 4 equal weights = 75% ≥ 67%.
    function test_verifyBundle_threeOfFour() public view {
        uint256[] memory idx = new uint256[](3);
        (idx[0], idx[1], idx[2]) = (0, 2, 3);
        _verify(_signedBundle(_s(), idx, _noRotation()), _anchor(_s(), P_HEIGHT, P_TIME));
    }

    /// Plain 4-field (subnet-evm) accounts are accepted too.
    function test_verifyBundle_fourFieldAccount() public view {
        (bytes32 storageRoot, bytes memory storage_) = _buildChannelStorageProof6(CHANNEL_ID);
        (bytes32 stateRoot, bytes memory account) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        Hdr memory h = _header(7, stateRoot, BLOCK_TIME);
        bytes memory proof =
            _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), _s().packed, hex"80", account, storage_);
        _verify(proof, _anchor(_s(), P_HEIGHT, P_TIME));
    }

    /// Weighted quorum boundary: 67 of 100 passes, 66 of 100 does not (avalanchego VerifyWeight).
    function test_quorum_exactBoundary() public {
        uint64[] memory w = new uint64[](3);
        (w[0], w[1], w[2]) = (34, 33, 33);
        Set memory s = _makeSet(3, "boundary", w);
        // Find the two validators whose weights sum to exactly 67 and 66.
        uint256 i34;
        for (uint256 i = 0; i < 3; i++) {
            if (s.vals[i].weight == 34) i34 = i;
        }
        uint256 other = i34 == 0 ? 1 : 0;
        uint256[] memory pass = new uint256[](2);
        (pass[0], pass[1]) = i34 < other ? (i34, other) : (other, i34);
        _verify(_signedBundle(s, pass, _noRotation()), _anchor(s, P_HEIGHT, P_TIME));

        uint256[] memory fail = new uint256[](2);
        uint256 k;
        for (uint256 i = 0; i < 3; i++) {
            if (i != i34) fail[k++] = i;
        }
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InsufficientSignedWeight.selector, 66, 100),
            _signedBundle(s, fail, _noRotation()),
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    /// Validators without a BLS key count in totalWeight (avalanchego WarpSet.TotalWeight).
    function test_quorum_countsKeylessWeight() public {
        Set memory s = _s();
        s.totalWeight += 2e9; // keyless validators holding 2/6 of the stake
        uint256[] memory idx = _range(0, 4); // 4/6 = 66.6% < 67%
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InsufficientSignedWeight.selector, 4e9, 6e9),
            _signedBundle(s, idx, _noRotation()),
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    // ── Signature / quorum negatives ──────────────────────────────────────────

    function test_rejects_belowThreshold() public {
        uint256[] memory idx = _range(0, 2); // 50%
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InsufficientSignedWeight.selector, 2e9, 4e9),
            _signedBundle(_s(), idx, _noRotation()),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_badSignature_wrongSigners() public {
        // Signed by 0,1,2 but the bit set claims 1,2,3.
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory sig = _signMessage(_s(), _range(0, 3), Warp.blockHashMessage(NETWORK_ID, C_CHAIN_ID, h.hash));
        bytes memory w = _pair(RLP.encode(_bits(_range(1, 4))), RLP.encode(sig));
        _expectBundleRevert(
            abi.encodeWithSelector(ClprBeaconBls.BlsSignatureInvalid.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_badSignature_otherBlock() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory w = _warpSig(_s(), _range(0, 4), keccak256("another block"));
        _expectBundleRevert(
            abi.encodeWithSelector(ClprBeaconBls.BlsSignatureInvalid.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    /// A signature from another Avalanche network / chain (Warp binds networkID + sourceChainID).
    function test_rejects_signatureForOtherChain() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory w = _warpSigFor(_s(), _range(0, 4), 1, C_CHAIN_ID, h.hash);
        _expectBundleRevert(
            abi.encodeWithSelector(ClprBeaconBls.BlsSignatureInvalid.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
        w = _warpSigFor(_s(), _range(0, 4), NETWORK_ID, keccak256("other chain"), h.hash);
        _expectBundleRevert(
            abi.encodeWithSelector(ClprBeaconBls.BlsSignatureInvalid.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_bitSet_leadingZeroByte() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory sig = _signMessage(_s(), _range(0, 4), Warp.blockHashMessage(NETWORK_ID, C_CHAIN_ID, h.hash));
        bytes memory w = _pair(RLP.encode(bytes(hex"000f")), RLP.encode(sig));
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InvalidSignerBitSet.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_bitSet_indexBeyondSet() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory sig = _signMessage(_s(), _range(0, 4), Warp.blockHashMessage(NETWORK_ID, C_CHAIN_ID, h.hash));
        bytes memory w = _pair(RLP.encode(bytes(hex"1f")), RLP.encode(sig)); // bit 4 with n = 4
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InvalidSignerBitSet.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_emptyBitSet() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory w = _pair(RLP.encode(new bytes(0)), RLP.encode(new bytes(256)));
        _expectBundleRevert(
            abi.encodeWithSelector(Warp.InvalidSignerBitSet.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_signatureWrongLength() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory w = _pair(RLP.encode(bytes(hex"0f")), RLP.encode(new bytes(96))); // compressed form not accepted
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.InvalidWarpSignature.selector),
            _bundle(h.rlp, w, _s().packed, hex"80", account, storage_),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    // ── Validator-set binding ─────────────────────────────────────────────────

    /// A quorum of a DIFFERENT (attacker) set, with the anchor still committing to the real one.
    function test_rejects_wrongValidatorSet() public {
        Set memory attacker = _equalSet(4, "attacker");
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.ValidatorSetMismatch.selector),
            _signedBundle(attacker, _range(0, 4), _noRotation()),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    /// Re-weighting the real keys (same keys, inflated weights for the signers) changes the set hash.
    function test_rejects_reweightedSet() public {
        Set memory s = _s();
        bytes memory forged = bytes.concat(s.packed);
        forged[103] = 0xff; // weight of validator 0
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory proof = _bundle(h.rlp, _warpSig(s, _range(0, 1), h.hash), forged, hex"80", account, storage_);
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.ValidatorSetMismatch.selector),
            proof,
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    // ── Freshness ─────────────────────────────────────────────────────────────

    function test_rejects_blockBeforeSet() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, P_TIME - 1);
        bytes memory proof =
            _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), _s().packed, hex"80", account, storage_);
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.BlockBeforeValidatorSet.selector, P_TIME - 1, P_TIME),
            proof,
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rejects_staleSet() public {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        uint64 t = P_TIME + MAX_AGE + 1;
        Hdr memory h = _header(100, stateRoot, t);
        bytes memory proof =
            _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), _s().packed, hex"80", account, storage_);
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.ValidatorSetExpired.selector, t, P_TIME + MAX_AGE),
            proof,
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    // ── Storage / account ─────────────────────────────────────────────────────

    function test_rejects_wrongStorageProof() public {
        (bytes32 stateRoot, bytes memory account,) = _serviceState();
        (, bytes memory otherStorage) = _buildChannelStorageProof6(bytes32(uint256(0xBAD)));
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes memory proof =
            _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), _s().packed, hex"80", account, otherStorage);
        _expectBundleRevert("", proof, _anchor(_s(), P_HEIGHT, P_TIME));
    }

    function test_rejects_accountNotUnderSignedRoot() public {
        (, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, keccak256("other state"), BLOCK_TIME);
        bytes memory proof =
            _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), _s().packed, hex"80", account, storage_);
        _expectBundleRevert("", proof, _anchor(_s(), P_HEIGHT, P_TIME));
    }

    function test_rejects_codeHashMismatch() public {
        bytes memory anchor =
            _anchorFull(_s(), P_HEIGHT, P_TIME, MAX_AGE, NETWORK_ID, bytes32(uint256(1)), _attestorsHash(2));
        _expectBundleRevert(
            abi.encodeWithSelector(ClprEvmBundleVerifier.CodeHashMismatch.selector),
            _signedBundle(_s(), _range(0, 4), _noRotation()),
            anchor
        );
    }

    function test_rejects_badAnchorLength() public {
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.InvalidTrustAnchor.selector),
            _signedBundle(_s(), _range(0, 4), _noRotation()),
            hex"00"
        );
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    function _who(uint256 a, uint256 b) internal pure returns (uint256[] memory w) {
        w = new uint256[](2);
        (w[0], w[1]) = (a, b);
    }

    function test_rotation_advancesAnchor() public view {
        Set memory next = _equalSet(5, "next");
        uint64 h2 = P_HEIGHT + 50;
        uint64 t2 = P_TIME + 300;
        bytes memory rot = _rotation(next, h2, t2, 2, _who(0, 2));
        (, bytes memory a, bytes memory id) =
            _verify(_signedBundle(next, _range(0, 4), rot), _anchor(_s(), P_HEIGHT, P_TIME));
        assertEq(a, _anchor(next, h2, t2));
        assertEq(id, abi.encodePacked(h2));
    }

    /// After a rotation the bundle must be signed by the NEW set; the old set no longer counts.
    function test_rotation_requiresNewSetSignature() public {
        Set memory next = _equalSet(5, "next");
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME, 2, _who(0, 1));
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        // Signature by the OLD set's validators, bit set interpreted against the new set.
        bytes memory proof = _bundle(h.rlp, _warpSig(_s(), _range(0, 4), h.hash), next.packed, rot, account, storage_);
        _expectBundleRevert(
            abi.encodeWithSelector(ClprBeaconBls.BlsSignatureInvalid.selector), proof, _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rotation_rejectsReplay() public {
        Set memory next = _equalSet(5, "next");
        uint64 h2 = P_HEIGHT + 50;
        bytes memory rot = _rotation(next, h2, P_TIME + 1, 2, _who(0, 1));
        bytes memory proof = _signedBundle(next, _range(0, 4), rot);
        (, bytes memory a,) = _verify(proof, _anchor(_s(), P_HEIGHT, P_TIME));
        _expectBundleRevert(abi.encodeWithSelector(AvalancheWarpVerifier.RotationNotNewer.selector, h2, h2), proof, a);
    }

    function test_rotation_rejectsOlderTimestamp() public {
        Set memory next = _equalSet(5, "next");
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME - 1, 2, _who(0, 1));
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.RotationNotNewer.selector, P_HEIGHT + 1, P_HEIGHT),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rotation_rejectsInsufficientAttestations() public {
        Set memory next = _equalSet(5, "next");
        uint256[] memory one = new uint256[](1);
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME, 2, one);
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.InsufficientAttestations.selector, 1, 2),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rotation_rejectsDuplicateAttestation() public {
        Set memory next = _equalSet(5, "next");
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME, 2, _who(1, 1));
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.AttestorsNotSorted.selector),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    /// Signatures by keys outside the attestor policy do not count.
    function test_rotation_ignoresOutsiders() public {
        Set memory next = _equalSet(5, "next");
        uint64 h2 = P_HEIGHT + 1;
        bytes32 d = _digest(h2, P_TIME, keccak256(next.packed), next.totalWeight);
        (uint256 pkA, uint256 pkB) = (uint256(0xE11), uint256(0xE12));
        if (vm.addr(pkA) > vm.addr(pkB)) (pkA, pkB) = (pkB, pkA);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = RLP.encode(_attSig(pkA, d));
        sigs[1] = RLP.encode(_attSig(pkB, d));
        bytes memory rot = _rotationRaw(h2, P_TIME, next.totalWeight, 2, _attestorList(), RLP.encode(sigs));
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.InsufficientAttestations.selector, 0, 2),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    /// Attestations over a different set (e.g. the set with different weights) don't verify for this one.
    function test_rotation_rejectsAttestationForOtherSet() public {
        Set memory next = _equalSet(5, "next");
        Set memory other = _equalSet(5, "other");
        bytes32 d = _digest(P_HEIGHT + 1, P_TIME, keccak256(other.packed), other.totalWeight);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = RLP.encode(_attSig(attestorPks[0], d));
        sigs[1] = RLP.encode(_attSig(attestorPks[1], d));
        bytes memory rot = _rotationRaw(P_HEIGHT + 1, P_TIME, next.totalWeight, 2, _attestorList(), RLP.encode(sigs));
        // Recovered addresses are unrelated keys → insufficient (or unsorted).
        _expectBundleRevert("", _signedBundle(next, _range(0, 4), rot), _anchor(_s(), P_HEIGHT, P_TIME));
    }

    function test_rotation_rejectsOtherAttestorPolicy() public {
        Set memory next = _equalSet(5, "next");
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME, 1, _who(0, 1)); // threshold 1 ≠ anchor's 2
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.AttestorSetMismatch.selector),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    function test_rotation_disabledWhenThresholdZero() public {
        Set memory next = _equalSet(5, "next");
        bytes memory anchor =
            _anchorFull(_s(), P_HEIGHT, P_TIME, MAX_AGE, NETWORK_ID, SERVICE_CODE_HASH, _attestorsHash(0));
        bytes memory rot = _rotation(next, P_HEIGHT + 1, P_TIME, 0, _who(0, 1));
        _expectBundleRevert(
            abi.encodeWithSelector(AvalancheWarpVerifier.RotationDisabled.selector),
            _signedBundle(next, _range(0, 4), rot),
            anchor
        );
    }

    function test_rotation_rejectsMalformedSignature() public {
        Set memory next = _equalSet(5, "next");
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = RLP.encode(bytes(hex"1234"));
        bytes memory rot = _rotationRaw(P_HEIGHT + 1, P_TIME, next.totalWeight, 2, _attestorList(), RLP.encode(sigs));
        _expectBundleRevert(
            abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2),
            _signedBundle(next, _range(0, 4), rot),
            _anchor(_s(), P_HEIGHT, P_TIME)
        );
    }

    // ── Set validation (config + rotation) ────────────────────────────────────

    function test_validate_rejectsUnsortedSet() public {
        Set memory s = _equalSet(3, "unsorted");
        bytes memory swapped =
            bytes.concat(_slice(s.packed, 104, 208), _slice(s.packed, 0, 104), _slice(s.packed, 208, 312));
        vm.expectRevert(abi.encodeWithSelector(Warp.ValidatorSetNotCanonical.selector, 1));
        lib.validate(swapped, s.totalWeight);
    }

    function test_validate_rejectsDuplicateKey() public {
        Set memory s = _equalSet(2, "dup");
        bytes memory dup = bytes.concat(_slice(s.packed, 0, 104), _slice(s.packed, 0, 104));
        vm.expectRevert(abi.encodeWithSelector(Warp.ValidatorSetNotCanonical.selector, 1));
        lib.validate(dup, 2e9);
    }

    function test_validate_rejectsZeroWeight() public {
        uint64[] memory w = new uint64[](2);
        (w[0], w[1]) = (0, 5);
        Set memory s = _makeSet(2, "zw", w);
        vm.expectRevert();
        lib.validate(s.packed, 5);
    }

    function test_validate_rejectsWeightAboveTotal() public {
        vm.expectRevert(abi.encodeWithSelector(Warp.ValidatorWeightExceedsTotal.selector, 4e9, 4e9 - 1));
        lib.validate(_s().packed, 4e9 - 1);
    }

    function test_validate_rejectsOffCurveKey() public {
        bytes memory bad = bytes.concat(_s().packed);
        bad[150] = bytes1(uint8(bad[150]) ^ 1); // y of validator 1
        vm.expectRevert();
        lib.validate(bad, 4e9);
    }

    function test_validate_rejectsBadLength() public {
        vm.expectRevert(abi.encodeWithSelector(Warp.InvalidValidatorSetLength.selector, 103));
        lib.validate(new bytes(103), 1);
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function test_verifyConfig_buildsAnchor() public view {
        (bytes memory ctx, string memory chainId, bytes memory svc,,, bytes memory anchor, bytes memory id,) =
            verifier.verifyConfig(_configProof("eip155:43113", EVM_CHAIN_ID, _s(), 2), CHANNEL_ID, "");
        assertEq(chainId, "eip155:43113");
        assertEq(svc, abi.encodePacked(SERVICE_ADDR));
        assertEq(ctx, _channelContext());
        assertEq(anchor, _anchor(_s(), P_HEIGHT, P_TIME));
        assertEq(id, abi.encodePacked(P_HEIGHT));
        // And the anchor verifies a bundle.
        verifier.verifyBundle(_signedBundle(_s(), _range(0, 4), _noRotation()), anchor, ctx);
    }

    function test_verifyConfig_rejectsCaip2Mismatch() public {
        vm.expectRevert(AvalancheWarpVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(_configProof("eip155:43114", EVM_CHAIN_ID, _s(), 2), CHANNEL_ID, "");
    }

    /// Fuji's (networkId, C-Chain id) cannot be advertised as mainnet's EVM chain.
    function test_verifyConfig_rejectsKnownChainMismatch() public {
        vm.expectRevert(AvalancheWarpVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(_configProof("eip155:43114", 43114, _s(), 2), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsThresholdAboveAttestors() public {
        vm.expectRevert(AvalancheWarpVerifier.InvalidConfigPayload.selector);
        verifier.verifyConfig(_configProof("eip155:43113", EVM_CHAIN_ID, _s(), 4), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsUnsortedAttestors() public {
        bytes[] memory a = new bytes[](2);
        a[0] = RLP.encode(attestorAddrs[1]);
        a[1] = RLP.encode(attestorAddrs[0]);
        bytes memory cfg = _configProofFull(
            _ledgerConfig("eip155:43113"), EVM_CHAIN_ID, NETWORK_ID, C_CHAIN_ID, _s(), 1, RLP.encode(a)
        );
        vm.expectRevert(AvalancheWarpVerifier.AttestorsNotSorted.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_verifyConfig_manifestProof() public view {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = 2;
        m.serviceAddress = abi.encodePacked(SERVICE_ADDR);
        m.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory pre = _encodeManifest(m);
        bytes32 slot = bytes32(uint256(18));
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(pre))));
        (bytes32 root, bytes memory ap) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        Hdr memory h = _header(5, root, BLOCK_TIME);
        bytes[] memory p = new bytes[](5);
        p[0] = RLP.encode(h.rlp);
        p[1] = _warpSig(_s(), _range(0, 4), h.hash);
        p[2] = ap;
        p[3] = _list1(_pair(RLP.encode(abi.encodePacked(slot)), nodes));
        p[4] = RLP.encode(pre);
        (,,,,,,, ClprTypes.ClprEndpointManifest memory got) =
            verifier.verifyConfig(_configProof("eip155:43113", EVM_CHAIN_ID, _s(), 2), CHANNEL_ID, RLP.encode(p));
        assertEq(got.version, 2);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Arguments are fully built (precompile calls included) before `expectRevert` arms.
    function _expectBundleRevert(bytes memory err, bytes memory proof, bytes memory anchor) internal {
        if (err.length == 0) vm.expectRevert();
        else vm.expectRevert(err);
        verifier.verifyBundle(proof, anchor, _channelContext());
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; i++) {
            out[i - from] = b[i];
        }
    }

    function _encodeManifest(ClprTypes.ClprEndpointManifest memory m) internal pure returns (bytes memory) {
        return ClprProtobuf.encodeEndpointManifest(m);
    }
}

