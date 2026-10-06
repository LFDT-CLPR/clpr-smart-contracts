// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";

/// @dev External wrapper so `vm.expectRevert` can catch reverts from the internal library calls.
contract BlsHarness {
    function aggregateVerifyComplement(
        bytes memory aggregatePubkey,
        bytes[] memory nonParticipants,
        bytes memory signature,
        bytes32 signingRoot
    ) external view {
        ClprBeaconBls.aggregateVerifyComplement(aggregatePubkey, nonParticipants, signature, signingRoot);
    }
}

/// @dev Validates the on-chain BLS aggregate-signature pipeline (EIP-2537 G1MSM complement aggregation,
///      hash-to-G2, pairing) against self-consistent vectors built from secret key = 1.
///
///      With sk = 1 the public key is the G1 generator and a signature over message m is exactly
///      H(m) (the hash-to-G2 of the signing root). The pairing check then reduces to the identity
///      e(N·G1, H(m))·e(-G1, N·H(m)) = 1, so a correct implementation must accept it. The complement
///      path recovers the participant aggregate as committeeAggregate − Σ(non-participants), so a
///      2-member committee with one non-participant must verify against a single-signer signature.
///      This exercises the complete machinery — precompile addresses, the (r−1) MSM negation, the
///      pairing equation and the negated generator — end to end. (Cross-checking hash-to-G2
///      byte-for-byte against blst still requires one real sync-committee vector; that is a production
///      gating item, noted in the lib.)
contract ClprBeaconBlsTest is Test {
    // BLS12-381 G1 generator coordinates (the public key for secret key = 1).
    bytes internal constant G1_GEN_X =
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes internal constant G1_GEN_Y =
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    BlsHarness internal harness;

    function setUp() public {
        harness = new BlsHarness();
    }

    /// @dev EIP-2537 uncompressed G1 generator: pad16||x || pad16||y (128 bytes).
    function _generator() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y);
    }

    /// @dev G2 point addition via the EIP-2537 precompile (used to build a "2 signers" signature).
    function _g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = ClprBls12381.BLS12_G2ADD.staticcall(abi.encodePacked(a, b));
        require(ok && out.length == 256, "g2add failed");
        return out;
    }

    /// @dev `n·G1` via the EIP-2537 G1MSM precompile — the committee aggregate of `n` sk=1 members.
    function _g1Mul(uint256 n) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = ClprBls12381.BLS12_G1MSM.staticcall(abi.encodePacked(_generator(), bytes32(n)));
        require(ok && out.length == 128, "g1msm failed");
        return out;
    }

    // ── Complement aggregation (aggregate − Σ non-participants) ──────────────────

    /// Committee aggregate = 2·G1, one non-participant (G1) ⇒ participant aggregate = G1, matching a
    /// single-signer signature H(m). Exercises the MSM subtraction path (r−1 scalar negation).
    function test_aggregateVerifyComplement_subtractsNonParticipant() public view {
        bytes32 root = sha256("clpr-bls-complement");
        bytes memory aggregate = _g1Mul(2); // 2 committee members, sk=1 each
        bytes memory sig = ClprBeaconBls.hashToG2(root); // participant aggregate G1 ⇒ sig = 1·H(m)
        bytes[] memory nonParticipants = new bytes[](1);
        nonParticipants[0] = _generator();
        ClprBeaconBls.aggregateVerifyComplement(aggregate, nonParticipants, sig, root);
    }

    /// Full participation (zero non-participants) ⇒ the aggregate is used directly (no MSM).
    function test_aggregateVerifyComplement_fullParticipation_skipsMsm() public view {
        bytes32 root = sha256("clpr-bls-complement-full");
        bytes memory aggregate = _g1Mul(2);
        bytes memory hm = ClprBeaconBls.hashToG2(root);
        bytes memory sig = _g2Add(hm, hm); // 2·H(m) matches the 2·G1 aggregate
        bytes[] memory nonParticipants = new bytes[](0);
        ClprBeaconBls.aggregateVerifyComplement(aggregate, nonParticipants, sig, root);
    }

    function test_aggregateVerifyComplement_wrongSignature_reverts() public {
        bytes32 root = sha256("clpr-bls-complement-bad");
        bytes memory aggregate = _g1Mul(2);
        bytes memory sig = ClprBeaconBls.hashToG2(root); // matches 1·G1, but we leave 2·G1 (no subtraction)
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, sig, root);
    }

    /// A signature for message-A must not verify against message-B (signing-root binding).
    function test_aggregateVerifyComplement_wrongMessage_reverts() public {
        bytes memory aggregate = _g1Mul(1);
        bytes memory hm = ClprBeaconBls.hashToG2(sha256("message-A"));
        bytes memory sig = hm; // sk=1 over message-A
        bytes32 wrongRoot = sha256("message-B");
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, sig, wrongRoot);
    }

    /// A bit-flipped signature is no longer a valid G2 point ⇒ the pairing precompile rejects it.
    function test_aggregateVerifyComplement_tamperedSignature_reverts() public {
        bytes32 root = sha256("clpr-bls-complement-tampered");
        bytes memory aggregate = _g1Mul(1);
        bytes memory sig = ClprBeaconBls.hashToG2(root);
        sig[200] = bytes1(uint8(sig[200]) ^ 0x01); // flip a bit in a y-coordinate limb
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert();
        harness.aggregateVerifyComplement(aggregate, nonParticipants, sig, root);
    }

    function test_aggregateVerifyComplement_badAggregateLength_reverts() public {
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.InvalidPubkeyLength.selector);
        harness.aggregateVerifyComplement(new bytes(127), nonParticipants, new bytes(256), bytes32(0));
    }

    function test_aggregateVerifyComplement_badSignatureLength_reverts() public {
        bytes memory aggregate = _g1Mul(1); // precompute: expectRevert binds to the *next* call
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.InvalidSignatureLength.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, new bytes(255), bytes32(0));
    }

    function test_aggregateVerifyComplement_badNonParticipantLength_reverts() public {
        bytes memory aggregate = _g1Mul(1); // precompute: expectRevert binds to the *next* call
        bytes[] memory nonParticipants = new bytes[](1);
        nonParticipants[0] = new bytes(127); // not a 128-byte G1 point
        vm.expectRevert(ClprBeaconBls.InvalidPubkeyLength.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, new bytes(256), bytes32(0));
    }

    // ── Identity-element forgery defense ─────────────────────────────────────────
    //
    // EIP-2537 encodes the point at infinity as an all-zero byte string.
    // e(O, H(m)) · e(-O, O) = 1 FOR ANY MESSAGE so any identity aggregate and
    // any identity signature could make the check pass against forged signing root.

    /// @dev The core forgery vector: all-zero aggregate + all-zero signature must be rejected
    function test_aggregateVerifyComplement_zeroKeyZeroSig_identityForgeryRejected() public {
        bytes32 root = sha256("arbitrary-message-identity-forgery");
        bytes memory zeroAggregate = new bytes(128); // G1 identity: 128 zero bytes
        bytes memory zeroSignature = new bytes(256); // G2 identity: 256 zero bytes
        bytes[] memory nonParticipants = new bytes[](0);

        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(zeroAggregate, nonParticipants, zeroSignature, root);
    }

    /// @dev An identity signature paired with a legitimate (non-identity) aggregate must also be
    ///      rejected — a forger controls only the supplied signature/aggregate, so both are guarded.
    function test_aggregateVerifyComplement_realKeyZeroSig_rejected() public {
        bytes32 root = sha256("m"); // precompute: expectRevert binds to the *next* call
        bytes memory aggregate = _g1Mul(1); // real G1 generator
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, new bytes(256), root);
    }

    /// @dev Identity aggregate with a real (non-identity) signature is likewise rejected up front.
    function test_aggregateVerifyComplement_zeroKeyRealSig_rejected() public {
        bytes32 root = sha256("m");
        bytes memory sig = ClprBeaconBls.hashToG2(root); // real G2 point
        bytes memory zeroAggregate = new bytes(128);
        bytes[] memory nonParticipants = new bytes[](0);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(zeroAggregate, nonParticipants, sig, root);
    }

    /// @dev The guard covers the COMPLEMENT path too: if the non-participants subtract the whole
    ///      committee aggregate down to the identity (aggregate − aggregate = O), the resulting
    ///      participant aggregate is identity and must be rejected — not silently paired.
    function test_aggregateVerifyComplement_complementToIdentity_rejected() public {
        bytes32 root = sha256("m");
        bytes memory aggregate = _g1Mul(1); // committee aggregate = G1
        bytes[] memory nonParticipants = new bytes[](1);
        nonParticipants[0] = _generator(); // subtract the same G1 ⇒ participant aggregate = O
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.aggregateVerifyComplement(aggregate, nonParticipants, new bytes(256), root);
    }
}
