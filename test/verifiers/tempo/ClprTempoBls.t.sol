// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprTempoCertificate} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoCertificate.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @dev Wrapper so `vm.expectRevert` sees an external call.
contract TempoBlsHarness {
    function verify(bytes memory sig, bytes memory message, bytes memory key) external view {
        ClprTempoBls.verifyMinSig(sig, message, key);
    }

    function compressG2(bytes memory unc) external pure returns (bytes memory) {
        return ClprBls12381.compressG2(unc);
    }

    function hashToG1(bytes memory message) external view returns (bytes memory) {
        return ClprBls12381.hashToG1(message, ClprTempoBls.DST);
    }
}

/// @title ClprTempoBlsTest
/// @notice BLS checks against real mainnet certificates and a test key.
contract ClprTempoBlsTest is TempoSyntheticProofs {
    TempoBlsHarness internal h;

    function setUp() public {
        h = new TempoBlsHarness();
    }

    // ── Real mainnet data ───────────────────────────────────────────────────

    function test_compressG2_reproducesCompiledMainnetIdentity() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        assertEq(h.compressG2(f.keyUncompressed), f.keyCompressed, "G2 compression must match the committed key");
    }

    function test_compressG1_reproducesCertificateSignature() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        assertEq(ClprBls12381.compressG1(f.sigUncompressed), f.sigCompressed, "G1 compression must match the RPC bytes");
    }

    function test_verifyMinSig_mainnetTipCertificate() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        h.verify(f.sigUncompressed, ClprTempoCertificate.finalizeMessage(f.proposal), f.keyUncompressed);
    }

    function test_verifyMinSig_mainnetBoundaryCertificate() public view {
        TempoFixture memory f = _loadTempoFixture("presto-boundary");
        h.verify(f.sigUncompressed, ClprTempoCertificate.finalizeMessage(f.proposal), f.keyUncompressed);
    }

    /// @dev constants.json is computed with @noble/curves, apart from the hard-coded constant.
    function test_negatedG2Generator_matchesFixture() public view {
        string memory json = vm.readFile(string.concat(TEMPO_FIXTURE_DIR, "constants.json"));
        assertEq(vm.parseJsonBytes(json, ".negG2Generator"), ClprBls12381.G2_GENERATOR_NEG);
    }

    function test_verifyMinSig_rejectsTamperedMessage() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory message = ClprTempoCertificate.finalizeMessage(f.proposal);
        message[message.length - 1] ^= 0x01;
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        h.verify(f.sigUncompressed, message, f.keyUncompressed);
    }

    function test_verifyMinSig_rejectsWrongNamespace() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        // A notarize vote is not a finalization.
        bytes memory message = abi.encodePacked(bytes1(0x0e), "TEMPO_NOTARIZE", f.proposal);
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        h.verify(f.sigUncompressed, message, f.keyUncompressed);
    }

    function test_verifyMinSig_rejectsForeignKey() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory otherKey = _blsPublicKey(_testKey("not-tempo"));
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        h.verify(f.sigUncompressed, ClprTempoCertificate.finalizeMessage(f.proposal), otherKey);
    }

    function test_verifyMinSig_rejectsPointOffCurve() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory badSig = f.sigUncompressed;
        badSig[127] ^= 0x01; // y no longer satisfies the curve equation
        vm.expectRevert(ClprBls12381.BlsPrecompileCallFailed.selector);
        h.verify(badSig, ClprTempoCertificate.finalizeMessage(f.proposal), f.keyUncompressed);
    }

    // ── Test signer round trip ──────────────────────────────────────────────

    function test_verifyMinSig_testSignerRoundTrip() public view {
        uint256 sk = _testKey("round-trip");
        bytes memory message = "hello tempo";
        h.verify(_blsSign(sk, message), message, _blsPublicKey(sk));
    }

    function test_hashToG1_isDeterministic() public view {
        assertEq(h.hashToG1("m"), h.hashToG1("m"));
        assertTrue(keccak256(h.hashToG1("m")) != keccak256(h.hashToG1("n")));
    }

    // ── Length and encoding guards ──────────────────────────────────────────

    function test_verifyMinSig_rejectsBadLengths() public {
        vm.expectRevert(ClprTempoBls.BadLength.selector);
        h.verify(new bytes(48), "m", new bytes(256));
        vm.expectRevert(ClprTempoBls.BadLength.selector);
        h.verify(new bytes(128), "m", new bytes(96));
    }

    function test_hashToG1_revertsWhenMapPrecompileFails() public {
        bytes memory any_ = new bytes(0);
        vm.mockCallRevert(address(0x10), any_, any_);
        vm.expectRevert(ClprBls12381.BlsPrecompileCallFailed.selector);
        h.hashToG1("m");
        vm.clearMockedCalls();
    }

    function test_hashToG1_revertsWhenMapPrecompileReturnsWrongLength() public {
        bytes memory any_ = new bytes(0);
        vm.mockCall(address(0x10), any_, new bytes(64));
        vm.expectRevert(ClprBls12381.BlsPrecompileCallFailed.selector);
        h.hashToG1("m");
        vm.clearMockedCalls();
    }

    function test_hashToG1_revertsWhenAddPrecompileFails() public {
        bytes memory any_ = new bytes(0);
        vm.mockCallRevert(address(0x0b), any_, any_);
        vm.expectRevert(ClprBls12381.BlsPrecompileCallFailed.selector);
        h.hashToG1("m");
        vm.clearMockedCalls();
    }

    function test_hashToG1_revertsWhenAddPrecompileReturnsWrongLength() public {
        bytes memory any_ = new bytes(0);
        vm.mockCall(address(0x0b), any_, new bytes(32));
        vm.expectRevert(ClprBls12381.BlsPrecompileCallFailed.selector);
        h.hashToG1("m");
        vm.clearMockedCalls();
    }

    function test_verifyMinSig_revertsWhenPairingReturnsWrongLength() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory any_ = new bytes(0);
        vm.mockCall(address(0x0f), any_, new bytes(31));
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        h.verify(f.sigUncompressed, ClprTempoCertificate.finalizeMessage(f.proposal), f.keyUncompressed);
        vm.clearMockedCalls();
    }

    function test_compressG2_rejectsBadLength() public {
        vm.expectRevert(ClprBls12381.BadLength.selector);
        h.compressG2(new bytes(96));
    }

    function test_compressG2_infinity() public view {
        bytes memory out = h.compressG2(new bytes(256));
        assertEq(out.length, 96);
        assertEq(uint8(out[0]), 0xc0, "compressed + infinity flags");
        for (uint256 i = 1; i < 96; i++) {
            assertEq(uint8(out[i]), 0);
        }
    }

    /// @dev When y.c1 is zero, the sign follows y.c0.
    function test_compressG2_signFollowsC0WhenC1IsZero() public view {
        bytes memory unc = new bytes(256);
        unc[63] = 0x01; // x.c0 = 1
        unc[127] = 0x02; // x.c1 = 2
        // y.c0 = p - 1, y.c1 = 0
        bytes memory pMinus1 =
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa";
        for (uint256 i = 0; i < 48; i++) {
            unc[128 + 16 + i] = pMinus1[i];
        }
        bytes memory out = h.compressG2(unc);
        assertEq(uint8(out[0]), 0xa0, "compressed + sign");
        assertEq(uint8(out[47]), 0x02, "x.c1 comes first");
        assertEq(uint8(out[95]), 0x01, "x.c0 comes second");

        for (uint256 i = 0; i < 48; i++) {
            unc[128 + 16 + i] = 0;
        }
        unc[128 + 63] = 0x01; // y.c0 = 1: positive
        out = h.compressG2(unc);
        assertEq(uint8(out[0]), 0x80, "compressed only");
    }
}
