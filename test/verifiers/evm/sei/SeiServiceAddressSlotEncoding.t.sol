// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {SeiSyntheticProofs} from "@test/helpers/SeiSyntheticProofs.sol";
import {SeiCometBftVerifierHarness} from "@test/helpers/SeiCometBftVerifierHarness.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";

/// @title SeiServiceAddressSlotEncodingTest
/// @notice Pins the `_config.serviceAddress` storage-slot encoding that `verifyConfig` demands
///         against a *hand-computed* 32-byte literal, rather than against the production formula.
///
/// @dev Why this file exists, separately from the other Sei verifier tests:
///
///      Every other Sei test builds its service-address slot value with the same
///      `or(serviceAddr20, 0x28)` assembly that `SeiCometBftVerifier.verifyConfig` uses. That makes
///      them self-confirming — when the production formula carried a spurious `shl(96, ...)`, the
///      fixtures shifted in lockstep and the suite stayed green while every real besu <-> Sei
///      `completeChannel` reverted with `ServiceAddressSlotMismatch()`.
///
///      The expected value here is instead written out by hand from Solidity's documented
///      short-`bytes` layout, so it can be checked by eye against the spec and is derived from
///      nothing in `src/`. For a 20-byte `bytes` value, a single slot holds:
///
///          [ data, left-aligned, 20B ][ zero padding, 11B ][ length * 2 = 0x28, 1B ]
///
///      For `SERVICE_ADDR = 0x5e7c1Ce1...ACce5e7C` that is exactly:
///
///          0x5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c 0000000000000000000000 28
///            ^-- 20 address bytes ------------------^ ^-- 11 zero bytes ---^ ^^ 0x28
///
///      `test_verifyConfig_acceptsHandComputedSlotValue` proves production accepts that literal;
///      `test_verifyConfig_rejectsPreFixShiftedSlotValue` proves it rejects the pre-fix encoding.
///      Together they fail if the formula in `verifyConfig` ever drifts again, in either direction.
contract SeiServiceAddressSlotEncodingTest is SeiSyntheticProofs {
    string internal constant CHAIN_ID = "sei-chain-1";
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;

    /// @dev Hand-written short-bytes(20) slot value for `SERVICE_ADDR`: the 20 address bytes,
    ///      11 zero bytes, then the `length * 2 == 40 == 0x28` tag. Deliberately NOT computed from
    ///      `SERVICE_ADDR` — a literal is the whole point of this file.
    bytes32 internal constant SERVICE_ADDR_SLOT_VALUE =
        0x5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c000000000000000000000028;

    /// @dev The value the pre-fix verifier demanded: `or(shl(96, serviceAddr20), 0x28)`. `bytes20`
    ///      is already left-aligned, so shifting left by 96 bits (12 bytes) discarded the top 12
    ///      address bytes and left only the trailing 8, followed by zero padding and the tag.
    bytes32 internal constant PRE_FIX_SHIFTED_SLOT_VALUE =
        0x5e7c1ce1acce5e7c000000000000000000000000000000000000000000000028;

    bytes32 internal constant VAL0_PK = keccak256("sei-validator-0");
    bytes32 internal constant VAL1_PK = keccak256("sei-validator-1");

    CometBftLib.SeiValidator[] internal _validators;
    SeiCometBftVerifierHarness internal harness;

    function setUp() public {
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: 100}));
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL1_PK, votingPower: 200}));

        harness = SeiCometBftVerifierHarness(
            deployCode("SeiCometBftVerifierHarness.sol:SeiCometBftVerifierHarness", abi.encode(true))
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Layout cross-check — the literal really is "address || zeros || 0x28"
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Decomposes the literal byte-by-byte so a reviewer can confirm it encodes the documented
    ///      layout without trusting any assembly. Reads the slot value as 32 bytes and checks the
    ///      three regions independently.
    function test_handComputedSlotValue_decomposesToAddressZeroPadAndLengthTag() public pure {
        bytes memory word = abi.encodePacked(SERVICE_ADDR_SLOT_VALUE);
        assertEq(word.length, 32, "slot value must be one 32-byte word");

        // Region 1 — the leading 20 bytes are the address, most-significant byte first.
        bytes memory addrBytes = new bytes(20);
        for (uint256 i = 0; i < 20; i++) {
            addrBytes[i] = word[i];
        }
        assertEq(addrBytes, abi.encodePacked(SERVICE_ADDR), "bytes[0..19] must be the service address");

        // Region 2 — the next 11 bytes are zero padding.
        for (uint256 i = 20; i < 31; i++) {
            assertEq(uint8(word[i]), 0, "bytes[20..30] must be zero padding");
        }

        // Region 3 — the final byte is the short-bytes length tag, `20 * 2`.
        assertEq(uint8(word[31]), 0x28, "bytes[31] must be the length tag 0x28");
        assertEq(uint8(word[31]), uint8(abi.encodePacked(SERVICE_ADDR).length * 2), "length tag must be len * 2");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyConfig — accepts the hand-computed value, rejects the pre-fix one
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev The regression guard: a proof carrying the hand-written literal must verify. This fails
    ///      if `verifyConfig` reintroduces the `shl(96, ...)` or otherwise changes the encoding.
    function test_verifyConfig_acceptsHandComputedSlotValue() public view {
        bytes memory configProofBytes = _buildConfigProof(SERVICE_ADDR_SLOT_VALUE);

        (, string memory gotChainId, bytes memory gotServiceAddr,,,,,) =
            harness.verifyConfig(configProofBytes, bytes32(0), "");

        assertEq(gotChainId, CHAIN_ID);
        assertEq(gotServiceAddr, abi.encodePacked(SERVICE_ADDR), "verified service address must round-trip");
    }

    /// @dev The other half of the pin: the pre-fix shifted encoding must now be rejected. Without
    ///      this, an encoding that accepted *both* forms would still pass the test above.
    function test_verifyConfig_rejectsPreFixShiftedSlotValue() public {
        bytes memory configProofBytes = _buildConfigProof(PRE_FIX_SHIFTED_SLOT_VALUE);

        vm.expectRevert(SeiCometBftVerifier.ServiceAddressSlotMismatch.selector);
        harness.verifyConfig(configProofBytes, bytes32(0), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Proof assembly
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev A complete, internally valid Sei config proof for `SERVICE_ADDR` whose single proven
    ///      storage slot carries `slotValue`. Everything except that value is well-formed, so the
    ///      only thing either test above can trip on is the slot-value check.
    function _buildConfigProof(bytes32 slotValue) internal view returns (bytes memory) {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        bytes memory validatorSetBytes = abi.encodePacked(
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(_validators[0])),
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(_validators[1]))
        );

        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 100000,
            maxQueueDepth: 50,
            maxSyncBytes: 2048,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });

        bytes memory ledgerConfigBytes = abi.encodePacked(
            PB.encodeBytesField(1, bytes(CHAIN_ID)),
            PB.encodeBytesField(2, abi.encodePacked(SERVICE_ADDR)),
            PB.encodeVarintField(3, uint64(123456789)),
            PB.encodeBytesField(4, _buildThrottlesBytes(throttles))
        );

        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(0));
        (bytes memory storageProofEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, abi.encodePacked(slotValue));
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory stateProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeaderBytes(header)),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            PB.encodeBytesField(4, storageProofEntry)
        );

        return abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, stateProofBytes)
        );
    }

    /// @dev SignedHeader half of a synthetic state proof: header plus a 2-signature commit. Mirrors
    ///      the helper in `SeiCometBftVerifier.t.sol`; the harness stubs curve verification.
    function _signedHeaderBytes(CometBftLib.SeiHeader memory header) internal view returns (bytes memory) {
        CometBftLib.SeiCommit memory commit;
        commit.height = header.height;
        commit.round = 0;
        commit.blockIdHash = harness.headerHash(header);
        commit.partSetTotal = 1;
        commit.partSetHash = bytes32(uint256(0xBBBB));
        commit.signersBits = hex"C0";
        commit.signatures = new CometBftLib.CommitSig[](2);
        commit.signatures[0] =
            CometBftLib.CommitSig({timestampSeconds: header.timeSeconds, timestampNanos: 0, signature: new bytes(64)});
        commit.signatures[1] =
            CometBftLib.CommitSig({timestampSeconds: header.timeSeconds, timestampNanos: 0, signature: new bytes(64)});
        return abi.encodePacked(
            PB.encodeBytesField(1, _buildHeaderBytes(header)),
            PB.encodeBytesField(2, _buildCommitBytes(commit, header.timeSeconds))
        );
    }
}
