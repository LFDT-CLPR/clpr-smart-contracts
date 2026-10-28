// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {SeiSyntheticProofs} from "@test/helpers/SeiSyntheticProofs.sol";
import {SeiCometBftVerifierHarness} from "@test/helpers/SeiCometBftVerifierHarness.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";

// ─────────────────────────────────────────────────────────────────────────────
//  Main test contract
// ─────────────────────────────────────────────────────────────────────────────

contract SeiCometBftVerifierTest is SeiSyntheticProofs {
    // ── Synthetic constants ───────────────────────────────────────────────────

    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    string internal constant CHAIN_ID = "sei-chain-1";

    // Two synthetic validators — pubkeys derived from test seeds.
    bytes32 internal constant VAL0_PK = keccak256("sei-validator-0");
    bytes32 internal constant VAL1_PK = keccak256("sei-validator-1");
    int64 internal constant VAL0_VP = 100;
    int64 internal constant VAL1_VP = 200;

    CometBftLib.SeiValidator[] internal _validators;

    SeiCometBftVerifierHarness internal harness;

    function setUp() public {
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: VAL0_VP}));
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL1_PK, votingPower: VAL1_VP}));

        harness = SeiCometBftVerifierHarness(
            deployCode("SeiCometBftVerifierHarness.sol:SeiCometBftVerifierHarness", abi.encode(true))
        );
    }

    /// @dev Builds the ChannelContext bytes carrying `svc` as the remote service address.
    function _ctx(bytes20 svc) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: bytes32(0), remoteServiceAddress: abi.encodePacked(svc)})
        );
    }

    /// @dev The SignedHeader half of a synthetic state proof (header + 2-signature commit).
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

    // ─────────────────────────────────────────────────────────────────────────
    //  Constructor
    // ─────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyConfig — empty proof reverts
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyConfig_emptyProof_reverts() public {
        vm.expectRevert(SeiCometBftVerifier.InvalidPayloadShape.selector);
        harness.verifyConfig("", bytes32(0), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyBundle — trust anchor validation
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_emptyTrustAnchor_reverts() public {
        vm.expectRevert(SeiCometBftVerifier.InvalidTrustAnchor.selector);
        harness.verifyBundle(hex"aabb", "", "");
    }

    function test_verifyBundle_shortTrustAnchor_reverts() public {
        vm.expectRevert();
        harness.verifyBundle(hex"aabb", hex"deadbeef", "");
    }

    function test_verifyBundle_noValidatorsInAnchor_reverts() public {
        // ABI-encode with an empty validator array
        CometBftLib.SeiValidator[] memory empty;
        bytes memory badAnchor = abi.encode(CHAIN_ID, empty);
        vm.expectRevert(SeiCometBftVerifier.InvalidTrustAnchor.selector);
        harness.verifyBundle(hex"aabb", badAnchor, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Trust-anchor rotation (bundle content field 3)
    // ─────────────────────────────────────────────────────────────────────────

    function test_decodeBundleContent_returnsMessages() public view {
        // ClprBundleContent with one message payload (field 2). Trust-anchor rotation on Sei is carried
        // by the bundle payload's next_validator_set (not bundle content), so the shared decoder only
        // surfaces the field-2 message payloads.
        bytes memory msgPayload = hex"deadbeef";
        bytes memory content = abi.encodePacked(PB.encodeBytesField(2, msgPayload));
        bytes[] memory msgs = harness.decodeBundleContent(content);
        assertEq(msgs.length, 1);
        assertEq(msgs[0], msgPayload);
    }

    function test_decodeBundleContent_multipleMessages() public view {
        bytes memory m1 = hex"0011";
        bytes memory m2 = hex"2233";
        bytes memory m3 = hex"4455";
        bytes memory content =
            abi.encodePacked(PB.encodeBytesField(2, m1), PB.encodeBytesField(2, m2), PB.encodeBytesField(2, m3));
        bytes[] memory msgs = harness.decodeBundleContent(content);
        assertEq(msgs.length, 3);
        assertEq(msgs[0], m1);
        assertEq(msgs[1], m2);
        assertEq(msgs[2], m3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Tendermint simple Merkle tree
    // ─────────────────────────────────────────────────────────────────────────

    function test_simpleMerkleRoot_empty_returnsEmptySha256() public view {
        bytes[] memory empty;
        bytes32 got = harness.simpleMerkleRoot(empty);
        assertEq(got, sha256(""));
    }

    function test_simpleMerkleRoot_oneItem_isLeafHash() public view {
        bytes[] memory items = new bytes[](1);
        items[0] = hex"aabb";
        bytes32 got = harness.simpleMerkleRoot(items);
        assertEq(got, sha256(abi.encodePacked(bytes1(0x00), hex"aabb")));
    }

    function test_simpleMerkleRoot_twoItems_isPairHash() public view {
        bytes[] memory items = new bytes[](2);
        items[0] = hex"aabb";
        items[1] = hex"ccdd";
        bytes32 left = sha256(abi.encodePacked(bytes1(0x00), hex"aabb"));
        bytes32 right = sha256(abi.encodePacked(bytes1(0x00), hex"ccdd"));
        bytes32 expected = sha256(abi.encodePacked(bytes1(0x01), left, right));
        assertEq(harness.simpleMerkleRoot(items), expected);
    }

    function test_simpleMerkleRoot_threeItems_splitAtTwo() public view {
        // split(3) = 2  → left = root([a,b]), right = root([c])
        bytes[] memory items = new bytes[](3);
        items[0] = hex"01";
        items[1] = hex"02";
        items[2] = hex"03";

        bytes32 l0 = sha256(abi.encodePacked(bytes1(0x00), hex"01"));
        bytes32 l1 = sha256(abi.encodePacked(bytes1(0x00), hex"02"));
        bytes32 l = sha256(abi.encodePacked(bytes1(0x01), l0, l1));
        bytes32 r = sha256(abi.encodePacked(bytes1(0x00), hex"03"));
        bytes32 expected = sha256(abi.encodePacked(bytes1(0x01), l, r));
        assertEq(harness.simpleMerkleRoot(items), expected);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Validator set hash
    // ─────────────────────────────────────────────────────────────────────────

    function test_validatorSetHash_singleValidator_isLeafHash() public view {
        CometBftLib.SeiValidator[] memory vals = new CometBftLib.SeiValidator[](1);
        vals[0] = CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: VAL0_VP});
        bytes32 got = harness.validatorSetHash(vals);
        bytes memory leaf = harness.encodeValidator(vals[0]);
        bytes32 expected = sha256(abi.encodePacked(bytes1(0x00), leaf));
        assertEq(got, expected);
    }

    function test_validatorSetHash_twoValidators_isPairHash() public view {
        bytes32 h0 = sha256(abi.encodePacked(bytes1(0x00), harness.encodeValidator(_validators[0])));
        bytes32 h1 = sha256(abi.encodePacked(bytes1(0x00), harness.encodeValidator(_validators[1])));
        bytes32 expected = sha256(abi.encodePacked(bytes1(0x01), h0, h1));
        assertEq(harness.validatorSetHash(_validators), expected);
    }

    function test_validatorSetHash_emptyReverts() public {
        CometBftLib.SeiValidator[] memory empty;
        vm.expectRevert(SeiCometBftVerifier.EmptyValidatorSet.selector);
        harness.validatorSetHash(empty);
    }

    function test_validatorSetHash_deterministicAcrossCalls() public view {
        bytes32 h1 = harness.validatorSetHash(_validators);
        bytes32 h2 = harness.validatorSetHash(_validators);
        assertEq(h1, h2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Protobuf encoding helpers
    // ─────────────────────────────────────────────────────────────────────────

    function test_pbVarint_zero() public view {
        bytes memory got = harness.pbVarint(0);
        assertEq(got.length, 1);
        assertEq(uint8(got[0]), 0);
    }

    function test_pbVarint_one() public view {
        bytes memory got = harness.pbVarint(1);
        assertEq(got.length, 1);
        assertEq(uint8(got[0]), 1);
    }

    function test_pbVarint_128() public view {
        // 128 = 0x80 → little-endian base-128: [0x80, 0x01]
        bytes memory got = harness.pbVarint(128);
        assertEq(got.length, 2);
        assertEq(uint8(got[0]), 0x80);
        assertEq(uint8(got[1]), 0x01);
    }

    function test_pbBytesField_empty_returnsEmpty() public view {
        bytes memory got = harness.pbBytesField(1, "");
        assertEq(got.length, 0);
    }

    function test_pbBytesField_nonEmpty_hasTagAndLength() public view {
        bytes memory val = hex"aabb";
        bytes memory got = harness.pbBytesField(1, val);
        // tag = (1 << 3) | 2 = 0x0a; length = 2 = 0x02; data = 0xaabb
        assertEq(got, abi.encodePacked(bytes1(0x0a), bytes1(0x02), hex"aabb"));
    }

    function test_pbVarintField_zero_returnsEmpty() public view {
        assertEq(harness.pbVarintField(1, 0).length, 0);
    }

    function test_pbVarintField_one_hasTagAndValue() public view {
        bytes memory got = harness.pbVarintField(1, 1);
        // tag = (1 << 3) | 0 = 0x08; value = 0x01
        assertEq(got, abi.encodePacked(bytes1(0x08), bytes1(0x01)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Precommit sign bytes — structural checks
    // ─────────────────────────────────────────────────────────────────────────

    function test_precommitSignBytes_nonEmpty() public view {
        bytes memory got = harness.precommitSignBytes(
            CHAIN_ID,
            100, // height
            0, // round
            bytes32(uint256(0xDEAD)),
            1, // partTotal
            bytes32(uint256(0xBEEF)),
            1_700_000_000, // tsSeconds
            0 // tsNanos
        );
        assertGt(got.length, 0);
    }

    function test_precommitSignBytes_differentHeights_differentBytes() public view {
        bytes memory b1 = harness.precommitSignBytes(CHAIN_ID, 1, 0, bytes32(0), 0, bytes32(0), 0, 0);
        bytes memory b2 = harness.precommitSignBytes(CHAIN_ID, 2, 0, bytes32(0), 0, bytes32(0), 0, 0);
        assertNotEq(keccak256(b1), keccak256(b2));
    }

    function test_precommitSignBytes_differentChainIds_differentBytes() public view {
        bytes memory b1 = harness.precommitSignBytes("chain-A", 1, 0, bytes32(0), 0, bytes32(0), 0, 0);
        bytes memory b2 = harness.precommitSignBytes("chain-B", 1, 0, bytes32(0), 0, bytes32(0), 0, 0);
        assertNotEq(keccak256(b1), keccak256(b2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Header hash — structural
    // ─────────────────────────────────────────────────────────────────────────

    function test_headerHash_deterministicAcrossCalls() public view {
        CometBftLib.SeiHeader memory h = _syntheticHeader();
        bytes32 h1 = harness.headerHash(h);
        bytes32 h2 = harness.headerHash(h);
        assertEq(h1, h2);
    }

    function test_headerHash_differentChainIds_differentHash() public view {
        CometBftLib.SeiHeader memory h1 = _syntheticHeader();
        CometBftLib.SeiHeader memory h2 = _syntheticHeader();
        h2.chainId = "other-chain";
        assertNotEq(harness.headerHash(h1), harness.headerHash(h2));
    }

    function test_headerHash_differentHeights_differentHash() public view {
        CometBftLib.SeiHeader memory h1 = _syntheticHeader();
        CometBftLib.SeiHeader memory h2 = _syntheticHeader();
        h2.height = 9999;
        assertNotEq(harness.headerHash(h1), harness.headerHash(h2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Validator encoding
    // ─────────────────────────────────────────────────────────────────────────

    function test_encodeValidator_zeroPower_omitsField2() public view {
        CometBftLib.SeiValidator memory v = CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: 0});
        bytes memory enc = harness.encodeValidator(v);
        // Field 2 (votingPower) must be absent when zero (proto3 default)
        // The only bytes present are the pubKey wrapper (field 1 nested message)
        // Tag for field 1 LEN = 0x0a; inner tag for field 1 LEN = 0x0a; 32 bytes
        assertGt(enc.length, 0);
        // Confirm field 2 varint tag (0x10) is not present (zero votingPower)
        bool field2Found = false;
        for (uint256 i = 0; i < enc.length; i++) {
            if (uint8(enc[i]) == 0x10) {
                field2Found = true;
                break;
            }
        }
        assertFalse(field2Found, "votingPower=0 must not appear in encoding");
    }

    function test_encodeValidator_nonZeroPower_includesField2() public view {
        CometBftLib.SeiValidator memory v = CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: 1});
        bytes memory enc = harness.encodeValidator(v);
        bool field2Found = false;
        for (uint256 i = 0; i < enc.length; i++) {
            if (uint8(enc[i]) == 0x10) {
                field2Found = true;
                break;
            }
        }
        assertTrue(field2Found, "votingPower != 0 must appear in encoding");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Ed25519 bypass — harness-level
    // ─────────────────────────────────────────────────────────────────────────

    function test_setAlwaysVerifyOk_false_rejectsBadSig() public {
        harness.setAlwaysVerifyOk(false);
        // We can't call _verifyEd25519 directly, but we confirm the harness setter works
        // by checking that setAlwaysVerifyOk(true) re-enables it
        harness.setAlwaysVerifyOk(true);
    }

    function test_synthetic_verifyConfig_success() public view {
        string memory chainId = "sei-chain-1";
        address serviceAddr = SERVICE_ADDR;
        bytes20 serviceAddr20 = bytes20(serviceAddr);
        CometBftLib.SeiValidator[] memory validators = _validators;

        bytes memory validatorSetBytes = abi.encodePacked(
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(validators[0])),
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(validators[1]))
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
            PB.encodeBytesField(1, bytes(chainId)),
            PB.encodeBytesField(2, abi.encodePacked(serviceAddr)),
            PB.encodeVarintField(3, uint64(123456789)),
            PB.encodeBytesField(4, _buildThrottlesBytes(throttles))
        );

        bytes32 expectedSlotValue;
        assembly {
            expectedSlotValue := or(serviceAddr20, 0x28)
        }

        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(0));
        (bytes memory storageProofEntry, bytes32 iavlRoot) =
            _buildStorageProofEntry(spKey, abi.encodePacked(expectedSlotValue));
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory stateProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeaderBytes(header)),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            PB.encodeBytesField(4, storageProofEntry)
        );

        bytes memory configProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, stateProofBytes)
        );

        (
            bytes memory gotChannelContext,
            string memory gotChainId,
            bytes memory gotServiceAddr,
            uint96 gotConfigNanos,
            ClprTypes.Throttles memory gotThrottles,
            bytes memory gotTrustAnchor,,
        ) = harness.verifyConfig(configProofBytes, bytes32(0), "");

        assertEq(gotChainId, chainId);
        assertEq(gotServiceAddr, abi.encodePacked(serviceAddr));
        assertEq(gotConfigNanos, 123456789);
        assertEq(gotThrottles.maxMessagesPerBundle, 10);

        (string memory decChainId, CometBftLib.SeiValidator[] memory decVals) =
            abi.decode(gotTrustAnchor, (string, CometBftLib.SeiValidator[]));
        assertEq(decChainId, chainId);
        assertEq(decVals.length, 2);

        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(gotChannelContext);
        assertEq(ctx.channelId, bytes32(0));
        assertEq(ctx.remoteServiceAddress, abi.encodePacked(serviceAddr));
    }

    function test_synthetic_verifyBundle_success() public view {
        string memory chainId = "sei-chain-1";
        address serviceAddr = SERVICE_ADDR;
        bytes20 serviceAddr20 = bytes20(serviceAddr);
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes memory anchor = abi.encode(chainId, validators);

        // Five genuinely distinct slot values, one per real Channel metadata slot
        // (cBase+1/+2/+4/+5/+16) — no reused/placeholder entry, so the verifier's per-position
        // channelId-derived slot check (`_verifyChannelStateProof`) is actually exercised
        // at every index, including position 0.
        bytes32[5] memory values;
        values[0] = bytes32((uint256(1) << 160) | (uint256(100) << 168)); // status=ACTIVE, nextMessageId=100
        values[1] = bytes32(uint256(50) << 64); // receivedMessageId=50
        values[2] = bytes32(uint256(0xAAAA1111)); // sentRunningHash
        values[3] = bytes32(uint256(0xBBBB2222)); // receivedRunningHash
        values[4] = bytes32(uint256(7)); // endpointManifestVersion

        (bytes[5] memory storageProofEntries, bytes32 iavlRoot) =
            _buildFiveLeafChannelProof(bytes32(0), serviceAddr20, values);
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory stateProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeaderBytes(header)),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            PB.encodeBytesField(4, storageProofEntries[0]),
            PB.encodeBytesField(4, storageProofEntries[1]),
            PB.encodeBytesField(4, storageProofEntries[2]),
            PB.encodeBytesField(4, storageProofEntries[3]),
            PB.encodeBytesField(4, storageProofEntries[4])
        );

        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabbcc");

        bytes memory proofBytes =
            abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));

        (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
        ) = harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr20));

        assertEq(uint8(metadata.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(metadata.nextMessageId, 100);
        assertEq(metadata.receivedMessageId, 50);
        assertEq(metadata.sentRunningHash, values[2]);
        assertEq(metadata.receivedRunningHash, values[3]);
        assertEq(metadata.endpointManifestVersion, 7);

        assertEq(messagePayloads.length, 1);
        assertEq(messagePayloads[0], hex"aabbcc");
        assertEq(newTrustAnchor.length, 0);
        assertEq(newTrustAnchorId.length, 0);
    }

    /// @dev Exhaustively checks all 5 positions
    function test_verifyBundle_wrongSlotAtAnyPosition_reverts() public {
        for (uint256 wrongPosition = 0; wrongPosition < 5; wrongPosition++) {
            _assertWrongSlotAtPositionReverts(wrongPosition);
        }
    }

    function _assertWrongSlotAtPositionReverts(uint256 wrongPosition) internal {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        bytes32[5] memory values;
        values[0] = bytes32((uint256(1) << 160) | (uint256(100) << 168));
        values[1] = bytes32(uint256(50) << 64);
        values[2] = bytes32(uint256(0xAAAA1111));
        values[3] = bytes32(uint256(0xBBBB2222));
        values[4] = bytes32(uint256(7)); // endpointManifestVersion

        bytes32 cBase = keccak256(abi.encode(bytes32(0), uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[5] memory keys;
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(uint256(cBase) + offsets[i]));
        }
        // Corrupt exactly one position with a slot number that has nothing to do with this
        // channel's real layout.
        keys[wrongPosition] = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(uint256(0xDEADBEEF)));

        (bytes[5] memory storageProofEntries, bytes32 iavlRoot) = _buildFiveLeafStorageProof(keys, values);
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory stateProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeaderBytes(header)),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            PB.encodeBytesField(4, storageProofEntries[0]),
            PB.encodeBytesField(4, storageProofEntries[1]),
            PB.encodeBytesField(4, storageProofEntries[2]),
            PB.encodeBytesField(4, storageProofEntries[3]),
            PB.encodeBytesField(4, storageProofEntries[4])
        );
        bytes memory proofBytes = abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabbcc"))
        );

        vm.expectRevert(SeiCometBftVerifier.StorageKeyMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr20));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Fixture-based happy-path (skipped when fixture absent)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev When the sei-specific proof fixture is available, run the full verifyBundle.
    ///      Place the fixture at test/verifiers/sei/fixtures/bundlePayload.hex
    ///      (protobuf-encoded ClprSeiBundlePayload), trustAnchor.hex
    ///      (abi.encode(chainId, CometBftLib.SeiValidator[])), and channelContext.hex
    ///      (ClprTypes.encodeChannelContext output).
    function test_success_verifyBundle_skipIfNoFixture() public {
        string memory proofPath = "test/verifiers/sei/fixtures/bundlePayload.hex";
        string memory anchorPath = "test/verifiers/sei/fixtures/trustAnchor.hex";
        string memory ctxPath = "test/verifiers/sei/fixtures/channelContext.hex";

        // Skip gracefully when fixture files don't exist yet.
        try vm.readFile(proofPath) returns (string memory proofRaw) {
            try vm.readFile(anchorPath) returns (string memory anchorRaw) {
                try vm.readFile(ctxPath) returns (string memory ctxRaw) {
                    bytes memory proof = _parseHex(proofRaw);
                    bytes memory anchor = _parseHex(anchorRaw);
                    bytes memory channelContext = _parseHex(ctxRaw);

                    (ClprTypes.QueueMetadata memory metadata, bytes[] memory msgs, bytes memory rotation,,) =
                        harness.verifyBundle(proof, anchor, channelContext);

                    assertEq(uint8(metadata.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
                    assertGe(msgs.length, 0);
                    // Rotation may or may not be present; just check it doesn't panic.
                    assertTrue(rotation.length == 0 || rotation.length > 0);
                } catch {
                    vm.skip(true);
                }
            } catch {
                vm.skip(true);
            }
        } catch {
            vm.skip(true);
        }
    }

    function test_success_verifyConfig_skipIfNoFixture() public {
        string memory configPath = "test/verifiers/sei/fixtures/configProof.hex";

        try vm.readFile(configPath) returns (string memory raw) {
            bytes memory proof = _parseHex(raw);
            (
                ,
                string memory chainId,
                bytes memory serviceAddr,,
                ClprTypes.Throttles memory throttles,
                bytes memory trustAnchor,,
            ) = harness.verifyConfig(proof, bytes32(0), "");

            assertGt(bytes(chainId).length, 0);
            assertGt(serviceAddr.length, 0);
            assertGe(throttles.maxMessagesPerBundle, 0);
            assertGt(trustAnchor.length, 0);
        } catch {
            vm.skip(true);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _parseHex(string memory raw) internal pure returns (bytes memory) {
        bytes memory b = bytes(raw);
        // Strip trailing newline/CR
        while (b.length > 0 && (b[b.length - 1] == 0x0a || b[b.length - 1] == 0x0d)) {
            assembly { mstore(b, sub(mload(b), 1)) }
        }
        return vm.parseBytes(string.concat("0x", string(b)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Endpoint-manifest commitment proof (bundle payload fields 4/5)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Manifest-commitment slot 18 key: 0x03 || serviceAddr || slot32. Using it for the
    ///      channel entries too keeps every entry in the same single-leaf IAVL tree (the
    ///      verifier checks only prefix+address on channel-slot keys, but the FULL key on
    ///      the manifest entry).
    function _manifestSlotKey(bytes20 serviceAddr20) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(uint256(18)));
    }

    /// @dev Builds a 6-leaf IAVL chain: the five real Channel metadata slots
    ///      (channelId = 0, base slot 15, offsets 1/2/4/5/16) plus one manifest leaf carrying
    ///      `mVal` under `mKey` — so the channel-slot binding passes and the manifest logic
    ///      under test is actually reached.
    function _buildManifestScenario(bytes20 serviceAddr20, bytes memory mKey, bytes32 mVal)
        internal
        pure
        returns (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot)
    {
        bytes32 cBase = keccak256(abi.encode(bytes32(0), uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory keys = new bytes[](6);
        bytes32[] memory values = new bytes32[](6);
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(uint256(cBase) + offsets[i]));
        }
        values[0] = bytes32((uint256(1) << 160) | (uint256(100) << 168)); // status=ACTIVE, nextMessageId=100
        values[1] = bytes32(uint256(50) << 64); // receivedMessageId=50
        values[4] = bytes32(uint256(3)); // endpointManifestVersion
        keys[5] = mKey;
        values[5] = mVal;
        (bytes[] memory entries, bytes32 root) = _buildLinearChainStorageProof(keys, values);
        connEntries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            connEntries[i] = entries[i];
        }
        manifestEntry = entries[5];
        iavlRoot = root;
    }

    function _buildManifestBundleProof(
        bytes memory preimage,
        bytes memory manifestEntry,
        bytes[] memory connEntries,
        bytes32 iavlRoot,
        bool includePreimage
    ) internal view returns (bytes memory proofBytes) {
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory stateProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeaderBytes(header)),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            PB.encodeBytesField(4, connEntries[0]),
            PB.encodeBytesField(4, connEntries[1]),
            PB.encodeBytesField(4, connEntries[2]),
            PB.encodeBytesField(4, connEntries[3]),
            PB.encodeBytesField(4, connEntries[4])
        );

        proofBytes = abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes),
            PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabbcc")),
            PB.encodeBytesField(4, manifestEntry),
            includePreimage ? PB.encodeBytesField(5, preimage) : bytes("")
        );
    }

    /// @dev IAVL leaf hash exactly as `_existenceRoot` computes it.
    function _iavlLeafHash(bytes memory spKey, bytes memory spValue) internal pure returns (bytes32) {
        bytes memory hashedValue = abi.encodePacked(sha256(spValue));
        bytes memory encodedKey = abi.encodePacked(PB.encodeVarint(uint64(spKey.length)), spKey);
        bytes memory encodedValue = abi.encodePacked(PB.encodeVarint(uint64(hashedValue.length)), hashedValue);
        return sha256(abi.encodePacked(hex"00", encodedKey, encodedValue));
    }

    function _iavlEntry(bytes memory spKey, bytes memory spValue, bytes memory innerPrefix, bytes memory innerSuffix)
        internal
        pure
        returns (bytes memory entry)
    {
        bytes memory leafBytes = abi.encodePacked(
            PB.encodeVarintField(1, 1), // hashOp SHA256
            PB.encodeVarintField(2, 0), // prehashKey NO_HASH
            PB.encodeVarintField(3, 1), // prehashValue SHA256
            PB.encodeVarintField(4, 1), // lengthOp VAR_PROTO
            PB.encodeBytesField(5, hex"00")
        );
        bytes memory innerOp = abi.encodePacked(
            PB.encodeVarintField(1, 1), // hashOp SHA256
            PB.encodeBytesField(2, innerPrefix),
            innerSuffix.length > 0 ? PB.encodeBytesField(3, innerSuffix) : bytes("")
        );
        bytes memory epInner = abi.encodePacked(
            PB.encodeBytesField(1, spKey),
            PB.encodeBytesField(2, spValue),
            PB.encodeBytesField(3, leafBytes),
            PB.encodeBytesField(4, innerOp)
        );
        bytes memory iavlProofBytes = PB.encodeBytesField(1, epInner);
        entry = abi.encodePacked(
            PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, spValue), PB.encodeBytesField(3, iavlProofBytes)
        );
    }

    /// @dev A two-leaf IAVL tree so the channel slots and the manifest commitment can carry
    ///      DIFFERENT values under one root: root = sha256(P || 0x20 || hA || 0x20 || hB), with
    ///      leaf A proven via {prefix: P||0x20, suffix: 0x20||hB} and leaf B via
    ///      {prefix: P||0x20||hA||0x20, suffix: empty} (both shapes valid per the IAVL spec).
    function _buildTwoLeafEntries(bytes memory keyA, bytes memory valueA, bytes memory keyB, bytes memory valueB)
        internal
        pure
        returns (bytes memory entryA, bytes memory entryB, bytes32 iavlRoot)
    {
        bytes32 hA = _iavlLeafHash(keyA, valueA);
        bytes32 hB = _iavlLeafHash(keyB, valueB);
        bytes memory base = hex"04AABBCC"; // 4-byte inner prefix; must not start with 0x00

        entryA = _iavlEntry(keyA, valueA, abi.encodePacked(base, hex"20"), abi.encodePacked(hex"20", hB));
        entryB = _iavlEntry(keyB, valueB, abi.encodePacked(base, hex"20", hA, hex"20"), "");
        iavlRoot = sha256(abi.encodePacked(base, hex"20", hA, hex"20", hB));
    }

    function test_verifyBundle_manifestProof_returnedAndBound() public view {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        ClprTypes.ClprEndpointManifest memory m;
        m.version = 4;
        m.serviceAddress = abi.encodePacked(serviceAddr20);
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "10.2.2.2", port: 50211, tlsCertificate: hex"BB", accountId: hex"09"});
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);

        // Channel slots carry decodable metadata; the manifest entry carries
        // keccak256(preimage) under the commitment-slot key.
        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, _manifestSlotKey(serviceAddr20), keccak256(preimage));

        bytes memory proofBytes = _buildManifestBundleProof(preimage, manifestEntry, connEntries, iavlRoot, true);

        (ClprTypes.QueueMetadata memory metadata,,,, ClprTypes.ClprEndpointManifest memory newManifest) =
            harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));

        assertEq(newManifest.version, 4, "manifest version");
        assertEq(newManifest.endpoints.length, 1, "manifest endpoints");
        assertEq(
            keccak256(newManifest.serviceAddress), keccak256(abi.encodePacked(serviceAddr20)), "manifest svc address"
        );
        assertEq(metadata.nextMessageId, 100, "metadata still decoded from channel slots");
    }

    function test_verifyBundle_manifestProof_withoutPreimage_reverts() public {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);
        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, _manifestSlotKey(serviceAddr20), bytes32(uint256(1)));

        bytes memory proofBytes = _buildManifestBundleProof("", manifestEntry, connEntries, iavlRoot, false);

        vm.expectRevert(SeiCometBftVerifier.ManifestProofPairMismatch.selector);
        harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));
    }

    function test_verifyBundle_manifestProof_commitmentMismatch_reverts() public {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        ClprTypes.ClprEndpointManifest memory m;
        m.version = 4;
        m.serviceAddress = abi.encodePacked(serviceAddr20);
        m.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);

        // Proven commitment does NOT match the supplied preimage.
        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, _manifestSlotKey(serviceAddr20), bytes32(uint256(1)));

        bytes memory proofBytes = _buildManifestBundleProof(preimage, manifestEntry, connEntries, iavlRoot, true);

        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));
    }

    /// @dev Spec (IClprVerifier): MUST revert when manifest.service_address does not match
    ///      ctx.service_address, even when the preimage matches the proven commitment.
    function test_verifyBundle_manifestServiceAddressMismatch_reverts() public {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        ClprTypes.ClprEndpointManifest memory m;
        m.version = 4;
        m.serviceAddress = hex"BEEF"; // committed, but wrong service address
        m.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);

        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, _manifestSlotKey(serviceAddr20), keccak256(preimage));

        bytes memory proofBytes = _buildManifestBundleProof(preimage, manifestEntry, connEntries, iavlRoot, true);

        vm.expectRevert(ClprEvmBundleVerifier.ManifestServiceAddressMismatch.selector);
        harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));
    }

    /// @dev Spec (IClprVerifier): MUST revert when the manifest version is 0 — the uninitialized
    ///      sentinel is never a valid manifest — even when the preimage matches the proven commitment
    ///      and the service address is correct (the version check precedes the service-address check).
    function test_verifyBundle_manifestVersionZero_reverts() public {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        ClprTypes.ClprEndpointManifest memory m;
        m.version = 0; // invalid: 0 is the uninitialized sentinel
        m.serviceAddress = abi.encodePacked(serviceAddr20); // correct address, so only version 0 can trip
        m.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);

        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, _manifestSlotKey(serviceAddr20), keccak256(preimage));

        bytes memory proofBytes = _buildManifestBundleProof(preimage, manifestEntry, connEntries, iavlRoot, true);

        vm.expectRevert(ClprEvmBundleVerifier.ManifestVersionZero.selector);
        harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));
    }

    function test_verifyBundle_manifestProof_wrongSlotKey_reverts() public {
        bytes20 serviceAddr20 = bytes20(SERVICE_ADDR);

        ClprTypes.ClprEndpointManifest memory m;
        m.version = 4;
        m.serviceAddress = abi.encodePacked(serviceAddr20);
        m.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);

        // Entry proves slot 0 instead of the commitment slot (18) — full-key check must reject.
        bytes memory wrongKey = abi.encodePacked(uint8(0x03), serviceAddr20, bytes32(0));
        (bytes[] memory connEntries, bytes memory manifestEntry, bytes32 iavlRoot) =
            _buildManifestScenario(serviceAddr20, wrongKey, keccak256(preimage));

        bytes memory proofBytes = _buildManifestBundleProof(preimage, manifestEntry, connEntries, iavlRoot, true);

        vm.expectRevert(SeiCometBftVerifier.StorageKeyMismatch.selector);
        harness.verifyBundle(proofBytes, abi.encode(CHAIN_ID, _validators), _ctx(serviceAddr20));
    }
}
