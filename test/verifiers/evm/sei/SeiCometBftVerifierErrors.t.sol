// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {SeiSyntheticProofs} from "@test/helpers/SeiSyntheticProofs.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";

// ─────────────────────────────────────────────────────────────────────────────
//  Minimal harness that does NOT override _verifyEd25519 — used to cover the
//  sig-length guard at SeiCometBftVerifier.sol:1524.
// ─────────────────────────────────────────────────────────────────────────────

contract SeiCometBftVerifierBaseHarness is SeiCometBftVerifier {
    constructor(address ed25519) SeiCometBftVerifier(ed25519) {}

    function verifyEd25519Direct(bytes32 pk, bytes memory msg_, bytes memory sig_) external view returns (bool) {
        return _verifyEd25519(pk, msg_, sig_);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Extended harness — exposes internals needed for error-path testing
// ─────────────────────────────────────────────────────────────────────────────

contract SeiCometBftVerifierExtHarness is SeiCometBftVerifier {
    bool internal _alwaysVerifyOk;

    constructor(bool alwaysOk) SeiCometBftVerifier(address(0xED)) {
        _alwaysVerifyOk = alwaysOk;
    }

    function setAlwaysVerifyOk(bool v) external {
        _alwaysVerifyOk = v;
    }

    function _verifyEd25519(bytes32, bytes memory, bytes memory sig) internal view override returns (bool) {
        if (_alwaysVerifyOk) return true;
        // All-zero 64-byte signature is the "bad sig" sentinel used in tests.
        // forge-lint: disable-next-line(unsafe-typecast)
        return sig.length == 64 && uint256(bytes32(sig)) != 0;
    }

    // ── ICS-23 existence proof helpers ───────────────────────────────────────

    function existenceRootIavl(Ics23Lib.ExistenceProof memory proof) external pure returns (bytes32) {
        return Ics23Lib.existenceRootIavl(proof);
    }

    function existenceRootTendermint(Ics23Lib.ExistenceProof memory proof) external pure returns (bytes32) {
        return Ics23Lib.existenceRootTendermint(proof);
    }

    function verifyMembershipIavl(
        Ics23Lib.ExistenceProof memory proof,
        bytes32 root,
        bytes memory key,
        bytes memory value
    ) external pure {
        Ics23Lib.verifyMembershipIavl(proof, root, key, value);
    }

    function verifyMembershipTendermint(
        Ics23Lib.ExistenceProof memory proof,
        bytes32 root,
        bytes memory key,
        bytes memory value
    ) external pure {
        Ics23Lib.verifyMembershipTendermint(proof, root, key, value);
    }

    function verifyNonMembershipIavl(Ics23Lib.NonExistenceProof memory nep, bytes32 root, bytes memory key)
        external
        pure
    {
        Ics23Lib.verifyNonMembershipIavl(nep, root, key);
    }

    // ── IAVL branch / neighbour helpers ──────────────────────────────────────

    function iavlBranch(Ics23Lib.InnerOp memory op) external pure returns (uint8) {
        return Ics23Lib.iavlBranch(op);
    }

    function isLeftMost(Ics23Lib.InnerOp[] memory path) external pure returns (bool) {
        return Ics23Lib.isLeftMost(path);
    }

    function isRightMost(Ics23Lib.InnerOp[] memory path) external pure returns (bool) {
        return Ics23Lib.isRightMost(path);
    }

    function isLeftNeighbor(Ics23Lib.InnerOp[] memory l, Ics23Lib.InnerOp[] memory r) external pure returns (bool) {
        return Ics23Lib.isLeftNeighbor(l, r);
    }

    // ── Low-level utilities ───────────────────────────────────────────────────

    function bytesLt(bytes memory a, bytes memory b) external pure returns (bool) {
        return Ics23Lib.bytesLt(a, b);
    }

    function bitSet(bytes memory bits, uint256 idx) external pure returns (bool) {
        return _bitSet(bits, idx);
    }

    function load32(bytes memory data, uint256 offset) external pure returns (bytes32) {
        return _load32(data, offset);
    }

    function splitPoint(uint256 n) external pure returns (uint256) {
        return CometBftLib.splitPoint(n);
    }

    function addressMatches(bytes memory key, uint256 offset, bytes20 addr) external pure returns (bool) {
        return _addressMatches(key, offset, addr);
    }

    function sfixed64LE(int64 value) external pure returns (bytes8) {
        return CometBftLib.sfixed64LE(value);
    }

    // ── Protobuf parsing ──────────────────────────────────────────────────────

    function parseBundlePayload(bytes memory data)
        external
        pure
        returns (bytes memory stateProof, bytes memory bundleContent, bytes memory nextValidatorSet)
    {
        BundlePayload memory p = _parseBundlePayload(data);
        return (p.stateProof, p.bundleContent, p.nextValidatorSet);
    }

    function parseConfigPayload(bytes memory data)
        external
        pure
        returns (bytes memory validatorSet, bytes memory ledgerConfig, bytes memory stateProof)
    {
        return _parseConfigPayload(data);
    }

    function parseCommitmentProof(bytes memory data)
        external
        pure
        returns (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep)
    {
        return _parseCommitmentProof(data);
    }

    function parseExistenceProof(bytes memory data) external pure returns (Ics23Lib.ExistenceProof memory proof) {
        return _parseExistenceProof(data);
    }

    // ── Header / validator helpers ────────────────────────────────────────────

    function validatorSetHash(CometBftLib.SeiValidator[] memory validators) external pure returns (bytes32) {
        return CometBftLib.validatorSetHash(validators);
    }

    function headerHash(CometBftLib.SeiHeader memory h) external pure returns (bytes32) {
        return CometBftLib.headerHash(h);
    }

    // ── Extra parse helpers (skipField coverage + additional paths) ───────────

    function parseStateProof(bytes memory data)
        external
        pure
        returns (
            bytes memory signedHeader,
            bytes memory storeKey,
            bytes memory multistoreProof,
            bytes[] memory storageProofEntries
        )
    {
        return _parseStateProof(data);
    }

    function parseSignedHeader(bytes memory data)
        external
        pure
        returns (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit)
    {
        return _parseSignedHeader(data);
    }

    function parseHeader(bytes memory data) external pure returns (CometBftLib.SeiHeader memory h) {
        return _parseHeader(data);
    }

    function parseTimestamp(bytes memory data) external pure returns (int64 seconds_, int32 nanos_) {
        return _parseTimestamp(data);
    }

    function parseBlockId(bytes memory data)
        external
        pure
        returns (bytes32 hash_, uint32 partTotal_, bytes32 partHash_)
    {
        return _parseBlockId(data);
    }

    function parsePartSetHeader(bytes memory data) external pure returns (uint32 total_, bytes32 hash_) {
        return _parsePartSetHeader(data);
    }

    function parseCommit(bytes memory data) external pure returns (CometBftLib.SeiCommit memory c) {
        return _parseCommit(data);
    }

    function parseCommitSig(bytes memory data) external pure returns (CometBftLib.CommitSig memory sig) {
        return _parseCommitSig(data);
    }

    function parseValidatorEntry(bytes memory data) external pure returns (CometBftLib.SeiValidator memory v) {
        return _parseValidatorEntry(data);
    }

    function parseLedgerConfiguration(bytes memory data)
        external
        pure
        returns (
            string memory chainId,
            bytes20 serviceAddr,
            uint96 configNanos,
            ClprTypes.Throttles memory throttles,
            ClprTypes.Endpoint[] memory endpoints
        )
    {
        return _parseLedgerConfiguration(data);
    }

    function parseNonExistenceProof(bytes memory data) external pure returns (Ics23Lib.NonExistenceProof memory nep) {
        return _parseNonExistenceProof(data);
    }

    function parseExistenceProofInner(bytes memory data) external pure returns (Ics23Lib.ExistenceProof memory proof) {
        return _parseExistenceProofInner(data);
    }

    function parseLeafOp(bytes memory data) external pure returns (Ics23Lib.LeafOp memory leaf) {
        return _parseLeafOp(data);
    }

    function parseInnerOp(bytes memory data) external pure returns (Ics23Lib.InnerOp memory op) {
        return _parseInnerOp(data);
    }

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }

    function parseValidatorSet(bytes memory data) external pure returns (CometBftLib.SeiValidator[] memory validators) {
        return _parseValidatorSet(data);
    }

    function parseStorageProofEntry(bytes memory data)
        external
        pure
        returns (bytes memory key, bytes memory value, bytes memory iavlProof)
    {
        return _parseStorageProofEntry(data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test contract
// ─────────────────────────────────────────────────────────────────────────────

contract SeiCometBftVerifierErrorsTest is SeiSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    string internal constant CHAIN_ID = "sei-chain-1";

    bytes32 internal constant VAL0_PK = keccak256("sei-validator-0");
    bytes32 internal constant VAL1_PK = keccak256("sei-validator-1");
    int64 internal constant VAL0_VP = 100;
    int64 internal constant VAL1_VP = 200;

    CometBftLib.SeiValidator[] internal _validators;
    SeiCometBftVerifierExtHarness internal harness;

    function setUp() public {
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: VAL0_VP}));
        _validators.push(CometBftLib.SeiValidator({ed25519PubKey: VAL1_PK, votingPower: VAL1_VP}));
        harness = SeiCometBftVerifierExtHarness(
            deployCode("SeiCometBftVerifierErrors.t.sol:SeiCometBftVerifierExtHarness", abi.encode(true))
        );
    }

    /// @dev Builds the ChannelContext bytes carrying `svc` as the remote service address.
    function _ctx(bytes20 svc) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: bytes32(0), remoteServiceAddress: abi.encodePacked(svc)})
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_constructor_zeroEd25519Verifier_reverts() public {
        vm.expectRevert(SeiCometBftVerifier.ZeroEd25519Verifier.selector);
        _deployAndExpectRevert("SeiCometBftVerifier.sol:SeiCometBftVerifier", abi.encode(address(0)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _load32
    // ─────────────────────────────────────────────────────────────────────────

    function test_load32_success() public view {
        bytes memory data = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(SafeCast.toUint8(i + 1));
        }
        bytes32 result = harness.load32(data, 0);
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(result, bytes32(data));
    }

    function test_load32_outOfBounds_reverts() public {
        bytes memory data = new bytes(31);
        vm.expectRevert(SeiCometBftVerifier.Load32OutOfBounds.selector);
        harness.load32(data, 0);
    }

    function test_load32_offsetOutOfBounds_reverts() public {
        bytes memory data = new bytes(32);
        vm.expectRevert(SeiCometBftVerifier.Load32OutOfBounds.selector);
        harness.load32(data, 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _splitPoint
    // ─────────────────────────────────────────────────────────────────────────

    function test_splitPoint_2_returns1() public view {
        assertEq(harness.splitPoint(2), 1);
    }

    function test_splitPoint_3_returns2() public view {
        assertEq(harness.splitPoint(3), 2);
    }

    function test_splitPoint_4_returns2() public view {
        assertEq(harness.splitPoint(4), 2);
    }

    function test_splitPoint_5_returns4() public view {
        assertEq(harness.splitPoint(5), 4);
    }

    function test_splitPoint_8_returns4() public view {
        assertEq(harness.splitPoint(8), 4);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _bitSet
    // ─────────────────────────────────────────────────────────────────────────

    function test_bitSet_msb() public view {
        bytes memory bits = hex"80";
        assertTrue(harness.bitSet(bits, 0));
        assertFalse(harness.bitSet(bits, 1));
    }

    function test_bitSet_lsb() public view {
        bytes memory bits = hex"01";
        assertFalse(harness.bitSet(bits, 0));
        assertTrue(harness.bitSet(bits, 7));
    }

    function test_bitSet_secondByte() public view {
        bytes memory bits = hex"0080";
        assertFalse(harness.bitSet(bits, 0));
        assertTrue(harness.bitSet(bits, 8));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _addressMatches
    // ─────────────────────────────────────────────────────────────────────────

    function test_addressMatches_success() public view {
        bytes20 addr = bytes20(SERVICE_ADDR);
        bytes memory key = abi.encodePacked(uint8(0x03), addr, bytes32(0));
        assertTrue(harness.addressMatches(key, 1, addr));
    }

    function test_addressMatches_failure() public view {
        bytes20 addr = bytes20(SERVICE_ADDR);
        bytes20 other = bytes20(address(0xBEEF));
        bytes memory key = abi.encodePacked(uint8(0x03), addr, bytes32(0));
        assertFalse(harness.addressMatches(key, 1, other));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _bytesLt
    // ─────────────────────────────────────────────────────────────────────────

    function test_bytesLt_shorterIsLess() public view {
        assertTrue(harness.bytesLt(hex"01", hex"0102"));
    }

    function test_bytesLt_longerIsNotLess() public view {
        assertFalse(harness.bytesLt(hex"0102", hex"01"));
    }

    function test_bytesLt_equalLength_firstDiffByte() public view {
        assertTrue(harness.bytesLt(hex"01", hex"02"));
        assertFalse(harness.bytesLt(hex"02", hex"01"));
    }

    function test_bytesLt_equal_isFalse() public view {
        assertFalse(harness.bytesLt(hex"aabb", hex"aabb"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _sfixed64LE
    // ─────────────────────────────────────────────────────────────────────────

    function test_sfixed64LE_value1_littleEndian() public view {
        bytes8 result = harness.sfixed64LE(1);
        // LE: 01 00 00 00 00 00 00 00 → bytes8 MSB=0x01, rest=0x00
        assertEq(uint64(result), uint64(0x0100000000000000));
    }

    function test_sfixed64LE_value256_littleEndian() public view {
        bytes8 result = harness.sfixed64LE(256);
        // 256 = 0x0100 LE: 00 01 00 00 00 00 00 00
        assertEq(uint64(result), uint64(0x0001000000000000));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _iavlBranch
    // ─────────────────────────────────────────────────────────────────────────

    function test_iavlBranch_leftChild_suffix33() public view {
        // Left child: suffix.length == IAVL_CHILD_SIZE(33), prefix 4..12 bytes
        Ics23Lib.InnerOp memory op;
        op.hashOp = 1;
        op.prefix = new bytes(5); // valid: 4..12
        op.prefix[0] = 0x01;
        op.suffix = new bytes(33);
        assertEq(harness.iavlBranch(op), 0);
    }

    function test_iavlBranch_rightChild_suffix0() public view {
        // Right child: suffix.length == 0, prefix 37..45 bytes (IAVL_MIN_PREFIX+CHILD_SIZE=37)
        Ics23Lib.InnerOp memory op;
        op.hashOp = 1;
        op.prefix = new bytes(37);
        op.prefix[0] = 0x01;
        op.suffix = new bytes(0);
        assertEq(harness.iavlBranch(op), 1);
    }

    function test_iavlBranch_invalid_returns255() public view {
        Ics23Lib.InnerOp memory op;
        op.hashOp = 1;
        op.prefix = new bytes(1); // < IAVL_MIN_PREFIX
        op.suffix = new bytes(10); // not 0 or 33
        assertEq(harness.iavlBranch(op), 255);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _isLeftMost / _isRightMost / _isLeftNeighbor
    // ─────────────────────────────────────────────────────────────────────────

    function test_isLeftMost_emptyPath_true() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](0);
        assertTrue(harness.isLeftMost(path));
    }

    function test_isLeftMost_allLeftChildren_true() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](2);
        path[0] = _leftInnerOp();
        path[1] = _leftInnerOp();
        assertTrue(harness.isLeftMost(path));
    }

    function test_isLeftMost_withRightChild_false() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](2);
        path[0] = _leftInnerOp();
        path[1] = _rightInnerOp();
        assertFalse(harness.isLeftMost(path));
    }

    function test_isRightMost_emptyPath_true() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](0);
        assertTrue(harness.isRightMost(path));
    }

    function test_isRightMost_allRightChildren_true() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](2);
        path[0] = _rightInnerOp();
        path[1] = _rightInnerOp();
        assertTrue(harness.isRightMost(path));
    }

    function test_isRightMost_withLeftChild_false() public view {
        Ics23Lib.InnerOp[] memory path = new Ics23Lib.InnerOp[](2);
        path[0] = _rightInnerOp();
        path[1] = _leftInnerOp();
        assertFalse(harness.isRightMost(path));
    }

    function test_isLeftNeighbor_emptyPaths_false() public view {
        Ics23Lib.InnerOp[] memory l = new Ics23Lib.InnerOp[](0);
        Ics23Lib.InnerOp[] memory r = new Ics23Lib.InnerOp[](0);
        assertFalse(harness.isLeftNeighbor(l, r));
    }

    function test_isLeftNeighbor_leftRight_diverge_true() public view {
        // Minimal valid neighbour: l takes left at depth 0; r takes right at depth 0.
        // Shared root suffix is stripped first, so with no shared ops it's just:
        // l[0] branches left (branch=0), r[0] branches right (branch=1).
        // Sub-paths below divergence must be right-most (l) / left-most (r) — both empty → true.
        Ics23Lib.InnerOp[] memory l = new Ics23Lib.InnerOp[](1);
        Ics23Lib.InnerOp[] memory r = new Ics23Lib.InnerOp[](1);
        l[0] = _leftInnerOp();
        r[0] = _rightInnerOp();
        assertTrue(harness.isLeftNeighbor(l, r));
    }

    function test_isLeftNeighbor_sameOp_false() public view {
        // Both paths are identical → no divergence → returns false
        Ics23Lib.InnerOp[] memory l = new Ics23Lib.InnerOp[](1);
        Ics23Lib.InnerOp[] memory r = new Ics23Lib.InnerOp[](1);
        l[0] = _leftInnerOp();
        r[0] = _leftInnerOp();
        assertFalse(harness.isLeftNeighbor(l, r));
    }

    function test_isLeftNeighbor_wrongDivergenceOrder_false() public view {
        // l takes right at depth 0, r takes left → not a valid left-neighbour relationship
        Ics23Lib.InnerOp[] memory l = new Ics23Lib.InnerOp[](1);
        Ics23Lib.InnerOp[] memory r = new Ics23Lib.InnerOp[](1);
        l[0] = _rightInnerOp();
        r[0] = _leftInnerOp();
        assertFalse(harness.isLeftNeighbor(l, r));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _existenceRootIavl — leaf-op error branches
    // ─────────────────────────────────────────────────────────────────────────

    function test_existenceRootIavl_emptyKey_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.key = bytes("");
        vm.expectRevert(SeiCometBftVerifier.EmptyKey.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_emptyValue_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.value = bytes("");
        vm.expectRevert(SeiCometBftVerifier.EmptyValue.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_wrongHashOp_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.hashOp = 2;
        vm.expectRevert(Ics23Lib.LeafOpSpecMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_wrongPrehashKey_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.prehashKey = 1;
        vm.expectRevert(Ics23Lib.LeafOpSpecMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_wrongPrehashValue_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.prehashValue = 2;
        vm.expectRevert(Ics23Lib.LeafOpSpecMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_wrongLengthOp_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.lengthOp = 2;
        vm.expectRevert(Ics23Lib.LeafOpSpecMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_emptyPrefix_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.prefix = bytes("");
        vm.expectRevert(SeiCometBftVerifier.LeafPrefixMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_wrongPrefixByte_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aa", hex"bb");
        proof.leaf.prefix = hex"01";
        vm.expectRevert(SeiCometBftVerifier.LeafPrefixMismatch.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_validLeaf_succeeds() public view {
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(hex"aabbcc", hex"ddeeff");
        bytes32 root = harness.existenceRootIavl(proof);
        assertNotEq(root, bytes32(0));
    }

    // ── Inner-op error branches ───────────────────────────────────────────────

    function test_existenceRootIavl_innerOp_wrongHashOp_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        proof.path[0].hashOp = 2;
        vm.expectRevert(SeiCometBftVerifier.HashOpNotSha256.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_innerOp_prefixCollidesLeaf_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        proof.path[0].prefix[0] = bytes1(0x00); // LEAF_PREFIX
        vm.expectRevert(SeiCometBftVerifier.PrefixCollidesWithLeaf.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_innerOp_prefixTooShort_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        proof.path[0].prefix = new bytes(3); // < IAVL_MIN_PREFIX=4
        proof.path[0].prefix[0] = 0x01;
        vm.expectRevert(SeiCometBftVerifier.InvalidPrefixLength.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_innerOp_prefixTooLong_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        // maxP = IAVL_MAX_PREFIX + IAVL_CHILD_SIZE = 12 + 33 = 45
        proof.path[0].prefix = new bytes(46); // > 45
        proof.path[0].prefix[0] = 0x01;
        vm.expectRevert(SeiCometBftVerifier.InvalidPrefixLength.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_innerOp_suffixWrongMod_reverts() public {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        proof.path[0].suffix = new bytes(10); // 10 % 33 != 0
        vm.expectRevert(SeiCometBftVerifier.InvalidSuffixLength.selector);
        harness.existenceRootIavl(proof);
    }

    function test_existenceRootIavl_validInnerOp_succeeds() public view {
        Ics23Lib.ExistenceProof memory proof = _validLeafProofWithInnerOp(hex"6b6579", hex"76616c");
        bytes32 root = harness.existenceRootIavl(proof);
        assertNotEq(root, bytes32(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _verifyMembershipIavl / _verifyMembershipTendermint
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyMembershipIavl_keyMismatch_reverts() public {
        bytes memory key = hex"aabb";
        bytes memory value = hex"ccdd";
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(key, value);
        bytes32 root = harness.existenceRootIavl(proof);
        vm.expectRevert(SeiCometBftVerifier.KeyMismatch.selector);
        harness.verifyMembershipIavl(proof, root, hex"1122", value);
    }

    function test_verifyMembershipIavl_valueMismatch_reverts() public {
        bytes memory key = hex"aabb";
        bytes memory value = hex"ccdd";
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(key, value);
        bytes32 root = harness.existenceRootIavl(proof);
        vm.expectRevert(SeiCometBftVerifier.ValueMismatch.selector);
        harness.verifyMembershipIavl(proof, root, key, hex"ffff");
    }

    function test_verifyMembershipIavl_rootMismatch_reverts() public {
        bytes memory key = hex"aabb";
        bytes memory value = hex"ccdd";
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(key, value);
        vm.expectRevert(SeiCometBftVerifier.RootMismatch.selector);
        harness.verifyMembershipIavl(proof, bytes32(uint256(0xdeadbeef)), key, value);
    }

    function test_verifyMembershipIavl_success() public view {
        bytes memory key = hex"aabb";
        bytes memory value = hex"ccdd";
        Ics23Lib.ExistenceProof memory proof = _validLeafProof(key, value);
        bytes32 root = harness.existenceRootIavl(proof);
        harness.verifyMembershipIavl(proof, root, key, value);
    }

    function test_verifyMembershipTendermint_keyMismatch_reverts() public {
        bytes memory key = bytes("evm");
        bytes memory value = new bytes(32);
        Ics23Lib.ExistenceProof memory proof = _validTmLeafProof(key, value);
        bytes32 root = harness.existenceRootTendermint(proof);
        vm.expectRevert(SeiCometBftVerifier.KeyMismatch.selector);
        harness.verifyMembershipTendermint(proof, root, bytes("other"), value);
    }

    function test_verifyMembershipTendermint_valueMismatch_reverts() public {
        bytes memory key = bytes("evm");
        bytes memory value = new bytes(32);
        Ics23Lib.ExistenceProof memory proof = _validTmLeafProof(key, value);
        bytes32 root = harness.existenceRootTendermint(proof);
        bytes memory wrongValue = new bytes(32);
        wrongValue[0] = 0xff;
        vm.expectRevert(SeiCometBftVerifier.ValueMismatch.selector);
        harness.verifyMembershipTendermint(proof, root, key, wrongValue);
    }

    function test_verifyMembershipTendermint_rootMismatch_reverts() public {
        bytes memory key = bytes("evm");
        bytes memory value = new bytes(32);
        Ics23Lib.ExistenceProof memory proof = _validTmLeafProof(key, value);
        vm.expectRevert(SeiCometBftVerifier.RootMismatch.selector);
        harness.verifyMembershipTendermint(proof, bytes32(uint256(0xbadbeef)), key, value);
    }

    function test_verifyMembershipTendermint_success() public view {
        bytes memory key = bytes("evm");
        bytes memory value = new bytes(32);
        value[0] = 0xab;
        Ics23Lib.ExistenceProof memory proof = _validTmLeafProof(key, value);
        bytes32 root = harness.existenceRootTendermint(proof);
        harness.verifyMembershipTendermint(proof, root, key, value);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _verifyNonMembershipIavl
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyNonMembershipIavl_keyMismatch_reverts() public {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep, bytes32 root) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        vm.expectRevert(SeiCometBftVerifier.NonExistenceKeyMismatch.selector);
        harness.verifyNonMembershipIavl(nep, root, hex"dddd");
    }

    function test_verifyNonMembershipIavl_noNeighbours_reverts() public {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep, bytes32 root) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        nep.hasLeft = false;
        nep.hasRight = false;
        vm.expectRevert(SeiCometBftVerifier.NonExistenceMissingNeighbour.selector);
        harness.verifyNonMembershipIavl(nep, root, absentKey);
    }

    function test_verifyNonMembershipIavl_leftRootMismatch_reverts() public {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep,) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        // Pass an incorrect root
        vm.expectRevert(SeiCometBftVerifier.LeftNeighbourRootMismatch.selector);
        harness.verifyNonMembershipIavl(nep, bytes32(uint256(0xdeadbeef)), absentKey);
    }

    function test_verifyNonMembershipIavl_leftNotBefore_reverts() public {
        // Left key >= absent key
        bytes memory absentKey = hex"aaaa";
        bytes memory leftKey = hex"bbbb"; // leftKey > absentKey
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep,) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        // Use just hasLeft=true, hasRight=false so only left-root check runs first
        nep.hasRight = false;
        // left root will match (we pass correct root for leftOnly case)
        bytes32 leftRoot = harness.existenceRootIavl(nep.left);
        vm.expectRevert(SeiCometBftVerifier.LeftNeighbourNotBeforeKey.selector);
        harness.verifyNonMembershipIavl(nep, leftRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_rightRootMismatch_reverts() public {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep,) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        // Only keep right, so left root check is skipped
        nep.hasLeft = false;
        // Provide wrong root for right
        bytes32 wrongRoot = bytes32(uint256(0x1));
        vm.expectRevert(SeiCometBftVerifier.RightNeighbourRootMismatch.selector);
        harness.verifyNonMembershipIavl(nep, wrongRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_rightNotAfter_reverts() public {
        // Right key <= absent key
        bytes memory absentKey = hex"cccc";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"bbbb"; // rightKey < absentKey
        (Ics23Lib.NonExistenceProof memory nep,) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        nep.hasLeft = false;
        bytes32 rightRoot = harness.existenceRootIavl(nep.right);
        vm.expectRevert(SeiCometBftVerifier.RightNeighbourNotAfterKey.selector);
        harness.verifyNonMembershipIavl(nep, rightRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_rightNotLeftMost_reverts() public {
        // Right-only path but the proof has a right-child inner op (not left-most)
        bytes memory absentKey = hex"bbbb";
        bytes memory rightKey = hex"cccc";
        Ics23Lib.ExistenceProof memory rightProof = _validLeafProof(rightKey, hex"ff");
        // Add a right-child inner op so _isLeftMost returns false
        rightProof = _appendInnerOp(rightProof, _rightInnerOp());
        bytes32 rightRoot = harness.existenceRootIavl(rightProof);

        Ics23Lib.NonExistenceProof memory nep;
        nep.key = absentKey;
        nep.hasLeft = false;
        nep.hasRight = true;
        nep.right = rightProof;

        vm.expectRevert(SeiCometBftVerifier.RightNeighbourNotLeftMost.selector);
        harness.verifyNonMembershipIavl(nep, rightRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_leftNotRightMost_reverts() public {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        Ics23Lib.ExistenceProof memory leftProof = _validLeafProof(leftKey, hex"ff");
        // Add a left-child inner op so _isRightMost returns false
        leftProof = _appendInnerOp(leftProof, _leftInnerOp());
        bytes32 leftRoot = harness.existenceRootIavl(leftProof);

        Ics23Lib.NonExistenceProof memory nep;
        nep.key = absentKey;
        nep.hasLeft = true;
        nep.left = leftProof;
        nep.hasRight = false;

        vm.expectRevert(SeiCometBftVerifier.LeftNeighbourNotRightMost.selector);
        harness.verifyNonMembershipIavl(nep, leftRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_leavesNotNeighbours_reverts() public {
        // Build a 3-leaf IAVL tree with keys A < B < C.  The absent key is B (which IS present in
        // the tree, so the non-existence claim is false). We prove A and C as neighbours, but they
        // are NOT adjacent in the tree — B sits between them — so _isLeftNeighbor returns false.
        bytes memory keyA = hex"aaaa";
        bytes memory keyB = hex"bbbb"; // absentKey (actually present in tree)
        bytes memory keyC = hex"cccc";

        // Leaf hashes via leaf-only proofs
        bytes32 hA = harness.existenceRootIavl(_validLeafProof(keyA, hex"11"));
        bytes32 hB = harness.existenceRootIavl(_validLeafProof(keyB, hex"22"));
        bytes32 hC = harness.existenceRootIavl(_validLeafProof(keyC, hex"33"));

        // Inner-node [AB]: root_AB = sha256(P1 || hA || P2 || hB)
        bytes5 P1 = hex"0408011001"; // 5-byte inner-node prefix (first byte 0x04 ≠ LEAF_PREFIX)
        bytes1 P2 = 0x20;
        bytes32 hAB = sha256(abi.encodePacked(P1, hA, P2, hB));

        // Root node [AB, C]: root = sha256(P3 || hAB || P4 || hC)
        bytes5 P3 = hex"0608021002"; // different prefix for root level
        bytes1 P4 = 0x30;
        bytes32 root = sha256(abi.encodePacked(P3, hAB, P4, hC));

        // Left proof (leaf A → AB → Root):
        //   inner[0] = left-child of AB: prefix=P1, suffix=P2||hB (33 bytes)
        //   inner[1] = left-child of Root: prefix=P3, suffix=P4||hC (33 bytes)
        Ics23Lib.ExistenceProof memory leftProof = _validLeafProof(keyA, hex"11");
        leftProof.path = new Ics23Lib.InnerOp[](2);
        leftProof.path[0].hashOp = 1;
        leftProof.path[0].prefix = abi.encodePacked(P1);
        leftProof.path[0].suffix = abi.encodePacked(P2, hB); // 33 bytes, branch=0 (left child of AB)
        leftProof.path[1].hashOp = 1;
        leftProof.path[1].prefix = abi.encodePacked(P3);
        leftProof.path[1].suffix = abi.encodePacked(P4, hC); // 33 bytes, branch=0 (left child of Root)

        // Right proof (leaf C → Root):
        //   inner[0] = right-child of Root: prefix=P3||hAB||P4 (38 bytes), suffix=[]
        Ics23Lib.ExistenceProof memory rightProof = _validLeafProof(keyC, hex"33");
        rightProof.path = new Ics23Lib.InnerOp[](1);
        rightProof.path[0].hashOp = 1;
        rightProof.path[0].prefix = abi.encodePacked(P3, hAB, P4); // 38 bytes, branch=1 (right child of Root)
        rightProof.path[0].suffix = new bytes(0);

        Ics23Lib.NonExistenceProof memory nep;
        nep.key = keyB; // absentKey
        nep.hasLeft = true;
        nep.left = leftProof;
        nep.hasRight = true;
        nep.right = rightProof;

        // Both proofs compute the same root, keys bracket the absent key, but A and C are NOT
        // left-neighbors (B is between them) → _isLeftNeighbor returns false → LeavesNotNeighbours.
        vm.expectRevert(SeiCometBftVerifier.LeavesNotNeighbours.selector);
        harness.verifyNonMembershipIavl(nep, root, keyB);
    }

    function test_verifyNonMembershipIavl_leftOnly_success() public view {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        Ics23Lib.ExistenceProof memory leftProof = _validLeafProof(leftKey, hex"ff");
        // left proof with right-most path (empty path is right-most)
        bytes32 leftRoot = harness.existenceRootIavl(leftProof);

        Ics23Lib.NonExistenceProof memory nep;
        nep.key = absentKey;
        nep.hasLeft = true;
        nep.left = leftProof;
        nep.hasRight = false;

        harness.verifyNonMembershipIavl(nep, leftRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_rightOnly_success() public view {
        bytes memory absentKey = hex"bbbb";
        bytes memory rightKey = hex"cccc";
        Ics23Lib.ExistenceProof memory rightProof = _validLeafProof(rightKey, hex"ff");
        // right proof with left-most path (empty path is left-most)
        bytes32 rightRoot = harness.existenceRootIavl(rightProof);

        Ics23Lib.NonExistenceProof memory nep;
        nep.key = absentKey;
        nep.hasLeft = false;
        nep.hasRight = true;
        nep.right = rightProof;

        harness.verifyNonMembershipIavl(nep, rightRoot, absentKey);
    }

    function test_verifyNonMembershipIavl_both_success() public view {
        bytes memory absentKey = hex"bbbb";
        bytes memory leftKey = hex"aaaa";
        bytes memory rightKey = hex"cccc";
        (Ics23Lib.NonExistenceProof memory nep, bytes32 root) = _buildNonExistenceProof(absentKey, leftKey, rightKey);
        harness.verifyNonMembershipIavl(nep, root, absentKey);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _parseBundlePayload
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseBundlePayload_missingStateProof_reverts() public {
        // Only bundle content, no state proof
        bytes memory data = PB.encodeBytesField(2, hex"aabb");
        vm.expectRevert(SeiCometBftVerifier.MissingStateProof.selector);
        harness.parseBundlePayload(data);
    }

    function test_parseBundlePayload_missingBundleContent_reverts() public {
        // Only state proof, no bundle content
        bytes memory data = PB.encodeBytesField(1, hex"aabb");
        vm.expectRevert(SeiCometBftVerifier.MissingBundleContent.selector);
        harness.parseBundlePayload(data);
    }

    function test_parseBundlePayload_success() public view {
        bytes memory stateProof = hex"aabb";
        bytes memory bundleContent = hex"ccdd";
        bytes memory data = abi.encodePacked(PB.encodeBytesField(1, stateProof), PB.encodeBytesField(2, bundleContent));
        (bytes memory sp, bytes memory bc, bytes memory nvs) = harness.parseBundlePayload(data);
        assertEq(sp, stateProof);
        assertEq(bc, bundleContent);
        assertEq(nvs.length, 0);
    }

    function test_parseBundlePayload_withNextValidatorSet_success() public view {
        bytes memory stateProof = hex"aabb";
        bytes memory bundleContent = hex"ccdd";
        bytes memory nextVals = hex"eeff";
        bytes memory data = abi.encodePacked(
            PB.encodeBytesField(1, stateProof), PB.encodeBytesField(2, bundleContent), PB.encodeBytesField(3, nextVals)
        );
        (bytes memory sp, bytes memory bc, bytes memory nvs) = harness.parseBundlePayload(data);
        assertEq(sp, stateProof);
        assertEq(bc, bundleContent);
        assertEq(nvs, nextVals);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _parseConfigPayload
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseConfigPayload_missingValidatorSet_reverts() public {
        bytes memory data = abi.encodePacked(PB.encodeBytesField(2, hex"aabb"), PB.encodeBytesField(3, hex"ccdd"));
        vm.expectRevert(SeiCometBftVerifier.MissingValidatorSet.selector);
        harness.parseConfigPayload(data);
    }

    function test_parseConfigPayload_missingLedgerConfig_reverts() public {
        bytes memory data = abi.encodePacked(PB.encodeBytesField(1, hex"aabb"), PB.encodeBytesField(3, hex"ccdd"));
        vm.expectRevert(SeiCometBftVerifier.MissingLedgerConfig.selector);
        harness.parseConfigPayload(data);
    }

    function test_parseConfigPayload_missingStateProof_reverts() public {
        bytes memory data = abi.encodePacked(PB.encodeBytesField(1, hex"aabb"), PB.encodeBytesField(2, hex"ccdd"));
        vm.expectRevert(SeiCometBftVerifier.MissingStateProof.selector);
        harness.parseConfigPayload(data);
    }

    function test_parseConfigPayload_success() public view {
        bytes memory validatorSet = hex"aabb";
        bytes memory ledgerConfig = hex"ccdd";
        bytes memory stateProof = hex"eeff";
        bytes memory data = abi.encodePacked(
            PB.encodeBytesField(1, validatorSet),
            PB.encodeBytesField(2, ledgerConfig),
            PB.encodeBytesField(3, stateProof)
        );
        (bytes memory vs, bytes memory lc, bytes memory sp) = harness.parseConfigPayload(data);
        assertEq(vs, validatorSet);
        assertEq(lc, ledgerConfig);
        assertEq(sp, stateProof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _parseCommitmentProof
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseCommitmentProof_unsupportedType_reverts() public {
        // Field 3 (neither existence=1 nor non-existence=2)
        bytes memory data = PB.encodeBytesField(3, hex"aabb");
        vm.expectRevert(SeiCometBftVerifier.UnsupportedProofType.selector);
        harness.parseCommitmentProof(data);
    }

    function test_parseCommitmentProof_emptyData_reverts() public {
        vm.expectRevert(SeiCometBftVerifier.UnsupportedProofType.selector);
        harness.parseCommitmentProof(bytes(""));
    }

    function test_parseCommitmentProof_existenceProof_success() public view {
        // CommitmentProof field 1 = Ics23Lib.ExistenceProof (just an empty inner proto for the test)
        bytes memory epBytes = PB.encodeBytesField(1, hex"aabb");
        bytes memory data = PB.encodeBytesField(1, epBytes);
        (bool isExistence,,) = harness.parseCommitmentProof(data);
        assertTrue(isExistence);
    }

    function test_parseCommitmentProof_nonExistenceProof_success() public view {
        bytes memory nepBytes = PB.encodeBytesField(1, hex"aabb");
        bytes memory data = PB.encodeBytesField(2, nepBytes);
        (bool isExistence,,) = harness.parseCommitmentProof(data);
        assertFalse(isExistence);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _parseExistenceProof (multistore, existence-only parser)
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseExistenceProof_nonExistenceField_reverts() public {
        // Field 2 is non-existence proof — rejected by parseExistenceProof
        bytes memory data = PB.encodeBytesField(2, hex"aabb");
        vm.expectRevert(SeiCometBftVerifier.OnlyExistenceProofsSupported.selector);
        harness.parseExistenceProof(data);
    }

    function test_parseExistenceProof_existenceField_success() public view {
        bytes memory epBytes = abi.encodePacked(
            PB.encodeBytesField(1, hex"aabb"), // key
            PB.encodeBytesField(2, hex"ccdd") // value
        );
        bytes memory data = PB.encodeBytesField(1, epBytes);
        Ics23Lib.ExistenceProof memory proof = harness.parseExistenceProof(data);
        assertEq(proof.key, hex"aabb");
        assertEq(proof.value, hex"ccdd");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyBundle — error paths exercising the full verification pipeline
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_validatorSetHashMismatch_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);

        // Use a different validator set in the anchor to force hash mismatch
        CometBftLib.SeiValidator[] memory wrongVals = new CometBftLib.SeiValidator[](1);
        wrongVals[0] = CometBftLib.SeiValidator({ed25519PubKey: keccak256("other"), votingPower: 999});
        bytes memory anchor = abi.encode(CHAIN_ID, wrongVals);

        (bytes memory proofBytes,) = _buildMinimalBundleProof(validators, serviceAddr, false);

        vm.expectRevert(SeiCometBftVerifier.ValidatorSetHashMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_chainIdMismatch_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode("sei-WRONG-chain", validators);

        (bytes memory proofBytes,) = _buildMinimalBundleProof(validators, serviceAddr, false);
        vm.expectRevert(SeiCometBftVerifier.ChainIdMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_invalidStoreKey_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // Build proof with wrong store key ("abc" instead of "evm")
        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(0));
        bytes memory spValue = new bytes(32);
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("abc"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory proofBytes =
            _wrapBundlePayload(header, validators, serviceAddr, storageEntry, multistoreProof, bytes("abc"));

        vm.expectRevert(SeiCometBftVerifier.InvalidStoreKey.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_storageKeyMismatch_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // Storage key length != 53 (use 10 bytes)
        bytes memory badKey = new bytes(10);
        bytes memory spValue = new bytes(32);
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(badKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory proofBytes =
            _wrapBundlePayload(header, validators, serviceAddr, storageEntry, multistoreProof, bytes("evm"));

        vm.expectRevert(SeiCometBftVerifier.StorageKeyMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_invalidSignersBitsLength_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators; // 2 validators → 1 byte
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        (bytes memory proofBytes,) = _buildMinimalBundleProofWithSignersBits(
            validators,
            serviceAddr,
            hex"C0C0" // 2 bytes instead of 1 → wrong length
        );
        vm.expectRevert(SeiCometBftVerifier.InvalidSignersBitsLength.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_signersBitOutOfRange_reverts() public {
        CometBftLib.SeiValidator[] memory vals = new CometBftLib.SeiValidator[](1);
        vals[0] = CometBftLib.SeiValidator({ed25519PubKey: VAL0_PK, votingPower: VAL0_VP});
        SeiCometBftVerifierExtHarness h = SeiCometBftVerifierExtHarness(
            deployCode("SeiCometBftVerifierErrors.t.sol:SeiCometBftVerifierExtHarness", abi.encode(true))
        );
        bytes memory anchor = abi.encode(CHAIN_ID, vals);

        // signersBits: 1 byte, n=1 validator → bits 1-7 are padding. Set bit 1 (0x40 → position 1 set)
        (bytes memory proofBytes,) =
            _buildMinimalBundleProofWithSignersBitsAndVals(vals, bytes20(SERVICE_ADDR), hex"7F");
        vm.expectRevert(SeiCometBftVerifier.SignersBitOutOfRange.selector);
        h.verifyBundle(proofBytes, anchor, _ctx(bytes20(SERVICE_ADDR)));
    }

    function test_verifyBundle_quorumNotMet_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators; // val0=100, val1=200, total=300
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // Only val0 signs (power=100, 100*3=300 <= 300*2=600) → QuorumNotMet
        (bytes memory proofBytes,) =
            _buildMinimalBundleProofWithSignersBits(
                validators,
                serviceAddr,
                hex"80" // only val0 bit set
            );
        vm.expectRevert(SeiCometBftVerifier.QuorumNotMet.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_tooFewSignatures_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // signersBits says both sign (0xC0) but we only provide 1 signature
        (bytes memory proofBytes,) =
            _buildMinimalBundleProofWithSignersBitsAndSigCount(validators, serviceAddr, hex"C0", 1);
        vm.expectRevert(SeiCometBftVerifier.TooFewSignatures.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_extraSignatures_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // signersBits says only val1 signs (0x40) but we provide 2 signatures
        (bytes memory proofBytes,) =
            _buildMinimalBundleProofWithSignersBitsAndSigCount(validators, serviceAddr, hex"40", 2);
        vm.expectRevert(SeiCometBftVerifier.ExtraSignatures.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_invalidSignature_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        harness.setAlwaysVerifyOk(false);
        // Provide all-zero signatures (bad-sig sentinel)
        (bytes memory proofBytes,) = _buildMinimalBundleProofWithZeroSigs(validators, serviceAddr);
        vm.expectRevert(SeiCometBftVerifier.InvalidSignature.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    /// @dev Quorum early exit: once the verified signers' power crosses
    ///      2/3 of total, the remaining signatures are NEVER verified (each skipped Ed25519 check
    ///      saves ~600K gas). Validators [200, 200, 100] (total 500): the first two already give
    ///      400·3 > 500·2, so the third signature — the invalid all-zero sentinel — is ignored and
    ///      the bundle verifies instead of reverting InvalidSignature.
    function test_verifyBundle_earlyExit_skipsPostQuorumSignatures() public {
        CometBftLib.SeiValidator[] memory vals = new CometBftLib.SeiValidator[](3);
        vals[0] = CometBftLib.SeiValidator({ed25519PubKey: bytes32(uint256(0x111)), votingPower: 200});
        vals[1] = CometBftLib.SeiValidator({ed25519PubKey: bytes32(uint256(0x222)), votingPower: 200});
        vals[2] = CometBftLib.SeiValidator({ed25519PubKey: bytes32(uint256(0x333)), votingPower: 100});
        bytes memory anchor = abi.encode(CHAIN_ID, vals);

        harness.setAlwaysVerifyOk(false); // sentinel mode: all-zero sig = invalid
        bytes memory proofBytes = _buildBundleProofLastSigZero(vals, bytes20(SERVICE_ADDR), hex"E0");
        // Must NOT revert: the invalid third signature sits beyond the quorum point.
        harness.verifyBundle(proofBytes, anchor, _ctx(bytes20(SERVICE_ADDR)));
    }

    function test_verifyBundle_invalidStorageValueLength_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // Existence proof but value is 16 bytes instead of 32. Position 0's slot must be the real
        // cBase+1 slot — the length check fires after the slot-key check.
        bytes memory spKey = _correctSlotKeys(serviceAddr)[0];
        bytes memory spValue = new bytes(16); // wrong length
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory proofBytes =
            _wrapBundlePayload(header, validators, serviceAddr, storageEntry, multistoreProof, bytes("evm"));
        vm.expectRevert(SeiCometBftVerifier.InvalidStorageValueLength.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_missingNextValidatorSet_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // nextValidatorsHash in header differs from current, but no nextValidatorSet provided
        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = keccak256("different-next-validator-set");

        bytes memory proofBytes = _wrapBundlePayloadWithHeader(header, validators, serviceAddr);
        vm.expectRevert(SeiCometBftVerifier.MissingNextValidatorSet.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_storageProofFailed_tooFew_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // Only 4 storage entries (min is 5)
        (bytes memory proofBytes,) = _buildBundleProofWithNStorageEntries(validators, serviceAddr, 4);
        vm.expectRevert(SeiCometBftVerifier.StorageProofFailed.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_storageProofFailed_tooMany_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        // 7 storage entries (max is 6)
        (bytes memory proofBytes,) = _buildBundleProofWithNStorageEntries(validators, serviceAddr, 7);
        vm.expectRevert(SeiCometBftVerifier.StorageProofFailed.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    /// @dev A channel's nextMessageId starts at 1 and only increments (per the CLPR spec), so a
    ///      proven nextMessageId of 0 means no message was ever sent — a 6-entry (message-bearing)
    ///      proof for such a channel is inherently invalid. Without an explicit guard this would
    ///      underflow `nextMessageId - 1` into an opaque arithmetic panic instead of the same
    ///      StorageKeyMismatch used for every other proof-shape violation in this function.
    function test_verifyBundle_zeroNextMessageId_sixEntries_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        (bytes memory proofBytes,) = _buildBundleProofWithNStorageEntriesAndNextMessageId(validators, serviceAddr, 6, 0);
        vm.expectRevert(SeiCometBftVerifier.StorageKeyMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    function test_verifyBundle_nextValidatorSetHashMismatch_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, validators);

        CometBftLib.SeiValidator[] memory nextVals = new CometBftLib.SeiValidator[](1);
        nextVals[0] = CometBftLib.SeiValidator({ed25519PubKey: keccak256("next"), votingPower: 500});
        bytes memory nextValBytes = _encodeValidatorSet(nextVals);

        // The header's nextValidatorsHash will not match the provided nextValidatorSet
        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = keccak256("wrong-hash"); // deliberate mismatch

        bytes memory proofBytes = _wrapBundlePayloadWithHeaderAndNextVals(header, validators, serviceAddr, nextValBytes);
        vm.expectRevert(SeiCometBftVerifier.NextValidatorSetHashMismatch.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyConfig — error paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyConfig_invalidStorageProofCount_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);

        // Config proof must have exactly 1 storage entry; build with 2
        (bytes memory configProofBytes) = _buildConfigProofWithNStorageEntries(validators, serviceAddr, 2);
        vm.expectRevert(SeiCometBftVerifier.InvalidStorageProofCount.selector);
        harness.verifyConfig(configProofBytes, bytes32(0), "");
    }

    function test_verifyConfig_serviceAddressSlotMismatch_reverts() public {
        CometBftLib.SeiValidator[] memory validators = _validators;
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);

        // Build config proof where the storage value is wrong (all zeros ≠ expected slot encoding)
        bytes memory configProofBytes = _buildConfigProofWithWrongSlot(validators, serviceAddr);
        vm.expectRevert(SeiCometBftVerifier.ServiceAddressSlotMismatch.selector);
        harness.verifyConfig(configProofBytes, bytes32(0), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Trust-anchor guard tests
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_emptyAnchor_reverts() public {
        vm.expectRevert(SeiCometBftVerifier.InvalidTrustAnchor.selector);
        harness.verifyBundle(hex"aabb", bytes(""), "");
    }

    function test_verifyBundle_emptyValidatorSet_reverts() public {
        CometBftLib.SeiValidator[] memory empty = new CometBftLib.SeiValidator[](0);
        bytes memory anchor = abi.encode(CHAIN_ID, empty);
        vm.expectRevert(SeiCometBftVerifier.InvalidTrustAnchor.selector);
        harness.verifyBundle(hex"aabb", anchor, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Multistore key mismatch — second InvalidStoreKey at line 431
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_multistoreKeyMismatch_reverts() public {
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, _validators);

        bytes memory multistoreProofBytes = _buildMultistoreProofWithWrongKey();

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = header.validatorsHash;
        // appHash arbitrary: revert fires before _verifyMembershipTendermint
        header.appHash = bytes32(uint256(0x99));

        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(0));
        (bytes memory storageEntry,) = _buildStorageProofEntry(spKey, new bytes(32));

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory storageEntries = abi.encodePacked(
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry)
        );
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProofBytes, bytes("evm"));
        bytes memory proofBytes = abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabb"))
        );

        vm.expectRevert(SeiCometBftVerifier.InvalidStoreKey.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Non-existence proof error path — NonExistenceSlotNotEmpty (line 458)
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_nonExistenceSlotNotEmpty_reverts() public {
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, _validators);

        bytes32 storeRoot = _nonExistenceStoreRoot();
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        // Position 0's slot must be the real cBase+1 slot — the emptiness check fires only after
        // the slot-key check.
        bytes memory spKey = _correctSlotKeys(serviceAddr)[0];
        // CommitmentProof field 2 = non-existence (minimal, just the key)
        bytes memory nepBytes = PB.encodeBytesField(1, spKey);
        bytes memory commitmentProof = PB.encodeBytesField(2, nepBytes);
        // StorageProofEntry: key + non-empty value + non-existence proof → NonExistenceSlotNotEmpty
        bytes memory entryWithValue = abi.encodePacked(
            PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, hex"ff"), PB.encodeBytesField(3, commitmentProof)
        );

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory storageEntries = abi.encodePacked(
            PB.encodeBytesField(4, entryWithValue),
            PB.encodeBytesField(4, entryWithValue),
            PB.encodeBytesField(4, entryWithValue),
            PB.encodeBytesField(4, entryWithValue)
        );
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory proofBytes = abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabb"))
        );

        vm.expectRevert(SeiCometBftVerifier.NonExistenceSlotNotEmpty.selector);
        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Non-existence proof success path — zero storage slots (line 453 false)
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_nonExistenceProof_succeeds() public view {
        bytes20 serviceAddr = bytes20(SERVICE_ADDR);
        bytes memory anchor = abi.encode(CHAIN_ID, _validators);

        // Single-leaf IAVL tree (key=0x00, value=0xff) proves all 0x03-prefixed keys absent
        bytes32 storeRoot = _nonExistenceStoreRoot();
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        // Each position must be the real cBase+1/+2/+4/+5 slot (not an arbitrary small integer) —
        // the verifier checks the declared slot number, not just the prefix/length/address.
        bytes[5] memory correctKeys = _correctSlotKeys(serviceAddr);
        bytes memory storageEntries;
        for (uint256 i = 0; i < 5; i++) {
            bytes memory entry = _buildValidNonExistenceStorageEntry(correctKeys[i]);
            storageEntries = abi.encodePacked(storageEntries, PB.encodeBytesField(4, entry));
        }

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory proofBytes = abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabb"))
        );

        harness.verifyBundle(proofBytes, anchor, _ctx(serviceAddr));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  verifyConfig — wrong-length Ed25519 pubkey (line 1202)
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyConfig_invalidEd25519KeyLength_reverts() public {
        bytes memory wrongPubKey = new bytes(31); // must be 32
        bytes memory valEntry = PB.encodeBytesField(1, wrongPubKey);
        bytes memory validatorSetBytes = PB.encodeBytesField(1, valEntry);

        bytes memory ledgerConfigBytes = _buildLedgerConfig(CHAIN_ID, bytes20(SERVICE_ADDR));
        bytes memory configPayload = abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, hex"0a01") // dummy non-empty stateProof — never reached
        );

        vm.expectRevert(SeiCometBftVerifier.InvalidEd25519KeyLength.selector);
        harness.verifyConfig(configPayload, bytes32(0), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  skipField defensive branches — unknown protobuf fields
    // ─────────────────────────────────────────────────────────────────────────
    // Each parser has an `else { off = PB.skipField(data, off, wt); }` branch.
    // Embed field-99 (varint wire type, value 0) to exercise that branch
    // without triggering any required-field errors.

    function test_skipField_bundlePayload() public view {
        bytes memory data = abi.encodePacked(
            PB.encodeBytesField(1, hex"aa"), // stateProof  (required)
            PB.encodeBytesField(2, hex"bb"), // bundleContent (required)
            PB.encodeVarintField(99, 0) // unknown → else { skipField }
        );
        (bytes memory sp, bytes memory bc, bytes memory nv) = harness.parseBundlePayload(data);
        assertEq(sp, hex"aa");
        assertEq(bc, hex"bb");
        assertEq(nv.length, 0);
    }

    function test_skipField_configPayload() public view {
        bytes memory data = abi.encodePacked(
            PB.encodeBytesField(1, hex"11"), // validatorSet (required)
            PB.encodeBytesField(2, hex"22"), // ledgerConfig (required)
            PB.encodeBytesField(3, hex"33"), // stateProof   (required)
            PB.encodeVarintField(99, 0) // unknown → else { skipField }
        );
        (bytes memory vs, bytes memory lc, bytes memory sp) = harness.parseConfigPayload(data);
        assertEq(vs, hex"11");
        assertEq(lc, hex"22");
        assertEq(sp, hex"33");
    }

    function test_skipField_stateProof() public view {
        (bytes memory sh, bytes memory sk, bytes memory mp, bytes[] memory entries) =
            harness.parseStateProof(PB.encodeVarintField(99, 0));
        assertEq(sh.length, 0);
        assertEq(sk.length, 0);
        assertEq(mp.length, 0);
        assertEq(entries.length, 0);
    }

    function test_skipField_signedHeader() public view {
        (CometBftLib.SeiHeader memory h,) = harness.parseSignedHeader(PB.encodeVarintField(99, 0));
        assertEq(h.height, 0);
    }

    function test_skipField_header() public view {
        CometBftLib.SeiHeader memory h = harness.parseHeader(PB.encodeVarintField(99, 0));
        assertEq(h.height, 0);
    }

    function test_skipField_timestamp() public view {
        (int64 s, int32 ns) = harness.parseTimestamp(PB.encodeVarintField(99, 0));
        assertEq(s, 0);
        assertEq(ns, 0);
    }

    function test_skipField_blockId() public view {
        (bytes32 hash_,, bytes32 partHash_) = harness.parseBlockId(PB.encodeVarintField(99, 0));
        assertEq(hash_, bytes32(0));
        assertEq(partHash_, bytes32(0));
    }

    function test_skipField_partSetHeader() public view {
        (uint32 total_, bytes32 hash_) = harness.parsePartSetHeader(PB.encodeVarintField(99, 0));
        assertEq(total_, 0);
        assertEq(hash_, bytes32(0));
    }

    function test_skipField_commit() public view {
        CometBftLib.SeiCommit memory c = harness.parseCommit(PB.encodeVarintField(99, 0));
        assertEq(c.round, 0);
        assertEq(c.signatures.length, 0);
    }

    function test_skipField_commitSig() public view {
        CometBftLib.CommitSig memory sig = harness.parseCommitSig(PB.encodeVarintField(99, 0));
        assertEq(sig.timestampSeconds, 0);
        assertEq(sig.signature.length, 0);
    }

    function test_skipField_validatorEntry() public view {
        CometBftLib.SeiValidator memory v = harness.parseValidatorEntry(PB.encodeVarintField(99, 0));
        assertEq(v.votingPower, 0);
        assertEq(v.ed25519PubKey, bytes32(0));
    }

    function test_skipField_ledgerConfiguration() public view {
        (string memory chainId,,,,) = harness.parseLedgerConfiguration(PB.encodeVarintField(99, 0));
        assertEq(bytes(chainId).length, 0);
    }

    function test_skipField_nonExistenceProof() public view {
        Ics23Lib.NonExistenceProof memory nep = harness.parseNonExistenceProof(PB.encodeVarintField(99, 0));
        assertEq(nep.key.length, 0);
        assertFalse(nep.hasLeft);
        assertFalse(nep.hasRight);
    }

    function test_skipField_existenceProofInner() public view {
        Ics23Lib.ExistenceProof memory ep = harness.parseExistenceProofInner(PB.encodeVarintField(99, 0));
        assertEq(ep.key.length, 0);
        assertEq(ep.path.length, 0);
    }

    function test_skipField_leafOp() public view {
        Ics23Lib.LeafOp memory leaf = harness.parseLeafOp(PB.encodeVarintField(99, 0));
        assertEq(leaf.hashOp, 0);
        assertEq(leaf.prefix.length, 0);
    }

    function test_skipField_innerOp() public view {
        Ics23Lib.InnerOp memory op = harness.parseInnerOp(PB.encodeVarintField(99, 0));
        assertEq(op.hashOp, 0);
        assertEq(op.prefix.length, 0);
    }

    function test_skipField_decodeBundleContent() public view {
        bytes[] memory msgs = harness.decodeBundleContent(PB.encodeVarintField(99, 0));
        assertEq(msgs.length, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Commit round field (fn_==1 in _parseCommit, lines 1121-1124)
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseCommit_roundField_parsed() public view {
        CometBftLib.SeiCommit memory c = harness.parseCommit(PB.encodeVarintField(1, 7));
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(c.round, int32(7));
        assertEq(c.signatures.length, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Ics23Lib.LeafOp optional fields (lines 1405-1413)
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseLeafOp_prehashKeyField() public view {
        // field 2 = prehashKey (varint)
        Ics23Lib.LeafOp memory leaf = harness.parseLeafOp(PB.encodeVarintField(2, 3));
        assertEq(leaf.prehashKey, 3);
        assertEq(leaf.hashOp, 0);
    }

    function test_parseLeafOp_prehashValueField() public view {
        // field 3 = prehashValue (varint)
        Ics23Lib.LeafOp memory leaf = harness.parseLeafOp(PB.encodeVarintField(3, 2));
        assertEq(leaf.prehashValue, 2);
        assertEq(leaf.hashOp, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  nextValidatorSet trust-anchor rotation (lines 288-293)
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyBundle_withNextValidatorSet_producesNewAnchor() public view {
        // Prepare a one-validator next set with a distinct key.
        CometBftLib.SeiValidator[] memory nextVals = new CometBftLib.SeiValidator[](1);
        nextVals[0] = CometBftLib.SeiValidator({ed25519PubKey: keccak256("sei-next-val"), votingPower: int64(500)});

        bytes32 nextSetHash = harness.validatorSetHash(nextVals);
        bytes memory nextValSetBytes = _encodeValidatorSet(nextVals);

        // Build header: validatorsHash = current set, nextValidatorsHash = next set.
        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(_validators);
        header.nextValidatorsHash = nextSetHash;

        bytes memory bundleProofBytes =
            _wrapBundlePayloadWithHeaderAndNextVals(header, _validators, bytes20(SERVICE_ADDR), nextValSetBytes);
        bytes memory anchor = abi.encode(CHAIN_ID, _validators);

        (,, bytes memory newAnchor,,) = harness.verifyBundle(bundleProofBytes, anchor, _ctx(bytes20(SERVICE_ADDR)));

        // New trust anchor must encode the next validator set.
        (string memory newChainId, CometBftLib.SeiValidator[] memory newVals) =
            abi.decode(newAnchor, (string, CometBftLib.SeiValidator[]));
        assertEq(newChainId, CHAIN_ID, "anchor chainId");
        assertEq(newVals.length, 1, "one next validator");
        assertEq(newVals[0].ed25519PubKey, keccak256("sei-next-val"), "next validator pubkey");
        assertEq(newVals[0].votingPower, int64(500), "next validator voting power");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  InvalidProposerAddressLength (SeiCometBftVerifier.sol:1019, branch=0)
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseHeader_invalidProposerAddressLength_reverts() public {
        // field 15 in the CometBftLib.SeiHeader proto encodes the proposer address.
        // Any length other than 20 bytes must revert with InvalidProposerAddressLength.
        bytes memory data = PB.encodeBytesField(15, hex"0102030405"); // 5 bytes, not 20
        vm.expectRevert(SeiCometBftVerifier.InvalidProposerAddressLength.selector);
        harness.parseHeader(data);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  InvalidServiceAddressLength (SeiCometBftVerifier.sol:1255, branch=0)
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseLedgerConfiguration_invalidServiceAddressLength_reverts() public {
        // field 2 in ClprLedgerConfiguration encodes the service address.
        // Any length other than 20 bytes must revert with InvalidServiceAddressLength.
        bytes memory data = PB.encodeBytesField(2, hex"dead"); // 2 bytes, not 20
        vm.expectRevert(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector);
        harness.parseLedgerConfiguration(data);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  _verifyEd25519 sig-length guard (SeiCometBftVerifier.sol:1524, branch=0)
    // ─────────────────────────────────────────────────────────────────────────

    function test_verifyEd25519_shortSig_returnsFalse() public {
        // Deploy a real Ed25519Verifier so the base _verifyEd25519 is exercised
        // (the extended harness overrides it; we use SeiCometBftVerifierBaseHarness
        //  which inherits the real implementation unchanged).
        address ed = deployCode("Ed25519Verifier.sol:Ed25519Verifier");

        SeiCometBftVerifierBaseHarness base = SeiCometBftVerifierBaseHarness(
            deployCode("SeiCometBftVerifierErrors.t.sol:SeiCometBftVerifierBaseHarness", abi.encode(ed))
        );

        // 63-byte sig triggers the length guard at line 1524: `if (sig.length != 64) return false`
        assertFalse(base.verifyEd25519Direct(bytes32(0), bytes("msg"), new bytes(63)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Last-condition-match tests (covers branch=1 for all preceding conditions)
    //  Pattern: pass the Nth (final) field in each if-else-if chain directly to
    //  the exposed harness function. viaIR registers branch=1 for conditions
    //  1..N-1 only when at least one condition eventually matches.
    // ─────────────────────────────────────────────────────────────────────────

    function test_parseBundlePayload_fn3LastConditionMatch_coversAllFalsePaths() public {
        // fn_=3 (nextValidatorSet): conditions 1 and 2 evaluate to FALSE → branch=1.
        // stateProof and bundleContent remain empty → revert expected.
        vm.expectRevert(SeiCometBftVerifier.MissingStateProof.selector);
        harness.parseBundlePayload(PB.encodeBytesField(3, hex"cc"));
    }

    function test_parseConfigPayload_fn3LastConditionMatch_coversAllFalsePaths() public {
        // fn_=3 (stateProof): conditions 1 and 2 evaluate to FALSE → branch=1.
        // validatorSet remains empty → revert expected.
        vm.expectRevert(SeiCometBftVerifier.MissingValidatorSet.selector);
        harness.parseConfigPayload(PB.encodeBytesField(3, hex"dd"));
    }

    function test_parseStateProof_fn4LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=4 (storageProofEntry): conditions 1, 2, 3 evaluate to FALSE → branch=1.
        (bytes memory sh, bytes memory sk, bytes memory mp, bytes[] memory entries) =
            harness.parseStateProof(PB.encodeBytesField(4, hex"ee"));
        assertEq(entries.length, 1);
        assertEq(entries[0], hex"ee");
        assertEq(sh.length, 0);
        assertEq(sk.length, 0);
        assertEq(mp.length, 0);
    }

    function test_parseSignedHeader_fn2LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=2 (commit bytes): condition 1 evaluates to FALSE → branch=1.
        // PB.encodeBytesField returns empty for empty content; use raw proto: tag=0x12, length=0.
        (, CometBftLib.SeiCommit memory c) = harness.parseSignedHeader(hex"1200");
        assertEq(c.signatures.length, 0);
    }

    function test_parseTimestamp_fn2LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=2, wt=0 (nanos varint): condition 1 (seconds) evaluates to FALSE → branch=1.
        (, int32 nanos) = harness.parseTimestamp(PB.encodeVarintField(2, 999));
        assertEq(nanos, 999);
    }

    function test_parseBlockId_fn3LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=3, wt=2 (partHash bytes): conditions 1 and 2 evaluate to FALSE → branch=1.
        bytes memory partHashBytes = abi.encodePacked(keccak256("partHash"));
        (,, bytes32 partHash) = harness.parseBlockId(PB.encodeBytesField(3, partHashBytes));
        assertEq(partHash, keccak256("partHash"));
    }

    function test_parseCommit_fn5LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=5, wt=2 (signature entry): conditions 1-4 evaluate to FALSE → branch=1.
        // Raw proto: tag = (5<<3)|2 = 0x2A, length = 0x00 (empty CometBftLib.CommitSig content).
        // PB.encodeBytesField skips empty content; use literal bytes instead.
        CometBftLib.SeiCommit memory c = harness.parseCommit(hex"2a00");
        assertEq(c.signatures.length, 1);
    }

    function test_parseCommitSig_fn2LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=2, wt=2 (signature bytes): condition 1 (timestamp) evaluates to FALSE → branch=1.
        CometBftLib.CommitSig memory sig = harness.parseCommitSig(PB.encodeBytesField(2, hex"112233"));
        assertEq(sig.signature, hex"112233");
    }

    function test_parseValidatorSet_unknownField_coversElsePath() public view {
        // Single-condition if-else: fn_!=1 exercises the else (skipField) → branch=1 at line 1183.
        CometBftLib.SeiValidator[] memory vals = harness.parseValidatorSet(PB.encodeVarintField(99, 0));
        assertEq(vals.length, 0);
    }

    function test_parseValidatorEntry_fn2LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=2, wt=0 (votingPower varint): condition 1 (pubkey) evaluates to FALSE → branch=1.
        CometBftLib.SeiValidator memory v = harness.parseValidatorEntry(PB.encodeVarintField(2, 5000));
        assertEq(v.votingPower, 5000);
        assertEq(v.ed25519PubKey, bytes32(0));
    }

    function test_parseStorageProofEntry_fn3LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=3, wt=2 (iavlProof): conditions 1 and 2 evaluate to FALSE → branch=1.
        (bytes memory key_, bytes memory value_, bytes memory iavl_) =
            harness.parseStorageProofEntry(PB.encodeBytesField(3, hex"1234"));
        assertEq(iavl_, hex"1234");
        assertEq(key_.length, 0);
        assertEq(value_.length, 0);
    }

    function test_parseLedgerConfiguration_fn4LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=4, wt=2 (throttles): conditions 1, 2, 3 evaluate to FALSE → branch=1.
        // Raw proto: tag = (4<<3)|2 = 0x22, length = 0x00 (empty Throttles content).
        (string memory chainId,,,,) = harness.parseLedgerConfiguration(hex"2200");
        assertEq(bytes(chainId).length, 0);
    }

    function test_parseNonExistenceProof_fn3LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=3, wt=2 (right proof): conditions 1 and 2 evaluate to FALSE → branch=1.
        // Raw proto: tag = (3<<3)|2 = 0x1A, length = 0x00 (empty Ics23Lib.ExistenceProof content).
        Ics23Lib.NonExistenceProof memory nep = harness.parseNonExistenceProof(hex"1a00");
        assertTrue(nep.hasRight);
        assertFalse(nep.hasLeft);
    }

    function test_parseExistenceProofInner_fn4LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=4, wt=2 (innerOp): conditions 1, 2, 3 evaluate to FALSE → branch=1.
        // Raw proto: tag = (4<<3)|2 = 0x22, length = 0x00 (empty Ics23Lib.InnerOp content).
        Ics23Lib.ExistenceProof memory proof = harness.parseExistenceProofInner(hex"2200");
        assertEq(proof.path.length, 1);
        assertEq(proof.key.length, 0);
    }

    function test_parseLeafOp_fn5LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=5, wt=2 (prefix bytes): conditions 1-4 (all varint) evaluate to FALSE → branch=1.
        Ics23Lib.LeafOp memory leaf = harness.parseLeafOp(PB.encodeBytesField(5, hex"aabb"));
        assertEq(leaf.prefix, hex"aabb");
        assertEq(leaf.hashOp, 0);
    }

    function test_parseInnerOp_fn3LastConditionMatch_coversAllFalsePaths() public view {
        // fn_=3, wt=2 (suffix bytes): conditions 1 and 2 evaluate to FALSE → branch=1.
        Ics23Lib.InnerOp memory op = harness.parseInnerOp(PB.encodeBytesField(3, hex"ccdd"));
        assertEq(op.suffix, hex"ccdd");
        assertEq(op.hashOp, 0);
    }

    function test_decodeBundleContent_ignoresNonMessageFields() public view {
        // A non-field-2 entry (here field 3) is skipped by the shared decoder; only field-2 message
        // payloads are surfaced. (Sei carries trust-anchor rotation via the bundle payload, not here.)
        bytes[] memory msgs = harness.decodeBundleContent(PB.encodeBytesField(3, hex"ff"));
        assertEq(msgs.length, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Proof-construction helpers (shared with error tests above)
    // ─────────────────────────────────────────────────────────────────────────

    function _deployAndExpectRevert(string memory artifact, bytes memory args) private {
        bytes memory code = abi.encodePacked(vm.getCode(artifact), args);
        assembly {
            let addr := create(0, add(code, 0x20), mload(code))
            if iszero(addr) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function _validLeafProof(bytes memory key, bytes memory value)
        internal
        pure
        returns (Ics23Lib.ExistenceProof memory proof)
    {
        proof.key = key;
        proof.value = value;
        proof.leaf = Ics23Lib.LeafOp({hashOp: 1, prehashKey: 0, prehashValue: 1, lengthOp: 1, prefix: hex"00"});
        proof.path = new Ics23Lib.InnerOp[](0);
    }

    function _validTmLeafProof(bytes memory key, bytes memory value)
        internal
        pure
        returns (Ics23Lib.ExistenceProof memory proof)
    {
        // Tendermint spec: minPrefix=1, maxPrefix=1, childSize=32 → same leaf format as IAVL
        return _validLeafProof(key, value);
    }

    function _validLeafProofWithInnerOp(bytes memory key, bytes memory value)
        internal
        pure
        returns (Ics23Lib.ExistenceProof memory proof)
    {
        proof.key = key;
        proof.value = value;
        proof.leaf = Ics23Lib.LeafOp({hashOp: 1, prehashKey: 0, prehashValue: 1, lengthOp: 1, prefix: hex"00"});
        proof.path = new Ics23Lib.InnerOp[](1);
        proof.path[0] = _leftInnerOp();
    }

    function _appendInnerOp(Ics23Lib.ExistenceProof memory proof, Ics23Lib.InnerOp memory op)
        internal
        pure
        returns (Ics23Lib.ExistenceProof memory)
    {
        Ics23Lib.InnerOp[] memory newPath = new Ics23Lib.InnerOp[](proof.path.length + 1);
        for (uint256 i = 0; i < proof.path.length; i++) {
            newPath[i] = proof.path[i];
        }
        newPath[proof.path.length] = op;
        proof.path = newPath;
        return proof;
    }

    function _leftInnerOp() internal pure returns (Ics23Lib.InnerOp memory op) {
        // Branch 0 (left child): suffix.length == IAVL_CHILD_SIZE(33), prefix 4..12 bytes
        op.hashOp = 1;
        op.prefix = new bytes(5);
        op.prefix[0] = 0x04; // non-zero, non-leaf
        op.suffix = new bytes(33);
    }

    function _rightInnerOp() internal pure returns (Ics23Lib.InnerOp memory op) {
        // Branch 1 (right child): suffix.length == 0, prefix 37..45 bytes
        op.hashOp = 1;
        op.prefix = new bytes(37);
        op.prefix[0] = 0x04;
        op.suffix = new bytes(0);
    }

    function _buildNonExistenceProof(bytes memory absentKey, bytes memory leftKey, bytes memory rightKey)
        internal
        view
        returns (Ics23Lib.NonExistenceProof memory nep, bytes32 root)
    {
        // Leaf-only proofs to obtain the leaf hashes.
        Ics23Lib.ExistenceProof memory leftProof = _validLeafProof(leftKey, hex"ff");
        Ics23Lib.ExistenceProof memory rightProof = _validLeafProof(rightKey, hex"ee");

        bytes32 lH = harness.existenceRootIavl(leftProof);
        bytes32 rH = harness.existenceRootIavl(rightProof);

        // Two-leaf IAVL tree: root = sha256(P1 || lH || P2 || rH)
        // where P1 is the shared inner-node prefix bytes and P2 is a 1-byte separator.
        // Left-child inner op:  prefix = P1 (5 bytes), suffix = P2 || rH (33 bytes)
        //   → sha256(P1 || lH || P2 || rH) = root ✓
        // Right-child inner op: prefix = P1 || lH || P2 (38 bytes), suffix = []
        //   → sha256((P1 || lH || P2) || rH) = sha256(P1 || lH || P2 || rH) = root ✓
        bytes5 P1 = hex"0408011001"; // 5-byte inner-node prefix (first byte 0x04 ≠ LEAF_PREFIX 0x00)
        bytes1 P2 = 0x20; // 1-byte separator between left and right child hashes

        Ics23Lib.InnerOp memory lInner;
        lInner.hashOp = 1;
        lInner.prefix = abi.encodePacked(P1); // 5 bytes ∈ [4,12] ✓
        lInner.suffix = abi.encodePacked(P2, rH); // 1+32 = 33 bytes (= IAVL_CHILD_SIZE) ✓

        Ics23Lib.InnerOp memory rInner;
        rInner.hashOp = 1;
        rInner.prefix = abi.encodePacked(P1, lH, P2); // 5+32+1 = 38 bytes ∈ [37,45] ✓
        rInner.suffix = new bytes(0); // right-child → no suffix ✓

        leftProof = _appendInnerOp(leftProof, lInner);
        rightProof = _appendInnerOp(rightProof, rInner);

        root = harness.existenceRootIavl(leftProof);

        nep.key = absentKey;
        nep.hasLeft = true;
        nep.left = leftProof;
        nep.hasRight = true;
        nep.right = rightProof;
    }

    // ── Full bundle proof builders ────────────────────────────────────────────

    function _syntheticHeader() internal pure override returns (CometBftLib.SeiHeader memory h) {
        h.versionBlock = 11;
        h.versionApp = 1;
        h.chainId = CHAIN_ID;
        h.height = 100;
        h.timeSeconds = 1_700_000_000;
        h.timeNanos = 0;
        h.lastBlockIdHash = bytes32(uint256(0xAAAA));
        h.lastBlockIdPartSetTotal = 1;
        h.lastBlockIdPartSetHash = bytes32(uint256(0xBBBB));
        h.lastCommitHash = bytes32(uint256(0x01));
        h.dataHash = bytes32(uint256(0x02));
        h.validatorsHash = bytes32(uint256(0x03));
        h.nextValidatorsHash = bytes32(uint256(0x04));
        h.consensusHash = bytes32(uint256(0x05));
        h.appHash = bytes32(uint256(0x06));
        h.lastResultsHash = bytes32(uint256(0x07));
        h.evidenceHash = bytes32(uint256(0x08));
        h.proposerAddress = bytes20(address(0xDEAD));
    }

    function _buildStorageProofEntry(bytes memory spKey, bytes memory spValue)
        internal
        pure
        override
        returns (bytes memory entry, bytes32 iavlRoot)
    {
        Ics23Lib.LeafOp memory leaf =
            Ics23Lib.LeafOp({hashOp: 1, prehashKey: 0, prehashValue: 1, lengthOp: 1, prefix: hex"00"});

        bytes memory hashedValue = abi.encodePacked(sha256(spValue));
        bytes memory encodedKey = abi.encodePacked(PB.encodeVarint(uint64(spKey.length)), spKey);
        bytes memory encodedValue = abi.encodePacked(PB.encodeVarint(uint64(hashedValue.length)), hashedValue);
        iavlRoot = sha256(abi.encodePacked(leaf.prefix, encodedKey, encodedValue));

        bytes memory leafBytes = abi.encodePacked(
            PB.encodeVarintField(1, leaf.hashOp),
            PB.encodeVarintField(2, leaf.prehashKey),
            PB.encodeVarintField(3, leaf.prehashValue),
            PB.encodeVarintField(4, leaf.lengthOp),
            PB.encodeBytesField(5, leaf.prefix)
        );
        bytes memory epInner = abi.encodePacked(
            PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, spValue), PB.encodeBytesField(3, leafBytes)
        );
        bytes memory iavlProofBytes = PB.encodeBytesField(1, epInner);
        entry = abi.encodePacked(
            PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, spValue), PB.encodeBytesField(3, iavlProofBytes)
        );
    }

    function _buildNonExistenceEntry(bytes memory spKey) internal pure returns (bytes memory entry) {
        // Non-existence proof with empty left and right (won't pass real verification,
        // but we just need to produce a proof with the right proto structure for shape testing)
        bytes memory nepBytes = PB.encodeBytesField(1, spKey);
        bytes memory commitmentProof = PB.encodeBytesField(2, nepBytes);
        entry = abi.encodePacked(
            PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, bytes("")), PB.encodeBytesField(3, commitmentProof)
        );
    }

    function _buildMultistoreProof(bytes32 iavlRoot, bytes memory storeKey)
        internal
        pure
        returns (bytes memory multistoreProofBytes, bytes32 appHash)
    {
        bytes memory storeRootBytes = abi.encodePacked(iavlRoot);

        bytes memory tmHashedValue = abi.encodePacked(sha256(storeRootBytes));
        bytes memory tmEncodedKey = abi.encodePacked(PB.encodeVarint(uint64(storeKey.length)), storeKey);
        bytes memory tmEncodedValue = abi.encodePacked(PB.encodeVarint(uint64(tmHashedValue.length)), tmHashedValue);
        appHash = sha256(abi.encodePacked(hex"00", tmEncodedKey, tmEncodedValue));

        bytes memory tmLeafBytes = abi.encodePacked(
            PB.encodeVarintField(1, 1),
            PB.encodeVarintField(2, 0),
            PB.encodeVarintField(3, 1),
            PB.encodeVarintField(4, 1),
            PB.encodeBytesField(5, hex"00")
        );
        bytes memory tmEpInner = abi.encodePacked(
            PB.encodeBytesField(1, storeKey),
            PB.encodeBytesField(2, storeRootBytes),
            PB.encodeBytesField(3, tmLeafBytes)
        );
        multistoreProofBytes = PB.encodeBytesField(1, tmEpInner);
    }

    function _buildHeaderBytes(CometBftLib.SeiHeader memory header) internal pure override returns (bytes memory) {
        bytes memory timeBytes = abi.encodePacked(
            PB.encodeVarintField(1, uint64(header.timeSeconds)),
            PB.encodeVarintField(2, uint64(uint32(header.timeNanos)))
        );
        bytes memory lastBlockIdBytes = abi.encodePacked(
            PB.encodeBytesField(1, abi.encodePacked(header.lastBlockIdHash)),
            PB.encodeVarintField(2, uint64(header.lastBlockIdPartSetTotal)),
            PB.encodeBytesField(3, abi.encodePacked(header.lastBlockIdPartSetHash))
        );
        return abi.encodePacked(
            PB.encodeVarintField(1, header.versionBlock),
            PB.encodeVarintField(2, header.versionApp),
            PB.encodeBytesField(3, bytes(header.chainId)),
            PB.encodeVarintField(4, uint64(header.height)),
            PB.encodeBytesField(5, timeBytes),
            PB.encodeBytesField(6, lastBlockIdBytes),
            PB.encodeBytesField(7, abi.encodePacked(header.lastCommitHash)),
            PB.encodeBytesField(8, abi.encodePacked(header.dataHash)),
            PB.encodeBytesField(9, abi.encodePacked(header.validatorsHash)),
            PB.encodeBytesField(10, abi.encodePacked(header.nextValidatorsHash)),
            PB.encodeBytesField(11, abi.encodePacked(header.consensusHash)),
            PB.encodeBytesField(12, abi.encodePacked(header.appHash)),
            PB.encodeBytesField(13, abi.encodePacked(header.lastResultsHash)),
            PB.encodeBytesField(14, abi.encodePacked(header.evidenceHash)),
            PB.encodeBytesField(15, abi.encodePacked(header.proposerAddress))
        );
    }

    function _buildCommitBytesWithBitsAndCount(
        CometBftLib.SeiHeader memory header,
        bytes memory signersBits,
        uint256 sigCount,
        bool zeroSigs
    ) internal pure returns (bytes memory) {
        bytes memory timeBytes = abi.encodePacked(
            PB.encodeVarintField(1, uint64(header.timeSeconds)), PB.encodeVarintField(2, 0)
        );

        bytes memory result = abi.encodePacked(
            PB.encodeVarintField(1, 0), // round=0
            PB.encodeVarintField(2, 1), // partSetTotal=1
            PB.encodeBytesField(3, abi.encodePacked(bytes32(uint256(0xBBBB)))),
            PB.encodeBytesField(4, signersBits)
        );

        for (uint256 i = 0; i < sigCount; i++) {
            bytes memory sig = zeroSigs ? new bytes(64) : _nonZeroSig();
            bytes memory sigBytes = abi.encodePacked(PB.encodeBytesField(1, timeBytes), PB.encodeBytesField(2, sig));
            result = abi.encodePacked(result, PB.encodeBytesField(5, sigBytes));
        }
        return result;
    }

    function _nonZeroSig() internal pure returns (bytes memory sig) {
        sig = new bytes(64);
        sig[0] = 0x01; // non-zero so harness doesn't reject it
    }

    function _buildStateProofBytes(
        CometBftLib.SeiHeader memory header,
        bytes memory commitBytes,
        bytes memory storageEntries,
        bytes memory multistoreProof,
        bytes memory storeKey
    ) internal pure returns (bytes memory) {
        bytes memory signedHeaderBytes = abi.encodePacked(
            PB.encodeBytesField(1, _buildHeaderBytes(header)), PB.encodeBytesField(2, commitBytes)
        );
        return abi.encodePacked(
            PB.encodeBytesField(1, signedHeaderBytes),
            PB.encodeBytesField(2, storeKey),
            PB.encodeBytesField(3, multistoreProof),
            storageEntries
        );
    }

    function _buildMinimalBundleProof(CometBftLib.SeiValidator[] memory validators, bytes20 serviceAddr, bool zeroSigs)
        internal
        view
        returns (bytes memory proofBytes, bytes memory anchor)
    {
        anchor = abi.encode(CHAIN_ID, validators);
        proofBytes = _buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag(validators, serviceAddr, hex"C0", zeroSigs);
    }

    function _buildMinimalBundleProofWithSignersBits(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        bytes memory signersBits
    ) internal view returns (bytes memory proofBytes, bytes memory anchor) {
        anchor = abi.encode(CHAIN_ID, validators);
        proofBytes = _buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag(validators, serviceAddr, signersBits, false);
    }

    function _buildMinimalBundleProofWithSignersBitsAndVals(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        bytes memory signersBits
    ) internal view returns (bytes memory proofBytes, bytes memory anchor) {
        anchor = abi.encode(CHAIN_ID, validators);
        proofBytes = _buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag(validators, serviceAddr, signersBits, false);
    }

    function _buildMinimalBundleProofWithSignersBitsAndSigCount(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        bytes memory signersBits,
        uint256 sigCount
    ) internal view returns (bytes memory proofBytes, bytes memory anchor) {
        anchor = abi.encode(CHAIN_ID, validators);

        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(0));
        bytes memory spValue = new bytes(32);
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, signersBits, sigCount, false);

        bytes memory storageEntries = abi.encodePacked(
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry)
        );
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        proofBytes =
            abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }

    function _buildMinimalBundleProofWithZeroSigs(CometBftLib.SeiValidator[] memory validators, bytes20 serviceAddr)
        internal
        view
        returns (bytes memory proofBytes, bytes memory anchor)
    {
        anchor = abi.encode(CHAIN_ID, validators);
        proofBytes = _buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag(validators, serviceAddr, hex"C0", true);
    }

    function _buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        bytes memory signersBits,
        bool zeroSigs
    ) internal view returns (bytes memory proofBytes) {
        (bytes memory storageEntries, bytes32 storeRoot) = _buildFourCorrectNonExistenceEntries(serviceAddr);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        // Count bits set to determine signature count
        uint256 sigCount = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_bitSetLocal(signersBits, i)) sigCount++;
        }

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, signersBits, sigCount, zeroSigs);

        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        proofBytes =
            abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }

    /// @dev Like `_buildMinimalBundleProofWithSignersBitsAndZeroSigsFlag`, but only the LAST
    ///      signature is the invalid all-zero sentinel — exercises the quorum early exit.
    function _buildBundleProofLastSigZero(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        bytes memory signersBits
    ) internal view returns (bytes memory proofBytes) {
        (bytes memory storageEntries, bytes32 storeRoot) = _buildFourCorrectNonExistenceEntries(serviceAddr);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        uint256 sigCount;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_bitSetLocal(signersBits, i)) sigCount++;
        }

        bytes memory timeBytes =
            abi.encodePacked(PB.encodeVarintField(1, uint64(header.timeSeconds)), PB.encodeVarintField(2, 0));
        bytes memory commitBytes = abi.encodePacked(
            PB.encodeVarintField(1, 0), // round=0
            PB.encodeVarintField(2, 1), // partSetTotal=1
            PB.encodeBytesField(3, abi.encodePacked(bytes32(uint256(0xBBBB)))),
            PB.encodeBytesField(4, signersBits)
        );
        for (uint256 i = 0; i < sigCount; i++) {
            bytes memory sig = i == sigCount - 1 ? new bytes(64) : _nonZeroSig(); // last sig invalid
            bytes memory sigBytes = abi.encodePacked(PB.encodeBytesField(1, timeBytes), PB.encodeBytesField(2, sig));
            commitBytes = abi.encodePacked(commitBytes, PB.encodeBytesField(5, sigBytes));
        }

        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        proofBytes =
            abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }

    function _bitSetLocal(bytes memory bits, uint256 idx) internal pure returns (bool) {
        if (bits.length == 0) return false;
        uint256 byteIdx = idx / 8;
        if (byteIdx >= bits.length) return false;
        // forge-lint: disable-next-line(incorrect-shift)
        uint256 mask = 0x80 >> (idx % 8);
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(bits[byteIdx]) & uint8(mask) != 0;
    }

    function _wrapBundlePayload(
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiValidator[] memory,
        bytes20,
        bytes memory storageEntry,
        bytes memory multistoreProof,
        bytes memory storeKey
    ) internal pure returns (bytes memory) {
        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory storageEntries = abi.encodePacked(
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry),
            PB.encodeBytesField(4, storageEntry)
        );
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, storeKey);
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        return abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }

    function _wrapBundlePayloadWithHeader(
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiValidator[] memory,
        bytes20 serviceAddr
    ) internal pure returns (bytes memory) {
        (bytes memory storageEntries, bytes32 storeRoot) = _buildFourCorrectNonExistenceEntries(serviceAddr);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));
        header.appHash = appHash;
        return _wrapBundlePayloadMulti(header, storageEntries, multistoreProof, bytes("evm"));
    }

    function _wrapBundlePayloadWithHeaderAndNextVals(
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiValidator[] memory,
        bytes20 serviceAddr,
        bytes memory nextValidatorSetBytes
    ) internal pure returns (bytes memory) {
        (bytes memory storageEntries, bytes32 storeRoot) = _buildFourCorrectNonExistenceEntries(serviceAddr);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(storeRoot, bytes("evm"));
        header.appHash = appHash;

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        return abi.encodePacked(
            PB.encodeBytesField(1, stateProofBytes),
            PB.encodeBytesField(2, bundleContentBytes),
            PB.encodeBytesField(3, nextValidatorSetBytes)
        );
    }

    function _buildBundleProofWithNStorageEntries(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        uint256 n
    ) internal view returns (bytes memory proofBytes, bytes memory anchor) {
        // nextMessageId=1 -> last message id = 0. See the nextMessageId parameter of
        // `_buildBundleProofWithNStorageEntriesAndNextMessageId` for why non-zero matters here.
        (proofBytes, anchor) = _buildBundleProofWithNStorageEntriesAndNextMessageId(validators, serviceAddr, n, 1);
    }

    function _buildBundleProofWithNStorageEntriesAndNextMessageId(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        uint256 n,
        uint256 nextMessageId
    ) internal view returns (bytes memory proofBytes, bytes memory anchor) {
        anchor = abi.encode(CHAIN_ID, validators);

        // Position 0 encodes `nextMessageId`: once n > 4, deriving the 5th+ entry's expected slot
        // computes `nextMessageId - 1`, which underflows a zero `nextMessageId` — callers exercising
        // that revert path pass `nextMessageId = 0` deliberately.
        // An existence-proof linear chain (rather than the non-existence trick used elsewhere)
        // lets every position — including 4+ — carry a real, distinct, correctly-keyed leaf.
        bytes[5] memory connSlots = _correctSlotKeys(serviceAddr);
        bytes32 msgSlot = _messageRunningHashSlot(0);
        bytes memory msgKey = abi.encodePacked(uint8(0x03), serviceAddr, msgSlot);

        bytes[] memory keys = new bytes[](n);
        bytes32[] memory values = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = i < 5 ? connSlots[i] : msgKey;
            values[i] = i == 0 ? bytes32(nextMessageId << 168) : bytes32(0);
        }
        (bytes[] memory entries, bytes32 iavlRoot) = _buildLinearChainStorageProof(keys, values);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory storageEntries = bytes("");
        for (uint256 i = 0; i < n; i++) {
            storageEntries = abi.encodePacked(storageEntries, PB.encodeBytesField(4, entries[i]));
        }

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        proofBytes =
            abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }

    function _buildConfigProofWithNStorageEntries(
        CometBftLib.SeiValidator[] memory validators,
        bytes20 serviceAddr,
        uint256 n
    ) internal view returns (bytes memory configProofBytes) {
        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(0));
        bytes32 expectedSlot;
        assembly {
            expectedSlot := or(serviceAddr, 0x28)
        }
        bytes memory spValue = abi.encodePacked(expectedSlot);
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory storageEntries = bytes("");
        for (uint256 i = 0; i < n; i++) {
            storageEntries = abi.encodePacked(storageEntries, PB.encodeBytesField(4, storageEntry));
        }
        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, bytes("evm"));

        bytes memory validatorSetBytes = _encodeValidatorSet(validators);
        bytes memory ledgerConfigBytes = _buildLedgerConfig(CHAIN_ID, serviceAddr);

        configProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, stateProofBytes)
        );
    }

    function _buildConfigProofWithWrongSlot(CometBftLib.SeiValidator[] memory validators, bytes20 serviceAddr)
        internal
        view
        returns (bytes memory configProofBytes)
    {
        bytes memory spKey = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(0));
        bytes memory spValue = new bytes(32); // all zeros — wrong slot encoding
        (bytes memory storageEntry, bytes32 iavlRoot) = _buildStorageProofEntry(spKey, spValue);
        (bytes memory multistoreProof, bytes32 appHash) = _buildMultistoreProof(iavlRoot, bytes("evm"));

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = harness.validatorSetHash(validators);
        header.nextValidatorsHash = header.validatorsHash;
        header.appHash = appHash;

        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes = _buildStateProofBytes(
            header, commitBytes, PB.encodeBytesField(4, storageEntry), multistoreProof, bytes("evm")
        );

        bytes memory validatorSetBytes = _encodeValidatorSet(validators);
        bytes memory ledgerConfigBytes = _buildLedgerConfig(CHAIN_ID, serviceAddr);

        configProofBytes = abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, stateProofBytes)
        );
    }

    function _encodeValidatorSet(CometBftLib.SeiValidator[] memory validators) internal pure returns (bytes memory) {
        bytes memory result;
        for (uint256 i = 0; i < validators.length; i++) {
            bytes memory pubKeyField = PB.encodeBytesField(1, abi.encodePacked(validators[i].ed25519PubKey));
            bytes memory vpField;
            if (validators[i].votingPower != 0) {
                vpField = PB.encodeVarintField(2, uint64(validators[i].votingPower));
            }
            bytes memory entry = abi.encodePacked(pubKeyField, vpField);
            result = abi.encodePacked(result, PB.encodeBytesField(1, entry));
        }
        return result;
    }

    function _buildLedgerConfig(string memory chainId, bytes20 serviceAddr) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes(chainId)),
            PB.encodeBytesField(2, abi.encodePacked(serviceAddr)),
            PB.encodeVarintField(3, 1000)
        );
    }

    // ── Non-existence and trust-anchor helpers ────────────────────────────────

    // IAVL leaf hash for a single-leaf tree: key=0x00, value=0xff, no inner ops.
    // Used as storeRoot for non-existence proofs of any key with first byte > 0x00.
    function _nonExistenceStoreRoot() internal pure returns (bytes32) {
        bytes memory k = hex"00";
        bytes memory encodedKey = abi.encodePacked(PB.encodeVarint(uint64(k.length)), k);
        bytes memory hashedValue = abi.encodePacked(sha256(hex"ff"));
        bytes memory encodedValue = abi.encodePacked(PB.encodeVarint(uint64(hashedValue.length)), hashedValue);
        return sha256(abi.encodePacked(hex"00", encodedKey, encodedValue));
    }

    // Builds a fully valid non-existence StorageProofEntry for spKey.
    // The left neighbour (key=0x00, value=0xff, empty path) satisfies:
    //   Ics23Lib.existenceRootIavl(left) == _nonExistenceStoreRoot()
    //   Ics23Lib.bytesLt(0x00, spKey)   == true  (spKey[0] == 0x03)
    //   Ics23Lib.isRightMost([])        == true
    function _buildValidNonExistenceStorageEntry(bytes memory spKey) internal pure returns (bytes memory entry) {
        bytes memory leftLeafBytes = abi.encodePacked(
            PB.encodeVarintField(1, 1), // hashOp=SHA256
            PB.encodeVarintField(2, 0), // prehashKey=0
            PB.encodeVarintField(3, 1), // prehashValue=SHA256
            PB.encodeVarintField(4, 1), // lengthOp=VAR_PROTO
            PB.encodeBytesField(5, hex"00") // prefix=0x00
        );
        bytes memory leftEpInner = abi.encodePacked(
            PB.encodeBytesField(1, hex"00"), // key
            PB.encodeBytesField(2, hex"ff"), // value
            PB.encodeBytesField(3, leftLeafBytes)
        );
        // Ics23Lib.NonExistenceProof proto: field1=absent key, field2=left existence proof
        bytes memory nepInner = abi.encodePacked(PB.encodeBytesField(1, spKey), PB.encodeBytesField(2, leftEpInner));
        bytes memory commitmentProof = PB.encodeBytesField(2, nepInner); // field2 = non-existence
        // StorageProofEntry: field1=key, field2 omitted (zero slot value), field3=iavlProof
        entry = abi.encodePacked(PB.encodeBytesField(1, spKey), PB.encodeBytesField(3, commitmentProof));
    }

    // Builds a multistore CommitmentProof with key="xyz" (≠ "evm") to trigger
    // the second InvalidStoreKey check at line 431 of _verifyStateProof.
    function _buildMultistoreProofWithWrongKey() internal pure returns (bytes memory multistoreProofBytes) {
        bytes memory epInner =
            abi.encodePacked(PB.encodeBytesField(1, bytes("xyz")), PB.encodeBytesField(2, new bytes(32)));
        multistoreProofBytes = PB.encodeBytesField(1, epInner);
    }

    // `verifyBundle` requires every proven slot to match
    // `_channelMetadataSlots(channelId)` (indices 0..3) / the derived message-running-hash
    // slot (index 4+). All tests use channelId = bytes32(0) (see `_ctx`), so these helpers
    // compute the same slots the verifier expects for that channelId.

    /// @dev The four real Channel metadata slots (cBase+1/+2/+4/+5) for channelId = bytes32(0).
    function _correctSlotKeys(bytes20 serviceAddr) internal pure returns (bytes[5] memory keys) {
        bytes32 cBase = keccak256(abi.encode(bytes32(0), uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = abi.encodePacked(uint8(0x03), serviceAddr, bytes32(uint256(cBase) + offsets[i]));
        }
    }

    /// @dev `_messageQueues[channelId=0][messageId].runningHashAfterProcessing` slot (+1),
    ///      matching `ClprEvmBundleVerifier._lastMessageRunningHashSlot`.
    function _messageRunningHashSlot(uint64 messageId) internal pure returns (bytes32) {
        bytes32 qBase = keccak256(abi.encode(bytes32(0), uint256(1)));
        bytes32 msgBase = keccak256(abi.encode(messageId, qBase));
        return bytes32(uint256(msgBase) + 1);
    }

    /// @dev Four correctly-keyed, zero-valued (non-existence) storage proof entries, already
    ///      protobuf-field-wrapped and concatenated (ready to pass as `_buildStateProofBytes`'s
    ///      `storageEntries` argument). All four reuse the same fixed non-existence anchor
    ///      (`_nonExistenceStoreRoot`), since `_buildValidNonExistenceStorageEntry`'s neighbour
    ///      checks don't depend on the specific slot number being proven absent — only on the
    ///      declared key's *prefix byte* (0x03 > the anchor's 0x00).
    function _buildFourCorrectNonExistenceEntries(bytes20 serviceAddr)
        internal
        pure
        returns (bytes memory storageEntries, bytes32 storeRoot)
    {
        bytes[5] memory keys = _correctSlotKeys(serviceAddr);
        storeRoot = _nonExistenceStoreRoot();
        for (uint256 i = 0; i < 5; i++) {
            storageEntries =
                abi.encodePacked(storageEntries, PB.encodeBytesField(4, _buildValidNonExistenceStorageEntry(keys[i])));
        }
    }

    /// @dev Same as `_wrapBundlePayload`, but takes already-built, already-field-wrapped
    ///      `storageEntries` bytes directly instead of reusing one entry four times — needed by
    ///      callers that must present four (or more) genuinely distinct, correctly-keyed slots.
    function _wrapBundlePayloadMulti(
        CometBftLib.SeiHeader memory header,
        bytes memory storageEntries,
        bytes memory multistoreProof,
        bytes memory storeKey
    ) internal pure returns (bytes memory) {
        bytes memory commitBytes = _buildCommitBytesWithBitsAndCount(header, hex"C0", 2, false);
        bytes memory stateProofBytes =
            _buildStateProofBytes(header, commitBytes, storageEntries, multistoreProof, storeKey);
        bytes memory bundleContentBytes = PB.encodeBytesField(2, hex"aabb");
        return abi.encodePacked(PB.encodeBytesField(1, stateProofBytes), PB.encodeBytesField(2, bundleContentBytes));
    }
}
