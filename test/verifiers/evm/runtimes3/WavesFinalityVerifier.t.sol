// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WavesFinalityVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/WavesFinalityVerifier.sol";
import {WavesBls} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/WavesBls.sol";
import {Blake2b256} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/Blake2b256.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @dev Exposes the libraries so revert selectors surface through an external call.
contract WavesLibHarness {
    function blake(bytes calldata d) external view returns (bytes32) {
        return Blake2b256.hash(d);
    }

    function hashToG2(bytes calldata m) external view returns (bytes memory) {
        return WavesBls.hashToG2(m);
    }
}

/// @dev WavesFinalityVerifier with real BLS12-381 signatures made on the EIP-2537 precompiles
///      (keys sk·G1 with G1MSM, signatures sk·H(m) with G2MSM) over a synthetic header.
///      Live Waves testnet data runs in waves-live.spec.ts.
contract WavesFinalityVerifierTest is Test {
    WavesFinalityVerifier internal verifier;
    WavesLibHarness internal lib;

    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    uint32 internal constant PERIOD_START = 1000;
    uint32 internal constant PERIOD_END = 4000;
    bytes32 internal constant FINALIZED_ID = keccak256("finalized block");
    uint32 internal constant FINALIZED_HEIGHT = 1500;

    uint256[4] internal sks = [uint256(11), 22, 33, 44];
    uint64[4] internal balances = [uint64(40), 30, 20, 10];

    function setUp() public {
        verifier = new WavesFinalityVerifier();
        lib = new WavesLibHarness();
    }

    // ── BLS helpers on the precompiles ───────────────────────────────────────

    function _g1Mul(uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0c).staticcall(abi.encodePacked(G1_GEN, sk));
        require(ok && r.length == 128, "g1msm");
        return r;
    }

    function _g2Mul(bytes memory p, uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0e).staticcall(abi.encodePacked(p, sk));
        require(ok && r.length == 256, "g2msm");
        return r;
    }

    function _set() internal view returns (bytes memory s) {
        s = abi.encodePacked(PERIOD_START, PERIOD_END);
        for (uint256 i; i < 4; ++i) {
            s = abi.encodePacked(s, _g1Mul(sks[i]), balances[i]);
        }
    }

    function _header() internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeVarintField(1, uint8(84)),
            PB.encodeBytesField(2, abi.encodePacked(keccak256("parent"))),
            PB.encodeVarintField(6, uint64(1_790_000_000_000)),
            PB.encodeVarintField(7, uint8(5)),
            PB.encodeBytesField(10, abi.encodePacked(keccak256("tx root"))),
            PB.encodeBytesField(11, abi.encodePacked(keccak256("state hash")))
        );
    }

    function _sign(uint32[] memory idx, bytes memory header, uint32 finalizedHeight)
        internal
        view
        returns (bytes memory sig)
    {
        bytes memory hm = lib.hashToG2(abi.encodePacked(FINALIZED_ID, finalizedHeight, lib.blake(header)));
        uint256 sum;
        for (uint256 j; j < idx.length; ++j) {
            sum += sks[idx[j]];
        }
        sig = _g2Mul(hm, sum);
    }

    function _idx(uint32 a, uint32 b) internal pure returns (uint32[] memory r) {
        r = new uint32[](2);
        r[0] = a;
        r[1] = b;
    }

    function _endorsement(uint32[] memory idx, bytes memory header)
        internal
        view
        returns (WavesFinalityVerifier.Endorsement memory e)
    {
        e = WavesFinalityVerifier.Endorsement({
            finalizedId: FINALIZED_ID,
            finalizedHeight: FINALIZED_HEIGHT,
            endorserIndexes: idx,
            signature: _sign(idx, header, FINALIZED_HEIGHT)
        });
    }

    // ── BLAKE2b-256 (vectors from Python hashlib.blake2b(digest_size=32)) ────

    function test_blake2b_vectors() public view {
        assertEq(lib.blake(""), 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8);
        assertEq(lib.blake("abc"), 0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319);
        bytes memory d128 = new bytes(128);
        for (uint256 i; i < 128; ++i) {
            d128[i] = bytes1(uint8(i));
        }
        assertEq(lib.blake(d128), 0xc3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1);
        bytes memory d300 = new bytes(300);
        for (uint256 i; i < 300; ++i) {
            d300[i] = bytes1(uint8((i * 7) % 256));
        }
        assertEq(lib.blake(d300), 0x91ccce0ba9e15867934e70e07d8d4af1270ec75748be56a3f48f5bc8b6c3967d);
    }

    // ── verifyFinalized ──────────────────────────────────────────────────────

    function test_verifyFinalized_twoThirds() public view {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.FinalBlock memory b =
            verifier.verifyFinalized(header, _endorsement(_idx(0, 1), header), set, keccak256(set));
        assertEq(b.id, lib.blake(header));
        assertEq(b.parentId, keccak256("parent"));
        assertEq(b.transactionsRoot, keccak256("tx root"));
        assertEq(b.stateHash, keccak256("state hash"));
        assertEq(b.timestamp, 1_790_000_000_000);
        assertEq(b.endorsedBalance, 70);
        assertEq(b.totalBalance, 100);
    }

    function test_revert_belowTwoThirds() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(1, 2), header);
        vm.expectRevert(abi.encodeWithSelector(WavesFinalityVerifier.BelowTwoThirds.selector, 50, 100));
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_notAscending() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(1, 0), header);
        vm.expectRevert(WavesFinalityVerifier.EndorserIndexesNotAscending.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_duplicateIndex() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 0), header);
        vm.expectRevert(WavesFinalityVerifier.EndorserIndexesNotAscending.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_indexOutOfRange() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        e.endorserIndexes = _idx(0, 4);
        vm.expectRevert(WavesFinalityVerifier.EndorserIndexOutOfRange.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_wrongSet() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        vm.expectRevert(WavesFinalityVerifier.GeneratorSetMismatch.selector);
        verifier.verifyFinalized(header, e, set, keccak256("other set"));
    }

    function test_revert_outsidePeriod() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        e.finalizedHeight = PERIOD_END;
        vm.expectRevert(WavesFinalityVerifier.OutsideGenerationPeriod.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_tamperedHeader() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        header[header.length - 1] ^= 0x01;
        vm.expectRevert(WavesBls.BlsSignatureInvalid.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_signatureOverOtherHeight() public {
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        e.signature = _sign(_idx(0, 1), header, FINALIZED_HEIGHT + 1);
        vm.expectRevert(WavesBls.BlsSignatureInvalid.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }

    function test_revert_signerNotListed() public {
        // Signed by 0 and 2, claimed as 0 and 1.
        bytes memory set = _set();
        bytes memory header = _header();
        WavesFinalityVerifier.Endorsement memory e = _endorsement(_idx(0, 1), header);
        e.signature = _sign(_idx(0, 2), header, FINALIZED_HEIGHT);
        vm.expectRevert(WavesBls.BlsSignatureInvalid.selector);
        verifier.verifyFinalized(header, e, set, keccak256(set));
    }
}
