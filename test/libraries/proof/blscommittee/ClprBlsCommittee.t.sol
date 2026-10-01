// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBlsCommittee as Bls} from "@hiero-ledger/clpr/libraries/proof/blscommittee/ClprBlsCommittee.sol";

contract BlsCommitteeHarness {
    function hashToG1(bytes memory m, bytes memory dst) external view returns (bytes memory) {
        return Bls.hashToG1(m, dst);
    }

    function hashToG2(bytes memory m, bytes memory dst) external view returns (bytes memory) {
        return Bls.hashToG2(m, dst);
    }

    function verifyMinPk(bytes memory pk, bytes memory sig, bytes memory h) external view {
        Bls.verifyMinPk(pk, sig, h);
    }

    function verifyMinSig(bytes memory pk, bytes memory sig, bytes memory h) external view {
        Bls.verifyMinSig(pk, sig, h);
    }

    function requireSubgroup(bytes memory p, uint256 len) external view {
        Bls.requireSubgroup(p, len);
    }

    function aggregate(bytes memory keys, uint256 len, uint256[] memory w, bytes memory bitmap)
        external
        view
        returns (bytes memory, uint256)
    {
        return Bls.aggregateByBitmap(keys, len, w, bitmap);
    }
}

/// @dev RFC 9380 appendix J.9.1 / J.10.1 vectors (QUUX suites) and sign/verify round trips on the
///      EIP-2537 precompiles.
contract ClprBlsCommitteeTest is Test {
    BlsCommitteeHarness internal h;

    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes internal constant G2_GEN =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    function setUp() public {
        h = new BlsCommitteeHarness();
    }

    function _mul(address pre, bytes memory p, uint256 k, uint256 len) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = pre.staticcall(abi.encodePacked(p, k));
        require(ok && out.length == len, "msm");
        return out;
    }

    function test_hashToG1_rfc9380() public view {
        bytes memory dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        assertEq(
            h.hashToG1("", dst),
            hex"00000000000000000000000000000000052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a10000000000000000000000000000000008ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
        );
        assertEq(
            h.hashToG1("abc", dst),
            hex"0000000000000000000000000000000003567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903000000000000000000000000000000000b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"
        );
    }

    function test_hashToG2_rfc9380() public view {
        bytes memory dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        assertEq(
            h.hashToG2("", dst),
            hex"000000000000000000000000000000000141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a0000000000000000000000000000000005cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d000000000000000000000000000000000503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd920000000000000000000000000000000012424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6"
        );
        assertEq(
            h.hashToG2("abc", dst),
            hex"0000000000000000000000000000000002c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e600000000000000000000000000000000139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8000000000000000000000000000000001787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba480000000000000000000000000000000000aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16"
        );
    }

    function test_minPk_roundTrip_andWrongMessage() public {
        bytes memory dst = "TEST_DST";
        bytes memory pk = _mul(address(0x0c), G1_GEN, 12345, 128);
        bytes memory hm = h.hashToG2("hello", dst);
        bytes memory sig = _mul(address(0x0e), hm, 12345, 256);
        h.verifyMinPk(pk, sig, hm);
        bytes memory other = h.hashToG2("hellp", dst);
        vm.expectRevert(Bls.BlsSignatureInvalid.selector);
        h.verifyMinPk(pk, sig, other);
    }

    function test_minSig_roundTrip_andWrongKey() public {
        bytes memory dst = "TEST_DST";
        bytes memory pk = _mul(address(0x0e), G2_GEN, 777, 256);
        bytes memory hm = h.hashToG1("hello", dst);
        bytes memory sig = _mul(address(0x0c), hm, 777, 128);
        h.verifyMinSig(pk, sig, hm);
        bytes memory pk2 = _mul(address(0x0e), G2_GEN, 778, 256);
        vm.expectRevert(Bls.BlsSignatureInvalid.selector);
        h.verifyMinSig(pk2, sig, hm);
    }

    function test_aggregateByBitmap_weightsAndTrailingBits() public {
        bytes memory keys = abi.encodePacked(
            _mul(address(0x0c), G1_GEN, 1, 128),
            _mul(address(0x0c), G1_GEN, 2, 128),
            _mul(address(0x0c), G1_GEN, 4, 128)
        );
        uint256[] memory w = new uint256[](3);
        w[0] = 10;
        w[1] = 20;
        w[2] = 40;
        (bytes memory agg, uint256 sw) = h.aggregate(keys, 128, w, hex"05");
        assertEq(sw, 50);
        assertEq(agg, _mul(address(0x0c), G1_GEN, 5, 128));
        vm.expectRevert(Bls.BlsBadPointLength.selector);
        h.aggregate(keys, 128, w, hex"0d"); // bit 3 is past n = 3
        vm.expectRevert(Bls.BlsNoSigners.selector);
        h.aggregate(keys, 128, w, hex"00");
    }

    function test_requireSubgroup_rejectsOffCurvePoint() public {
        h.requireSubgroup(G1_GEN, 128);
        bytes memory bad = G1_GEN;
        bad[127] = bytes1(uint8(bad[127]) ^ 1);
        vm.expectRevert(Bls.BlsPrecompileFailed.selector);
        h.requireSubgroup(bad, 128);
    }
}
