// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBlake3} from "@hiero-ledger/clpr/libraries/crypto/ClprBlake3.sol";

/// @dev SHA-512 and BLAKE3 against Node `crypto` (SHA-512) and @noble/hashes (BLAKE3) over inputs
///      byte[i] = i % 251, at every padding, block and chunk boundary that matters. The BLAKE3 lengths
///      past 1024 exercise the chunk tree (2, 3, 4 and 5 chunks). The official BLAKE3 vector for the
///      empty input and the FIPS 180-4 "abc" vector are pinned separately.
contract ClprHashesTest is Test {
    address internal hasher;

    function setUp() public {
        // deployed from its artifact: importing it would pull this file onto its legacy profile
        hasher = deployCode("ClprSha512Hasher.sol:ClprSha512Hasher");
    }

    function _sha512(bytes memory d) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = hasher.staticcall(d);
        require(ok && out.length == 64, "hasher");
    }

    function _input(uint256 n) internal pure returns (bytes memory d) {
        d = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            d[i] = bytes1(uint8(i % 251));
        }
    }

    function _v(uint256 n, bytes memory sha, bytes32 b3) internal view {
        bytes memory d = _input(n);
        require(keccak256(_sha512(d)) == keccak256(sha), string.concat("sha512 len ", vm.toString(n)));
        require(ClprBlake3.hash(d) == b3, string.concat("blake3 len ", vm.toString(n)));
    }

    function test_vectors() public view {
        _v(
            0,
            hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        );
        _v(
            1,
            hex"b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
            0x2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
        );
        _v(
            3,
            hex"8081da5f9c1e3d0e1aa16f604d5e5064543cff5d7bace2bb312252461e151b3fe0f034ea8dc1dacff3361a892d625fbe1b614cda265f87a473c24b0fa1d91dfd",
            0xe1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f
        );
        _v(
            63,
            hex"9dc9c5598e55dc42955695320839788e353f1d7f6ba74df74c80a8a52f463c0697f57f68835d1418f4ce9b6530cd79bd0f4c6f7e13c93feb1218c0b65c2c0561",
            0xe9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b
        );
        _v(
            64,
            hex"ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949",
            0x4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98
        );
        _v(
            65,
            hex"02856cef735f9acec6b9e33f0fbc8f9804d2aa54187f382b8ae842e5d3696c07459aad2a5aed25ea5e117eb1c7ba35da6a7a8adce9e6afe3ad79e9fa42d5bba8",
            0xde1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee
        );
        _v(
            111,
            hex"a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d",
            0x929dcdaf9b6a6e500a34978b5c9206d0258bc190f38c9e8e42fb19a4820b2171
        );
        _v(
            112,
            hex"c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9",
            0xc881a3c5ba84905a418f3da19726541b5bacd9e3438a741ffd980e00865fe13c
        );
        _v(
            113,
            hex"61b2e77db697dfe5571fff3ed06bd60c41e1e7b7c08a80de01cb16526d9a9a52d690dfbe792278a60f6e2b4c57a97c729773f26e258d2393890c985d645f6715",
            0xa2b62d6e7c7314e92e01de6c10643b7b0bfc2c780670d243e676763d7c41e390
        );
        _v(
            127,
            hex"eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0",
            0xd81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d
        );
        _v(
            128,
            hex"1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7",
            0xf17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef
        );
        _v(
            129,
            hex"1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f",
            0x683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12
        );
        _v(
            200,
            hex"986058e9895e2c2ab8f9e8cbdf801db12a44842a56a91d5a4e87b1fc98b293722c4664142e42c3c551ff898646268cd92b84ed230b8c94bed7798d4f27cd7465",
            0xf9c991a91ce818ab00f3bf22cef993a2f8d9ab0206f2b9efcef063bb19046966
        );
        _v(
            255,
            hex"e9746a5516961da1fdc8e6c59350cd147b7d80c120cc7ed621399faeb2462c28f34217a13009a8e6a721f538356db9a9b64d9a5412e0fd07d24cac1315d95548",
            0xcb97b80a66306dd2d4f1ab7ff9fd17d3d62d88c974e8daf0ea9fbd0b1ae1b1c1
        );
        _v(
            256,
            hex"7ff1cd1e9773a4b7ba1f40e642db0d879bd5f6cc151a7d3401a0bc7778b8270c108b530fb195f2383f4cec8cf05778e6af4db56811673371674cec1524488f83",
            0xf462b63aae56ed9fb899ad8eb93aa35d3dd62773fda9c33bfe20f9dab5d3df5f
        );
        _v(
            1023,
            hex"c260dc7074f5d12c5226aecfdb8e3f9b6457b14d980aa0d28b2082d78377ee8c33d65466d9f369cfb347e86d806ab5a9488dd93b63252341106f3604d8e96879",
            0x10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11
        );
        _v(
            1024,
            hex"9af3eed7e9dd11428bb922c6830c32065154532303781f8ea4f20792d616703884d564ebfd2bfa65faed8fc8fd91d9e1d3f12897fbb1e2247632db70ce30573e",
            0x42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7
        );
        _v(
            1025,
            hex"1f0cb287c12671e2f498170ff2762886686ceb88b7d63f944708d3060752376ff38e4a88ab7ceb0bb437083e7f1d051049b8d94356e72e4d59adcc102f585ac0",
            0xd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444
        );
        _v(
            2048,
            hex"586dec844d81eca239c38078af4e1531b7490aff64b7bc8939c7613b7332653eb142638f5e53c7fa755315bc25dbe97979deb832e586e9c7c5dd9cfb318b8940",
            0xe776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a
        );
        _v(
            2049,
            hex"c86261239b9dbf452f0b5ba56fd312c5f3eced55cfa7057e522a378fa5a707fbababd9c7c559160dd5b64a9826cf2db5e09a99fcdb8f411c8ae2f26f9bee8395",
            0x5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030
        );
        _v(
            3072,
            hex"1e287e9aac34fe5a7471d2c0de64d49e9587c8818825f411ad076a18fd898ca72940b9b5e906c0df2c2a003eedf31ade6355175aa98cbc678c1a9f33ba7a008a",
            0xb98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2
        );
        _v(
            3073,
            hex"22c0842940ca4deab80afea00b266e0954657e23dd7088701290c37cb52229487f51606d4c91f816a06ddd7e31e4e2d2c8f438313d9a1ca60f978881eaefceb6",
            0x7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3
        );
        _v(
            5000,
            hex"f7b8464be8c23f633cd761a6502801a7d77f59a9eb0523e50bec6b366687258a7c8e5f8b1578e56076b133a5ea1f0dd3cf439d97ebca4f335818be014a085c86",
            0xee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836
        );
    }

    function test_knownAnswers() public view {
        assertEq(
            _sha512("abc"),
            hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assertEq(ClprBlake3.hash(""), 0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262);
    }

    function test_gas_sha512() public {
        bytes memory d = _input(1000);
        uint256 g = gasleft();
        _sha512(d);
        uint256 g1 = g - gasleft();
        d = _input(2280);
        g = gasleft();
        _sha512(d);
        emit log_named_uint("sha512 per 128-byte block (marginal)", (g - gasleft() - g1) / 10);
        d = _input(516); // an XRPL inner node preimage: 4-byte prefix + 16 x 32
        g = gasleft();
        _sha512(d);
        emit log_named_uint("sha512 XRPL inner node (5 blocks, with call)", g - gasleft());
    }

    function test_gas_blake3() public {
        bytes memory d = _input(160); // a one-transaction Mixin snapshot payload
        uint256 g = gasleft();
        ClprBlake3.hash(d);
        emit log_named_uint("blake3 160 B gas", g - gasleft());
        d = _input(1500);
        g = gasleft();
        ClprBlake3.hash(d);
        emit log_named_uint("blake3 1500 B gas", g - gasleft());
    }
}
