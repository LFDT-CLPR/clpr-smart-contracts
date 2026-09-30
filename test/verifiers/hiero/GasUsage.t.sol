// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";
import {WRAPSVerifierHarness} from "@test/helpers/WrapsVerifierHarness.sol";
import {TSSVerifierHarness} from "@test/helpers/TSSVerifierHarness.sol";
import {PoseidonBN254Contract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonBN254Contract.sol";
import {PoseidonPermuteA} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteA.sol";
import {PoseidonPermuteB} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteB.sol";
import {HieroVerifier} from "@hiero-ledger/clpr/verifiers/hiero/HieroVerifier.sol";
import {WRAPSVerifierContract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/WRAPSVerifierContract.sol";

/// @notice Gas usage benchmark for Hiero verifier components.
contract HieroGasBenchmarkTest is Test {
    string internal constant STATE_PROOF_PATH = "test/verifiers/hiero/fixtures/stateProof.bin";
    string internal constant TRUST_ANCHOR_PATH = "test/verifiers/hiero/fixtures/trustAnchor.bin";

    uint256 internal constant BLOCK_SIG_LEN = 3432;
    uint256 internal constant HINTS_VK_LEN = 1096;
    uint256 internal constant AB_PROOF_LEN = 704;

    // n=8 hinTS fixture (from legacy TSSVerifier test)
    bytes internal constant HINTS_VK_N8 =
        hex"0800000000000000030000000000000000000000000000000000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e113e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828011885fd66d8396c1ebe911ed9b1166804d5a0ffb8583353c1097ac453c7eba603e065ae04f89664896def6866638bd6a4171f106af2f64c084fbb6dd326e18cdeea2fde03b9f5773d9f215880c90b18c1020ea583f1b5ed04dfccf34940be579d0bf42457442ab969994459c6c5e20c9a76960fa961140a7b29712fde5b4425293c36ad7d69b483fe48175e5893c40f00060cea91979255a9fcf2c16bc68536abfd431cf593f3301c8af6abcb2a6544ac7a63cb0836228dc28bce75b93a06146d0fffba9f4cc3d1ca8750a5f2eb32e18eae895f05e09a9c3d9c7c136ad693b4d704a5c601fb0b48a6d561d97d670ba09c1122a81531fd48b00afe81c8a9ae9ecb3097624ba54b5c12eb80cb91c04f199ab68fcbb9dc4078b8e59a51aeb43b458900be5cb7a4b590590b02c6dc1216ba086b6ef80e53db130e66b96c3fb165f3bb7b8cc0f3baf7de01b61c948e0c066cf901a69f59e78518f2d70889f659acfe4e01818d6ec481473ed5c48abd0d54c8fa058b8756c42c58c3fad13270441640d5181c8de9f934d35d9a4307f5b77951e77f95c07e137f1bd2c4efeff87415da9258439ce22223fc53fedf6bc97061aa2112fe43b933b634aee2eefee974cfac63ef55bf76cb6782cbd851d13dc36b9c638a06f07e298bafd58a2216440df956ee0662cc6a76d89b8076ed8d112444e98179e563e08f322e4da8db6023154e0cd28de33608bb0f3a021d7b57cce52d8def0f0b6d0cb8ddfc4c2c98dd558a03d5469a6db6c0a488976e25fd3052b80e86db18aa5707c90f1daec55c190422d2047013a66cbcae4c62517bf71e9509baf03fa212d78a50c80c6a57db75c072448bcad7cd8f9c7f9f043e95e39a8172c596b90d7c1125fe50cceac4af7956ac0c275603103de3498fb8e0804dd84116304c4ddb363ddc5d39f06ef10482a03dc3d0cb0decc8c8116a6800d42ab159eb927b3b958c16fef410048cafbd0d69abcfb6129d0c951ddea336c460b41be69c099ebb096387655db16c3ef59e955100be94d54388c7f19eddd2af243569c1cfc1c63eb6110ae27029f6110cfd5e03ec8deb2f";
    bytes internal constant HINTS_SIG_N8 =
        hex"10dcdac388faf68765aa81bb7b9f30e08ef11d68cc0c5eca1b915af65e359e29e47fe4fc7717ac6c01c24e85f7a7674908bc29d0be2d634157c57231b48a31784abac1ef6663e39b1d07194543cd3527f251a70131bf7e9b0e73888d41af0c760200000000000000000000000000000000000000000000000000000000000000145a3e910e45f738175b8fac3e2a6509a8deaeeba2521f8227f809e979b4028f4633615ddc90b7d57f867475355b35de047c6d5acb3b7266b955ed5d6d58144c73010e4fcac59af47c848986c71ef7be22f11afd64a9b68fd9b856b3d970bb49146d642291751e806a7c2cf2c755729707bfd2b9f48cdd503ee3c85f377741730d0f490d923434fda1b466969ed8bac910bc4556805b5bbf9c409b89cade3105ab4cbbe0949d49ed7fb735b6c4899a7f1b33be9a571dc7a1806d4a8c8860d8ff10d12d2d8e914b3d8984d1d914d5f12b426cd11b3f14055f92aa4de7d4e05087020500c9d8f53e6c48bb0d475ff4ec80170c11e8be0fb9f5a5fe2032ff11df68312aa87670f7a64aa6a3e0e8ef34a345b2e2eb948bf2ed5a15ad43c914177d5615515f89bd49422092b429a1f5bdd15696e247f1f710b89a29cfec682ba964e4c92001ffa72ccc528deed40c4f49f96f035dfbbe07cf85de45cff46edde04b8895c1afa573a2c6192cef482cfaefae1902729617caeb60aebb145793167a1927002f4069aed073e789f4de30901fae3d5274374a8dc8253c86eede0a5144bf5f1b01a5efbb230104952657505fb84ac1106f0328d94da4b04a953de6713a61ab3719ac25f7aa08db8b3e38fe6fb817f3515f724c0893799e9a581144e2b84184142c380079f72471d1b74cfe8eced4d47ab7f985fc3ad6efec4cfc4ecd819c97779782339092da83b39ee60f3f4209cc041c0e3c4f96e797522324469864ffcf9ba0668ef60aa31454932b52c2a44adb8ff47dbfcb905dfa48df5320f13e56be091d5429b3a121c1c9eb9c4c0f2e655afb59cd4b693a6ab08cbb07b71a75e795470378c142d0de9a888d230751db53081303d2db3520ee5857f9b74973a15b004deac5bfb13075889388565abf6f7fbc9e37a07a2515d9db93b930d8672199731118446693986340850efac25fc721388347d5bb120f32686a427f1a291a58e552f7f234c343f819f884638a535279590f2e9a42486548d5be06baf6116df2377082d9d56d0be91a1158c6a3c3504318771280ca2f0d182234f2107c95e679b413b6fbc459572227b7d4f3ca5b0c8eb2c123fb6a0c7c59e900a13f6977d69f88879215678e0f186754f0675f2751d03d0051f1c42903cb4d268b598337b5bd0d4bef635da3cb403763774da30f71b668f33f76c43b8801ad4f917a0e41ba20e117fa7eb853b757a8ba4f7df9b4e5d978e320385eafbfad389849c428999872797dd675ea8251994a0543a473a1a6722c0345ef2a62ac818e56f92af3f7379bde283b7a0b8bc8f5475aee3bb59854933e069d317beb809a85e37b4b00fa06c9571171518ff380e0d07d69f5dc8b351a6c57957544c56f4deb410a26f0d926fa9342ecd7997eae652fcb05033e89124a3f06f837ed6f0d102b43017db1b69b42a0b18bc30e39a8e193578b142fa1eb19bdfe3adfb33adc06dd27ed8e00e2fae913125985aa0c077419c7ee6312eea49f65c8e7d07348ef53a128f18b5f1e61b36448064403798cb4c30c54f99d198f5eb303a1641f8ce6c390e6c7b4ea5c0208b7e95419c90892aad4438f27f810753060f27dc1df7e7b3db3317e27a9b28e0c100785161635244d2e5fbe8741e3a9e58ab3a67b9d4dcea5a6d3655d3a112926e40817f8edbcd0ccb275f53a28bdc5874b0628c22c41f58974b998fe9dbb8d8c069d469fbcd517c1465b20e1609d41bbe6130482b1d0cb23300e04a4da69df5bcff6f277b33dcf6a6af1a2c769a1f1652f9ffef835e787f396f8fd0e452f457e5dc716a6edba107b92f6e6b724159f7cf7aa75e331d9f79a102fab1ab5b565e90ddc6eed355b06b2d1ec90f80778bf8d0131d5092802b073c199b8e6c7e126ef2239521b02325b9d83987044585caff6cc95d0e38a54373b013e05bcdd50ba6c0ab5406f86a98ce5adc02b1e10ea77e551b335ada259a5670e5f87c040e47b9a5a814f45be012e478f6d8575ff2e757313b7a48d9685fe866da30cb8409fdcc90f601c92eb7ac2ebf5cc0a3d18b88114a149d7388353a20e62e474dd5175eec77367c28aa69cb3fc2a6b9cc6ddbd991ed48a3a925d03710af29bdd12783250572c";
    bytes internal constant BLOCK_ROOT_N8 =
        hex"a7986473fa0a42a55a74f04eca352ec7cb6dc3715375500c141f01b1eae01c466f1fc88bd67bf84c84ab80c58fd1918e";

    WRAPSVerifierHarness internal wrapsHarness;
    TSSVerifierHarness internal hintsHarness;
    address internal poseidon;

    function setUp() public {
        wrapsHarness = WRAPSVerifierHarness(deployCode("WrapsVerifierHarness.sol:WRAPSVerifierHarness"));
        hintsHarness = TSSVerifierHarness(deployCode("TSSVerifierHarness.sol:TSSVerifierHarness"));
        // Deploy Poseidon contracts for WRAPSVerifier hashing
        address a = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address b = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        poseidon = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(a, b));
    }

    function test_hiero_verifier_gas_breakdown() public view {
        bytes memory rawProof = vm.readFileBinary(STATE_PROOF_PATH);
        bytes memory ledgerId = vm.readFileBinary(TRUST_ANCHOR_PATH);
        bytes memory hintsVk = _slice(rawProof, rawProof.length - BLOCK_SIG_LEN, HINTS_VK_LEN);
        bytes memory abProof = _slice(rawProof, rawProof.length - AB_PROOF_LEN, AB_PROOF_LEN);

        // ── Protobuf decode ──────────────────────────────────────────────────
        uint256 g0 = gasleft();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(rawProof);
        uint256 gasDecode = g0 - gasleft();

        // ── Merkle: one base-path blockRootHash (15 SHA-384 hashes) ─────────
        g0 = gasleft();
        uint256 baseIdx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        ClprMerkleProof.computeChainedRoot(sp.paths, baseIdx);
        uint256 gasMerkle1 = g0 - gasleft();

        // ── Merkle: second path (also 15 SHA-384 hashes) ────────────────────
        g0 = gasleft();
        for (uint256 i = 0; i < sp.paths.length; i++) {
            if (sp.paths[i].stateItemLeaf.length == 0 || baseIdx == i) continue;
            ClprMerkleProof.computeChainedRoot(sp.paths, i);
        }
        uint256 gasMerkle2 = g0 - gasleft();

        // ── hinTS BLS12-381 (n=8 fixture) ───────────────────────────────────
        g0 = gasleft();
        hintsHarness.verifyHintsAggregate(HINTS_VK_N8, HINTS_SIG_N8, BLOCK_ROOT_N8);
        uint256 gasHints = g0 - gasleft();

        // ── WRAPS Groth16 + KZG (n=4 fixture, real proof) ───────────────────
        g0 = gasleft();
        wrapsHarness.verify(abProof, hintsVk, ledgerId, poseidon);
        uint256 gasWraps = g0 - gasleft();

        uint256 gasTotal = gasDecode + gasMerkle1 + gasMerkle2 + gasHints + gasWraps;

        console.log("=== Hiero Gas Usage Breakdown ===");
        console.log("Protobuf decode  :", gasDecode);
        console.log("Merkle path 1    :", gasMerkle1);
        console.log("Merkle path 2    :", gasMerkle2);
        console.log("hinTS BLS12-381  :", gasHints);
        console.log("WRAPS Groth16+KZG:", gasWraps);
        console.log("TOTAL            :", gasTotal);
    }

    function test_gas_verifyBundle_success() public {
        bytes memory ledgerId = vm.readFileBinary(TRUST_ANCHOR_PATH);
        bytes memory proof = vm.readFileBinary("test/verifiers/hiero/fixtures/stateProof.bin");
        bytes memory trustAnchor = vm.readFileBinary("test/verifiers/hiero/fixtures/trustAnchor.bin");
        address permuteA = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address permuteB = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address poseidonLocal =
            deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(permuteA, permuteB));
        address wraps = deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(poseidonLocal));
        TSSVerifier tssVerifier = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(wraps)));
        HieroVerifier hieroVerifier =
            HieroVerifier(deployCode("HieroVerifier.sol:HieroVerifier", abi.encode(ledgerId, address(tssVerifier))));
        // channelContext = channelId(32) || remoteServiceAddress: the verifier binds the proven
        // ClprChannel leaf to this channel id.
        bytes memory channelContext = abi.encodePacked(
            bytes32(0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84),
            hex"ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d"
        );
        hieroVerifier.verifyBundle(proof, trustAnchor, channelContext);
    }

    function _slice(bytes memory data, uint256 offset, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            out[i] = data[offset + i];
        }
    }
}
