// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";

contract HintsProfiler is TSSVerifier {
    constructor() TSSVerifier(address(0)) {}

    function baseline(bytes calldata vk, bytes calldata sig, bytes calldata m) external view returns (bool) {
        return _verifyHintsAggregate(vk, sig, m);
    }

    /// Replays _verifyHintsAggregate step by step; g[i] = gas of step i.
    function profile(bytes calldata vk, bytes calldata sig, bytes calldata m)
        external
        view
        returns (uint256[10] memory g)
    {
        uint256 t = gasleft();
        _checkThreshold(vk, sig);
        uint64 n = _readU64Le(vk, VK_OFFSET_N);
        g[0] = t - gasleft();

        t = gasleft();
        uint256 r = _computeFiatShamirChallenge(vk, sig);
        g[1] = t - gasleft();

        t = gasleft();
        uint256 omega = _nthRootOfUnity(uint256(n));
        g[2] = t - gasleft();

        t = gasleft();
        bytes memory g0 = _arkG1ToEip2537(vk, VK_OFFSET_G0);
        bytes memory h0 = _arkG2ToEip2537(vk, VK_OFFSET_H0);
        bytes memory h1 = _arkG2ToEip2537(vk, VK_OFFSET_H1);
        g[3] = t - gasleft();

        t = gasleft();
        _verifyBls12381SignaturePairing(m, sig, g0);
        g[4] = t - gasleft();

        t = gasleft();
        _verifyMergedKzgOpening(r, vk, sig, g0, h0, h1);
        g[5] = t - gasleft();

        t = gasleft();
        _verifyShiftedKzgOpening(r, omega, sig, g0, h0, h1);
        g[6] = t - gasleft();

        t = gasleft();
        _verifyBskIdentity(vk, sig, h0, h1);
        g[7] = t - gasleft();

        t = gasleft();
        _verifyFieldIdentities(r, omega, n, sig);
        g[8] = t - gasleft();

        t = gasleft();
        _verifyDegreeBound(sig, h0, h1);
        g[9] = t - gasleft();
    }

    /// Precompile-level costs, measured around each wrapper call.
    function micro(bytes calldata vk, bytes calldata sig, bytes calldata m)
        external
        view
        returns (uint256[12] memory g)
    {
        bytes memory g0 = _arkG1ToEip2537(vk, VK_OFFSET_G0);
        bytes memory h0 = _arkG2ToEip2537(vk, VK_OFFSET_H0);
        bytes memory h1 = _arkG2ToEip2537(vk, VK_OFFSET_H1);
        bytes memory qx = _arkG1ToEip2537(sig, SIG_OFFSET_QX);
        bytes memory qxt = _negG1Eip(_arkG1ToEip2537(sig, SIG_OFFSET_QX_MUL_TAU));
        uint256 t;

        t = gasleft();
        _hashToG2(m);
        g[0] = t - gasleft();

        t = gasleft();
        _pairing(bytes.concat(qx, h1, qxt, h0));
        g[1] = t - gasleft(); // 2-pair pairing

        bytes memory four = bytes.concat(qx, h1, qxt, h0, qx, h1, qxt, h0);
        t = gasleft();
        _pairing(four);
        g[2] = t - gasleft(); // 4-pair pairing

        bytes memory six = bytes.concat(four, qx, h1, qxt, h0);
        t = gasleft();
        _pairing(six);
        g[3] = t - gasleft(); // 6-pair pairing

        bytes memory msm1 = abi.encodePacked(g0, uint256(7));
        t = gasleft();
        _g1Msm(msm1);
        g[4] = t - gasleft(); // 1-term G1MSM

        bytes memory msm2 = abi.encodePacked(g0, uint256(7), qx, uint256(9));
        t = gasleft();
        _g1Msm(msm2);
        g[5] = t - gasleft(); // 2-term G1MSM

        bytes memory msm9 = new bytes(9 * 160);
        bytes memory msm10 = new bytes(10 * 160);
        for (uint256 i = 0; i < 10; i++) {
            if (i < 9) _writeMsmTerm(msm9, i * 160, g0, i + 3);
            _writeMsmTerm(msm10, i * 160, g0, i + 3);
        }
        t = gasleft();
        _g1Msm(msm9);
        g[6] = t - gasleft(); // 9-term G1MSM
        t = gasleft();
        _g1Msm(msm10);
        g[7] = t - gasleft(); // 10-term G1MSM

        bytes memory g2in = abi.encodePacked(h0, bytes32(uint256(5)), h1, bytes32(uint256(1)));
        t = gasleft();
        _g2Msm(g2in);
        g[8] = t - gasleft(); // 2-term G2MSM

        t = gasleft();
        _frInv(123456789);
        g[9] = t - gasleft(); // full-exponent modexp

        t = gasleft();
        _frPow(123456789, 7);
        g[10] = t - gasleft(); // small-exponent modexp

        t = gasleft();
        _computeFiatShamirChallenge(vk, sig);
        g[11] = t - gasleft();
    }

    // ---- Prototype: suggestions #1 (G2MSM → G1 term) + #3 (fewer inversions) + partial #2 (batch 7+9) ----

    uint256 internal constant INV_TWO = (BLS_FR_ORDER + 1) / 2;

    function optimized(bytes calldata vk, bytes calldata sig, bytes calldata m, uint8 flags)
        external
        view
        returns (bool)
    {
        _checkThreshold(vk, sig);
        uint64 n = _readU64Le(vk, VK_OFFSET_N);
        uint256 r = _computeFiatShamirChallenge(vk, sig);
        uint256 omega = _nthRootOfUnity(uint256(n));
        bytes memory g0 = _arkG1ToEip2537(vk, VK_OFFSET_G0);
        bytes memory h0 = _arkG2ToEip2537(vk, VK_OFFSET_H0);
        bytes memory h1 = _arkG2ToEip2537(vk, VK_OFFSET_H1);

        _verifyBls12381SignaturePairing(m, sig, g0);
        if (flags & 1 != 0) _optMergedKzg(r, vk, sig, g0, h0, h1);
        else _verifyMergedKzgOpening(r, vk, sig, g0, h0, h1);

        uint256 omegaPowNm1 = _frPow(omega, uint256(n) - 1);
        if (flags & 1 != 0) _optShiftedKzg(r, flags & 2 != 0 ? omegaPowNm1 : _frInv(omega), sig, g0, h0, h1);
        else _verifyShiftedKzgOpening(r, omega, sig, g0, h0, h1);

        if (flags & 4 != 0) {
            _optBatched7and9(r, vk, sig, h0, h1);
        } else {
            _verifyBskIdentity(vk, sig, h0, h1);
        }

        if (flags & 2 != 0) _optFieldIdentities(r, omegaPowNm1, n, sig);
        else _verifyFieldIdentities(r, omega, n, sig);

        if (flags & 4 == 0) _verifyDegreeBound(sig, h0, h1);
        return true;
    }

    /// e(merged + r·π, h0) · e(−π, h1) == 1   (≡ e(merged, h0) · e(−π, h1 − r·h0))
    function _optMergedKzg(
        uint256 r,
        bytes calldata vk,
        bytes calldata sig,
        bytes memory g0,
        bytes memory h0,
        bytes memory h1
    ) internal view {
        uint256[5] memory rPow;
        rPow[0] = mulmod(r, r, BLS_FR_ORDER);
        rPow[1] = mulmod(rPow[0], r, BLS_FR_ORDER);
        rPow[2] = mulmod(rPow[1], r, BLS_FR_ORDER);
        rPow[3] = mulmod(rPow[2], r, BLS_FR_ORDER);
        rPow[4] = mulmod(rPow[3], r, BLS_FR_ORDER);
        uint256 lnS = mulmod(r, _frNeg(_readFrLe(sig, SIG_OFFSET_AGG_WEIGHT)), BLS_FR_ORDER);
        uint256 negCe = _frNeg(_combinedEvalAtR(r, rPow, sig));
        bytes memory pi = _arkG1ToEip2537(sig, SIG_OFFSET_OPENING_R);

        bytes memory input = new bytes(10 * 160);
        _writeMsmTerm(input, 0, _arkG1ToEip2537(sig, SIG_OFFSET_PARSUM), 1);
        _writeMsmTerm(input, 160, _arkG1ToEip2537(vk, VK_OFFSET_W), r);
        _writeMsmTerm(input, 320, _arkG1ToEip2537(vk, VK_OFFSET_LN_MINUS_1), lnS);
        _writeMsmTerm(input, 480, _arkG1ToEip2537(sig, SIG_OFFSET_B), rPow[0]);
        _writeMsmTerm(input, 640, _arkG1ToEip2537(sig, SIG_OFFSET_Q1), rPow[1]);
        _writeMsmTerm(input, 800, _arkG1ToEip2537(sig, SIG_OFFSET_Q3), rPow[2]);
        _writeMsmTerm(input, 960, _arkG1ToEip2537(sig, SIG_OFFSET_Q2), rPow[3]);
        _writeMsmTerm(input, 1120, _arkG1ToEip2537(sig, SIG_OFFSET_Q4), rPow[4]);
        _writeMsmTerm(input, 1280, g0, negCe);
        _writeMsmTerm(input, 1440, pi, r);

        if (!_pairing(bytes.concat(_g1Msm(input), h0, _negG1Eip(pi), h1))) revert HieroHintsKzgMergedFailed();
    }

    /// e(parsum − v·g0 + z·π', h0) · e(−π', h1) == 1, z = r/ω.
    function _optShiftedKzg(
        uint256 r,
        uint256 omegaInv,
        bytes calldata sig,
        bytes memory g0,
        bytes memory h0,
        bytes memory h1
    ) internal view {
        uint256 z = mulmod(r, omegaInv, BLS_FR_ORDER);
        uint256 v = _readFrLe(sig, SIG_OFFSET_PARSUM_OF_R_DIV_OMG);
        bytes memory pi = _arkG1ToEip2537(sig, SIG_OFFSET_OPENING_R_DIV_OMEGA);
        bytes memory lhs = _g1Msm(
            abi.encodePacked(
                _arkG1ToEip2537(sig, SIG_OFFSET_PARSUM), bytes32(uint256(1)), g0, bytes32(_frNeg(v)), pi, bytes32(z)
            )
        );
        if (!_pairing(bytes.concat(lhs, h0, _negG1Eip(pi), h1))) revert HieroHintsKzgShiftedFailed();
    }

    /// Step 7 · (step 9)^γ in one 4-pair pairing:
    /// e(B,SK) · e(−QZ,Z) · e((γ−1)·QX, h1) · e(−aggPk − γ·QXτ, h0) == 1.
    /// γ here is a stand-in derived from r only; a real implementation must bind it to the full transcript.
    function _optBatched7and9(uint256 r, bytes calldata vk, bytes calldata sig, bytes memory h0, bytes memory h1)
        internal
        view
    {
        uint256 gamma = uint256(keccak256(abi.encodePacked(r, sig))) % BLS_FR_ORDER;
        bytes memory qxTerm = _g1Msm(
            abi.encodePacked(_arkG1ToEip2537(sig, SIG_OFFSET_QX), addmod(gamma, BLS_FR_ORDER - 1, BLS_FR_ORDER))
        );
        bytes memory h0Term = _g1Msm(
            abi.encodePacked(
                _arkG1ToEip2537(sig, SIG_OFFSET_AGG_PK),
                BLS_FR_ORDER - 1,
                _arkG1ToEip2537(sig, SIG_OFFSET_QX_MUL_TAU),
                _frNeg(gamma)
            )
        );
        if (!_pairing(
                bytes.concat(
                    _arkG1ToEip2537(sig, SIG_OFFSET_B),
                    _arkG2ToEip2537(vk, VK_OFFSET_SK),
                    _negG1Eip(_arkG1ToEip2537(sig, SIG_OFFSET_QZ)),
                    _arkG2ToEip2537(vk, VK_OFFSET_Z),
                    qxTerm,
                    h1,
                    h0Term,
                    h0
                )
            )) revert HieroHintsBSkIdentityFailed();
    }

    /// Same identities; n⁻¹ = (1/2)^k via mulmod, ω^{n−1} passed in.
    function _optFieldIdentities(uint256 r, uint256 omegaPowNm1, uint64 n, bytes calldata sig) internal view {
        uint256 vanishingOfR = addmod(_frPow(r, uint256(n)), BLS_FR_ORDER - 1, BLS_FR_ORDER);
        uint256 nInv = 1;
        for (uint64 t = n; t > 1; t >>= 1) {
            nInv = mulmod(nInv, INV_TWO, BLS_FR_ORDER);
        }
        uint256 lnMinus1OfR = mulmod(
            mulmod(omegaPowNm1, nInv, BLS_FR_ORDER),
            mulmod(vanishingOfR, _frInv(addmod(r, _frNeg(omegaPowNm1), BLS_FR_ORDER)), BLS_FR_ORDER),
            BLS_FR_ORDER
        );
        _checkParsumRecurrence(sig, vanishingOfR);
        _checkParsumEndpoint(sig, vanishingOfR, lnMinus1OfR);
        _checkBitmapBinary(sig, vanishingOfR);
        _checkBitmapEndpoint(sig, vanishingOfR, lnMinus1OfR);
    }
}

contract HintsGasProfileTest is Test {
    bytes internal constant HINTS_VK_N8 =
        hex"0800000000000000030000000000000000000000000000000000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e113e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828011885fd66d8396c1ebe911ed9b1166804d5a0ffb8583353c1097ac453c7eba603e065ae04f89664896def6866638bd6a4171f106af2f64c084fbb6dd326e18cdeea2fde03b9f5773d9f215880c90b18c1020ea583f1b5ed04dfccf34940be579d0bf42457442ab969994459c6c5e20c9a76960fa961140a7b29712fde5b4425293c36ad7d69b483fe48175e5893c40f00060cea91979255a9fcf2c16bc68536abfd431cf593f3301c8af6abcb2a6544ac7a63cb0836228dc28bce75b93a06146d0fffba9f4cc3d1ca8750a5f2eb32e18eae895f05e09a9c3d9c7c136ad693b4d704a5c601fb0b48a6d561d97d670ba09c1122a81531fd48b00afe81c8a9ae9ecb3097624ba54b5c12eb80cb91c04f199ab68fcbb9dc4078b8e59a51aeb43b458900be5cb7a4b590590b02c6dc1216ba086b6ef80e53db130e66b96c3fb165f3bb7b8cc0f3baf7de01b61c948e0c066cf901a69f59e78518f2d70889f659acfe4e01818d6ec481473ed5c48abd0d54c8fa058b8756c42c58c3fad13270441640d5181c8de9f934d35d9a4307f5b77951e77f95c07e137f1bd2c4efeff87415da9258439ce22223fc53fedf6bc97061aa2112fe43b933b634aee2eefee974cfac63ef55bf76cb6782cbd851d13dc36b9c638a06f07e298bafd58a2216440df956ee0662cc6a76d89b8076ed8d112444e98179e563e08f322e4da8db6023154e0cd28de33608bb0f3a021d7b57cce52d8def0f0b6d0cb8ddfc4c2c98dd558a03d5469a6db6c0a488976e25fd3052b80e86db18aa5707c90f1daec55c190422d2047013a66cbcae4c62517bf71e9509baf03fa212d78a50c80c6a57db75c072448bcad7cd8f9c7f9f043e95e39a8172c596b90d7c1125fe50cceac4af7956ac0c275603103de3498fb8e0804dd84116304c4ddb363ddc5d39f06ef10482a03dc3d0cb0decc8c8116a6800d42ab159eb927b3b958c16fef410048cafbd0d69abcfb6129d0c951ddea336c460b41be69c099ebb096387655db16c3ef59e955100be94d54388c7f19eddd2af243569c1cfc1c63eb6110ae27029f6110cfd5e03ec8deb2f";
    bytes internal constant HINTS_SIG_N8 =
        hex"10dcdac388faf68765aa81bb7b9f30e08ef11d68cc0c5eca1b915af65e359e29e47fe4fc7717ac6c01c24e85f7a7674908bc29d0be2d634157c57231b48a31784abac1ef6663e39b1d07194543cd3527f251a70131bf7e9b0e73888d41af0c760200000000000000000000000000000000000000000000000000000000000000145a3e910e45f738175b8fac3e2a6509a8deaeeba2521f8227f809e979b4028f4633615ddc90b7d57f867475355b35de047c6d5acb3b7266b955ed5d6d58144c73010e4fcac59af47c848986c71ef7be22f11afd64a9b68fd9b856b3d970bb49146d642291751e806a7c2cf2c755729707bfd2b9f48cdd503ee3c85f377741730d0f490d923434fda1b466969ed8bac910bc4556805b5bbf9c409b89cade3105ab4cbbe0949d49ed7fb735b6c4899a7f1b33be9a571dc7a1806d4a8c8860d8ff10d12d2d8e914b3d8984d1d914d5f12b426cd11b3f14055f92aa4de7d4e05087020500c9d8f53e6c48bb0d475ff4ec80170c11e8be0fb9f5a5fe2032ff11df68312aa87670f7a64aa6a3e0e8ef34a345b2e2eb948bf2ed5a15ad43c914177d5615515f89bd49422092b429a1f5bdd15696e247f1f710b89a29cfec682ba964e4c92001ffa72ccc528deed40c4f49f96f035dfbbe07cf85de45cff46edde04b8895c1afa573a2c6192cef482cfaefae1902729617caeb60aebb145793167a1927002f4069aed073e789f4de30901fae3d5274374a8dc8253c86eede0a5144bf5f1b01a5efbb230104952657505fb84ac1106f0328d94da4b04a953de6713a61ab3719ac25f7aa08db8b3e38fe6fb817f3515f724c0893799e9a581144e2b84184142c380079f72471d1b74cfe8eced4d47ab7f985fc3ad6efec4cfc4ecd819c97779782339092da83b39ee60f3f4209cc041c0e3c4f96e797522324469864ffcf9ba0668ef60aa31454932b52c2a44adb8ff47dbfcb905dfa48df5320f13e56be091d5429b3a121c1c9eb9c4c0f2e655afb59cd4b693a6ab08cbb07b71a75e795470378c142d0de9a888d230751db53081303d2db3520ee5857f9b74973a15b004deac5bfb13075889388565abf6f7fbc9e37a07a2515d9db93b930d8672199731118446693986340850efac25fc721388347d5bb120f32686a427f1a291a58e552f7f234c343f819f884638a535279590f2e9a42486548d5be06baf6116df2377082d9d56d0be91a1158c6a3c3504318771280ca2f0d182234f2107c95e679b413b6fbc459572227b7d4f3ca5b0c8eb2c123fb6a0c7c59e900a13f6977d69f88879215678e0f186754f0675f2751d03d0051f1c42903cb4d268b598337b5bd0d4bef635da3cb403763774da30f71b668f33f76c43b8801ad4f917a0e41ba20e117fa7eb853b757a8ba4f7df9b4e5d978e320385eafbfad389849c428999872797dd675ea8251994a0543a473a1a6722c0345ef2a62ac818e56f92af3f7379bde283b7a0b8bc8f5475aee3bb59854933e069d317beb809a85e37b4b00fa06c9571171518ff380e0d07d69f5dc8b351a6c57957544c56f4deb410a26f0d926fa9342ecd7997eae652fcb05033e89124a3f06f837ed6f0d102b43017db1b69b42a0b18bc30e39a8e193578b142fa1eb19bdfe3adfb33adc06dd27ed8e00e2fae913125985aa0c077419c7ee6312eea49f65c8e7d07348ef53a128f18b5f1e61b36448064403798cb4c30c54f99d198f5eb303a1641f8ce6c390e6c7b4ea5c0208b7e95419c90892aad4438f27f810753060f27dc1df7e7b3db3317e27a9b28e0c100785161635244d2e5fbe8741e3a9e58ab3a67b9d4dcea5a6d3655d3a112926e40817f8edbcd0ccb275f53a28bdc5874b0628c22c41f58974b998fe9dbb8d8c069d469fbcd517c1465b20e1609d41bbe6130482b1d0cb23300e04a4da69df5bcff6f277b33dcf6a6af1a2c769a1f1652f9ffef835e787f396f8fd0e452f457e5dc716a6edba107b92f6e6b724159f7cf7aa75e331d9f79a102fab1ab5b565e90ddc6eed355b06b2d1ec90f80778bf8d0131d5092802b073c199b8e6c7e126ef2239521b02325b9d83987044585caff6cc95d0e38a54373b013e05bcdd50ba6c0ab5406f86a98ce5adc02b1e10ea77e551b335ada259a5670e5f87c040e47b9a5a814f45be012e478f6d8575ff2e757313b7a48d9685fe866da30cb8409fdcc90f601c92eb7ac2ebf5cc0a3d18b88114a149d7388353a20e62e474dd5175eec77367c28aa69cb3fc2a6b9cc6ddbd991ed48a3a925d03710af29bdd12783250572c";
    bytes internal constant BLOCK_ROOT_N8 =
        hex"a7986473fa0a42a55a74f04eca352ec7cb6dc3715375500c141f01b1eae01c466f1fc88bd67bf84c84ab80c58fd1918e";
    HintsProfiler internal p;
    bytes internal vk;
    bytes internal sig;
    bytes internal m;

    function setUp() public {
        p = new HintsProfiler();
        (vk, sig, m) = (HINTS_VK_N8, HINTS_SIG_N8, BLOCK_ROOT_N8);
    }

    function test_profile() public view {
        uint256 t = gasleft();
        p.baseline(vk, sig, m);
        uint256 total = t - gasleft();
        uint256[10] memory g = p.profile(vk, sig, m);
        string[10] memory names = [
            "0  threshold + read n",
            "3  Fiat-Shamir r",
            "3  n-th root of unity",
            "   SRS g0/h0/h1 convert",
            "4  BLS sig pairing (+H2G2)",
            "5  merged KZG @ r",
            "6  shifted KZG @ r/w",
            "7  B*SK identity",
            "8  field identities",
            "9  degree bound"
        ];
        uint256 sum;
        for (uint256 i = 0; i < 10; i++) {
            console.log(names[i], g[i]);
            sum += g[i];
        }
        console.log("sum of steps", sum);
        console.log("external call total (baseline)", total);
    }

    function test_micro() public view {
        uint256[12] memory g = p.micro(vk, sig, m);
        string[12] memory names = [
            "hashToG2",
            "pairing 2",
            "pairing 4",
            "pairing 6",
            "G1MSM 1",
            "G1MSM 2",
            "G1MSM 9",
            "G1MSM 10",
            "G2MSM 2",
            "frInv (full exp)",
            "frPow (exp 7)",
            "Fiat-Shamir"
        ];
        for (uint256 i = 0; i < 12; i++) {
            console.log(names[i], g[i]);
        }
    }

    function test_optimized() public view {
        uint256 t = gasleft();
        p.baseline(vk, sig, m);
        uint256 base = t - gasleft();
        console.log("baseline (cold fixture SLOADs)", base);
        t = gasleft();
        p.baseline(vk, sig, m);
        console.log("baseline (warm)", t - gasleft());
        uint8[5] memory fl = [uint8(0), 1, 2, 3, 7];
        string[5] memory names = ["replay (flags=0)", "#1 G2MSM->G1", "#3 inversions", "#1+#3", "#1+#3+#2(7+9)"];
        for (uint256 i = 0; i < 5; i++) {
            t = gasleft();
            assertTrue(p.optimized(vk, sig, m, fl[i]));
            uint256 used = t - gasleft();
            console.log(names[i], used);
        }
    }

    function test_optimized_rejectsTampered() public {
        bytes memory bad = sig;
        // Swap opening_R and opening_R_div_omega: valid curve points, wrong proofs.
        for (uint256 i = 0; i < 96; i++) {
            (bad[1184 + i], bad[1280 + i]) = (bad[1280 + i], bad[1184 + i]);
        }
        vm.expectRevert();
        p.optimized(vk, bad, m, 7);
        bytes memory bad2 = sig;
        // Swap QX and QX_MUL_TAU: hits steps 7/9.
        for (uint256 i = 0; i < 96; i++) {
            (bad2[416 + i], bad2[512 + i]) = (bad2[512 + i], bad2[416 + i]);
        }
        vm.expectRevert();
        p.optimized(vk, bad2, m, 7);
    }
}
