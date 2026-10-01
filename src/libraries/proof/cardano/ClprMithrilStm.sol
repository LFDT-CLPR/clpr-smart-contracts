// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @title ClprMithrilStm
/// @notice On-chain verification of a Mithril stake-based threshold multi-signature (STM) in its
///         production "concatenation" proof system, bit-for-bit with mithril-stm 0.12.x
///         (`ConcatenationProof::verify`, IntersectMBO/mithril @ 321f8d8):
///
///   msgp      = signed_message ‖ avk.root                  (the 64 ASCII hex chars of the protocol
///                                                           message hash, then the 32-byte root)
///   per signature i (σ_i ∈ G1, vk_i ∈ G2, stake_i, lottery indexes J_i):
///     - (vk_i, stake_i) is a leaf of the registration Merkle tree `avk.root` — leaf
///       `Blake2b-256(compress(vk_i) ‖ stake_i BE8)`, checked with one batch path for all signatures
///       (heap layout, padding node `Blake2b-256(0x00)`), mithril `verify_leaves_membership_from_batch_path`
///     - every j ∈ J_i is ≤ m, unique across the certificate, and wins the lottery:
///       `ev = Blake2b-512("map" ‖ msgp ‖ j LE8 ‖ compress(σ_i))` read little-endian, and
///       `ev / 2^512 < 1 − (1 − φ_f)^(stake_i / total)`
///   Σ|J_i| ≥ k
///   BLS (min_sig): r_i = LE(Blake2b-128(compress(σ_1) ‖ … ‖ compress(σ_n) ‖ i BE8)) (r = 1 if n = 1),
///     e(Σ r_i·σ_i, g2) = e(H(msgp), Σ r_i·vk_i) with H = hash_to_curve G1, SHA-256 XMD, EMPTY DST.
///
/// @dev The lottery uses the exact constant `c = ln(1 − φ_f)` as the f64 the Rust implementation
///      computes (`Ratio::from_float((1.0 - phi_f).ln())`), stored in the trust anchor as
///      `lnMant · 2^-lnExpNeg`. `1 − e^{−x}` is evaluated with 120-bit fixed point and a proven error
///      bound; an index whose `ev` falls inside that ±2^-104 band reverts (`LotteryAmbiguous`) rather
///      than guessing — honest certificates hit it with probability ≈ 2^-100 per index.
/// @dev Each σ_i and vk_i comes twice: uncompressed (EIP-2537 layout, used by the MSM and pairing
///      precompiles, which validate curve and subgroup membership) and as the compressed bytes Mithril
///      hashes (lottery, aggregation scalars, registration leaf). σ_i's encoding must equal the existing
///      {ClprBls12381.compressG1} of its point byte for byte. vk_i's encoding is bound by x-coordinate and
///      the compression and infinity flags only (see the README, "Limits").
library ClprMithrilStm {
    struct Avk {
        bytes32 root;
        uint64 nrLeaves;
        uint64 totalStake;
    }

    struct Params {
        uint64 k;
        uint64 m;
        uint32 phiFixed; // U8F24 φ_f, as hashed in `next_protocol_parameters`
        uint64 lnMant; // |ln(1 − φ_f)| as an f64 = lnMant · 2^-lnExpNeg
        uint16 lnExpNeg;
    }

    // ── Signer entry layout (one `bytes` per signature, ascending leaf index) ──
    // sigma G1 (128) ‖ vk G2 (256) ‖ sigma compressed (48) ‖ vk compressed (96) ‖ stake u64 BE ‖
    // leafIndex u32 BE ‖ lottery indexes u32 BE …
    uint256 internal constant E_SIGMA = 0;
    uint256 internal constant E_VK = 128;
    uint256 internal constant E_SIGMA_C = 384;
    uint256 internal constant E_VK_C = 432;
    uint256 internal constant E_STAKE = 528;
    uint256 internal constant E_LEAF = 536;
    uint256 internal constant E_INDEXES = 540;

    uint256 internal constant ONE = 1 << 120; // fixed-point unit of the lottery
    uint256 internal constant LOTTERY_SLACK = 1 << 16; // error bound, in units of 2^-120
    uint32 internal constant PHI_ONE = 1 << 24;
    uint256 internal constant MAX_M = 1 << 20;

    address internal constant G1MSM = address(0x0c);
    address internal constant G2MSM = address(0x0e);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);
    address internal constant MODEXP = address(0x05);
    address internal constant SHA256 = address(0x02);

    // BLS12-381 base field modulus p (48 bytes) as (hi 16 bytes, lo 32 bytes).
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    error NoSignatures();
    error BadSignerEntry(uint256 i);
    error EncodingMismatch(uint256 i);
    error LeafIndexOrder(uint256 i);
    error BatchPathInvalid();
    error IndexAboveM(uint256 index);
    error DuplicateIndex(uint256 index);
    error LotteryLost(uint256 signer, uint256 index);
    error LotteryAmbiguous(uint256 signer, uint256 index);
    error NotEnoughIndices(uint256 got, uint256 k);
    error BadParams();
    error PrecompileFailed(address precompile);
    error AggregateSignatureInvalid();

    struct Work {
        bytes sigmasC; // n × 48 compressed σ
        bytes32[] leafHashes;
        uint256[] leafIdx;
        bytes g1; // n × (128 point ‖ 32 scalar)
        bytes g2; // n × (256 point ‖ 32 scalar)
    }

    /// @notice Verify an STM concatenation proof over `message` (the 64-byte ASCII signed message).
    /// @return nrIndices total lottery indexes proven (≥ k).
    function verify(
        bytes memory message,
        Avk memory avk,
        Params memory p,
        bytes[] memory signers,
        bytes memory batchValues
    ) internal view returns (uint256 nrIndices) {
        uint256 n = signers.length;
        if (n == 0) revert NoSignatures();
        if (p.k == 0 || p.m == 0 || p.k > p.m || p.m >= MAX_M || avk.totalStake == 0 || avk.nrLeaves == 0) {
            revert BadParams();
        }
        bytes memory msgp = bytes.concat(message, avk.root);

        Work memory w;
        w.sigmasC = new bytes(n * 48);
        w.leafHashes = new bytes32[](n);
        w.leafIdx = new uint256[](n);
        w.g1 = new bytes(n * 160);
        w.g2 = new bytes(n * 288);
        _parseSigners(signers, avk.nrLeaves, w);

        if (!_verifyBatchPath(avk.root, avk.nrLeaves, w.leafIdx, w.leafHashes, batchValues)) revert BatchPathInvalid();

        nrIndices = _checkLottery(msgp, avk.totalStake, p, signers, w.sigmasC);
        if (nrIndices < p.k) revert NotEnoughIndices(nrIndices, p.k);

        _writeScalars(w);
        bytes memory aggSig = _msm(G1MSM, w.g1, 128);
        bytes memory aggVk = _msm(G2MSM, w.g2, 256);
        bytes memory h = hashToG1(msgp);
        _pairingCheck(aggSig, h, aggVk);
    }

    // ── Signer parsing ───────────────────────────────────────────────────────

    function _parseSigners(bytes[] memory signers, uint64 nrLeaves, Work memory w) private view {
        uint256 prev;
        for (uint256 i = 0; i < signers.length; i++) {
            bytes memory e = signers[i];
            if (e.length < E_INDEXES + 4 || (e.length - E_INDEXES) % 4 != 0) revert BadSignerEntry(i);
            uint256 leaf = _beUint(e, E_LEAF, 4);
            if (leaf >= nrLeaves || (i > 0 && leaf <= prev)) revert LeafIndexOrder(i);
            prev = leaf;
            w.leafIdx[i] = leaf;

            if (!bindsG1(e, E_SIGMA, E_SIGMA_C) || !bindsG2(e, E_VK, E_VK_C)) revert EncodingMismatch(i);
            bytes memory sc = w.sigmasC;
            bytes memory g1 = w.g1;
            bytes memory g2 = w.g2;
            assembly ("memory-safe") {
                mcopy(add(add(sc, 0x20), mul(i, 48)), add(add(e, 0x20), E_SIGMA_C), 48)
                mcopy(add(add(g1, 0x20), mul(i, 160)), add(e, 0x20), 128)
                mcopy(add(add(g2, 0x20), mul(i, 288)), add(e, 0xa0), 256)
            }
            // leaf = Blake2b-256(vk compressed ‖ stake BE8)
            bytes memory leafBytes = new bytes(104);
            assembly ("memory-safe") {
                mcopy(add(leafBytes, 0x20), add(add(e, 0x20), E_VK_C), 96)
                mcopy(add(leafBytes, 0x80), add(add(e, 0x20), E_STAKE), 8)
            }
            w.leafHashes[i] = _b2b256(leafBytes);
        }
    }

    // ── Registration-tree batch path (mithril MerkleTreeBatchCommitment) ─────

    function _verifyBatchPath(
        bytes32 root,
        uint64 nrLeaves,
        uint256[] memory leafIdx,
        bytes32[] memory leafHashes,
        bytes memory values
    ) private view returns (bool) {
        if (values.length % 32 != 0) return false;
        uint256 pow2 = 1;
        while (pow2 < nrLeaves) pow2 <<= 1;
        uint256 nrNodes = pow2 + nrLeaves - 1;
        uint256 len = leafIdx.length;
        uint256[] memory idx = new uint256[](len);
        bytes32[] memory hs = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            idx[i] = pow2 + leafIdx[i] - 1;
            hs[i] = leafHashes[i];
        }
        bytes32 pad = _b2b256(hex"00");
        uint256 v; // next unused value
        uint256 nv = values.length / 32;
        uint256 top = idx[0];
        while (top > 0) {
            top = (top - 1) / 2;
            uint256 outLen;
            for (uint256 i = 0; i < len; i++) {
                uint256 node = idx[i];
                bytes32 h;
                if (node % 2 == 0) {
                    if (v >= nv) return false;
                    h = _node(_word(values, v++), hs[i]);
                } else {
                    uint256 sib = node + 1;
                    if (i + 1 < len && idx[i + 1] == sib) {
                        h = _node(hs[i], hs[i + 1]);
                        i++;
                    } else if (sib < nrNodes) {
                        if (v >= nv) return false;
                        h = _node(hs[i], _word(values, v++));
                    } else {
                        h = _node(hs[i], pad);
                    }
                }
                idx[outLen] = (node - 1) / 2;
                hs[outLen] = h;
                outLen++;
            }
            len = outLen;
        }
        return len == 1 && hs[0] == root && v == nv;
    }

    function _node(bytes32 a, bytes32 b) private view returns (bytes32) {
        return _b2b256(abi.encodePacked(a, b));
    }

    // ── Lottery ──────────────────────────────────────────────────────────────

    /// @dev Per index: `ev = Blake2b-512("map" ‖ msgp ‖ j LE8 ‖ σ48)` — always two BLAKE2F blocks for the
    ///      96-byte msgp (block 1: "map" ‖ msgp ‖ j ‖ σ[0..21), block 2: σ[21..48)), both prepared once
    ///      per signature so that only the index bytes change between calls.
    function _checkLottery(
        bytes memory msgp,
        uint64 totalStake,
        Params memory p,
        bytes[] memory signers,
        bytes memory sigmasC
    ) private view returns (uint256 count) {
        if (msgp.length != 96) revert BadParams();
        uint256[] memory used = new uint256[]((uint256(p.m) >> 8) + 1); // m + 1 bits
        bytes memory blk1 = new bytes(128);
        bytes memory blk2 = new bytes(128);
        bytes memory frame = new bytes(256);
        assembly ("memory-safe") {
            mstore8(add(blk1, 0x20), 0x6d) // 'm'
            mstore8(add(blk1, 0x21), 0x61) // 'a'
            mstore8(add(blk1, 0x22), 0x70) // 'p'
            mcopy(add(blk1, 0x23), add(msgp, 0x20), 96)
        }
        bool ok = true;
        for (uint256 i = 0; i < signers.length; i++) {
            bytes memory e = signers[i];
            uint256 t = lotteryThreshold(_beUint(e, E_STAKE, 8), totalStake, p);
            assembly ("memory-safe") {
                let sg := add(add(sigmasC, 0x20), mul(i, 48))
                mcopy(add(blk1, add(0x20, 107)), sg, 21)
                mcopy(add(blk2, 0x20), add(sg, 21), 27)
            }
            uint256 ni = (e.length - E_INDEXES) / 4;
            uint256 m = p.m;
            for (uint256 j = 0; j < ni; j++) {
                uint256 ix;
                uint256 evTop;
                bool dup;
                assembly ("memory-safe") {
                    ix := shr(224, mload(add(add(e, 0x20), add(E_INDEXES, shl(2, j)))))
                }
                if (ix > m) revert IndexAboveM(ix);
                assembly ("memory-safe") {
                    let slot := add(add(used, 0x20), shl(5, shr(8, ix)))
                    let bit := shl(and(ix, 0xff), 1)
                    let wv := mload(slot)
                    dup := and(wv, bit)
                    mstore(slot, or(wv, bit))
                }
                if (dup) revert DuplicateIndex(ix);
                if (t != type(uint256).max) {
                    assembly ("memory-safe") {
                        let f := add(frame, 0x20)
                        mstore(f, shl(224, 12))
                        mstore(add(f, 4), 0x48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5)
                        mstore(add(f, 36), 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b)
                        mcopy(add(f, 68), add(blk1, 0x20), 128)
                        // index as u64 little-endian at message offset 99 (ix < 2^20)
                        let le := or(or(shl(56, and(ix, 0xff)), shl(48, and(shr(8, ix), 0xff))), shl(40, shr(16, ix)))
                        let q := add(f, 167)
                        mstore(q, or(shl(192, le), and(mload(q), 0xffffffffffffffffffffffffffffffffffffffffffffffff)))
                        mstore(add(f, 196), shl(248, 128)) // t = 128, f = 0
                        if iszero(staticcall(gas(), 0x09, f, 213, add(f, 4), 64)) { ok := 0 }
                        mcopy(add(f, 68), add(blk2, 0x20), 128)
                        mstore(add(f, 196), shl(248, 155)) // t = 155
                        mstore8(add(f, 212), 1) // final
                        if iszero(staticcall(gas(), 0x09, f, 213, add(f, 4), 64)) { ok := 0 }
                        evTop := mload(add(f, 36))
                    }
                    evTop = _bswap(evTop) >> 136; // top 120 bits of the little-endian integer
                    if (evTop + 1 + LOTTERY_SLACK > t) {
                        if (evTop >= t + LOTTERY_SLACK) revert LotteryLost(i, ix);
                        revert LotteryAmbiguous(i, ix);
                    }
                }
                count++;
            }
        }
        if (!ok) revert PrecompileFailed(address(0x09));
    }

    /// @notice `(1 − e^{−x})·2^120` with `x = stake/total · |ln(1 − φ_f)|` (exact f64 constant), or
    ///         `type(uint256).max` when φ_f = 1 (every index wins). Absolute error < 2^16 units.
    function lotteryThreshold(uint256 stake, uint256 total, Params memory p) internal pure returns (uint256) {
        if (p.phiFixed == PHI_ONE) return type(uint256).max;
        if (p.lnExpNeg > 128 || p.lnMant >= (1 << 53)) revert BadParams();
        uint256 x = ((stake * p.lnMant) << 120) / (total << p.lnExpNeg);
        if (x > 5 * ONE) revert BadParams();
        uint256 term = ONE;
        uint256 pos = ONE;
        uint256 neg;
        for (uint256 n = 1; n < 200; n++) {
            term = (term * x) / (n * ONE);
            if (term == 0) break;
            if (n & 1 == 1) neg += term;
            else pos += term;
        }
        uint256 e = pos - neg; // e^{-x}·2^120 (> 0)
        return ONE - e;
    }

    // ── Aggregation scalars ──────────────────────────────────────────────────

    /// @dev r_i = LE(Blake2b-128(σ_1‖…‖σ_n ‖ i BE8)); written big-endian after each point. The hasher
    ///      state after the full blocks of the shared prefix is computed once.
    function _writeScalars(Work memory w) private view {
        uint256 n = w.leafIdx.length;
        bytes memory g1 = w.g1;
        bytes memory g2 = w.g2;
        if (n == 1) {
            assembly ("memory-safe") {
                mstore(add(g1, 0xa0), 1)
                mstore(add(g2, 0x120), 1)
            }
            return;
        }
        bytes memory s = w.sigmasC;
        uint256 l = s.length;
        uint256 blocks = (l + 8 + 127) / 128;
        uint256 pre = (l / 128 < blocks - 1) ? l / 128 : blocks - 1; // full non-final prefix blocks
        bytes memory frame = new bytes(256);
        bool ok = true;
        assembly ("memory-safe") {
            let f := add(frame, 0x20)
            mstore(f, shl(224, 12))
            mstore(add(f, 4), xor(0x08c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5, shl(248, 16)))
            mstore(add(f, 36), 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b)
            for { let b := 0 } lt(b, pre) { b := add(b, 1) } {
                mcopy(add(f, 68), add(add(s, 0x20), mul(b, 128)), 128)
                let t := mul(add(b, 1), 128)
                mstore(add(f, 196), shl(248, and(t, 0xff)))
                mstore8(add(f, 197), and(shr(8, t), 0xff))
                mstore8(add(f, 198), and(shr(16, t), 0xff))
                mstore(add(f, 199), 0)
                mstore8(add(f, 212), 0)
                if iszero(staticcall(gas(), 0x09, f, 213, add(f, 4), 64)) { ok := 0 }
            }
        }
        bytes32 h0;
        bytes32 h1;
        assembly ("memory-safe") {
            h0 := mload(add(frame, 0x24))
            h1 := mload(add(frame, 0x44))
        }
        uint256 tailLen = l - pre * 128;
        bytes memory tail = new bytes(tailLen + 8);
        assembly ("memory-safe") {
            mcopy(add(tail, 0x20), add(add(s, 0x20), mul(pre, 128)), tailLen)
        }
        for (uint256 i = 0; i < n; i++) {
            assembly ("memory-safe") {
                mstore(add(add(tail, 0x20), tailLen), shl(192, i)) // i as u64 BE (overwrites only 8 bytes of payload)
                let f := add(frame, 0x20)
                mstore(add(f, 4), h0)
                mstore(add(f, 36), h1)
                let len := add(tailLen, 8)
                let nb := div(add(len, 127), 128)
                for { let b := 0 } lt(b, nb) { b := add(b, 1) } {
                    let off := mul(b, 128)
                    let last := eq(b, sub(nb, 1))
                    let cnt := 128
                    if last { cnt := sub(len, off) }
                    mstore(add(f, 68), 0)
                    mstore(add(f, 100), 0)
                    mstore(add(f, 132), 0)
                    mstore(add(f, 164), 0)
                    mcopy(add(f, 68), add(add(tail, 0x20), off), cnt)
                    let t := add(mul(pre, 128), add(off, cnt))
                    mstore(add(f, 196), shl(248, and(t, 0xff)))
                    mstore8(add(f, 197), and(shr(8, t), 0xff))
                    mstore8(add(f, 198), and(shr(16, t), 0xff))
                    mstore(add(f, 199), 0)
                    mstore8(add(f, 212), last)
                    if iszero(staticcall(gas(), 0x09, f, 213, add(f, 4), 64)) { ok := 0 }
                }
            }
            bytes32 out;
            assembly ("memory-safe") {
                out := mload(add(frame, 0x24))
            }
            uint256 r = _bswap(uint256(out) & (type(uint256).max << 128)); // 16 LE bytes → integer
            assembly ("memory-safe") {
                mstore(add(add(g1, 0x20), add(mul(i, 160), 128)), r)
                mstore(add(add(g2, 0x20), add(mul(i, 288), 256)), r)
            }
        }
        if (!ok) revert PrecompileFailed(address(0x09));
    }

    // ── BLS12-381 helpers ────────────────────────────────────────────────────

    function _msm(address pre, bytes memory input, uint256 outLen) private view returns (bytes memory out) {
        out = new bytes(outLen);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), pre, add(input, 0x20), mload(input), add(out, 0x20), outLen)
        }
        if (!ok) revert PrecompileFailed(pre);
    }

    /// @dev e(−aggSig, g2) · e(H, aggVk) == 1.
    function _pairingCheck(bytes memory aggSig, bytes memory h, bytes memory aggVk) private view {
        bytes memory input = abi.encodePacked(_negG1(aggSig), _g2Generator(), h, aggVk);
        uint256[1] memory r;
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x0f, add(input, 0x20), mload(input), r, 0x20)
        }
        if (!ok) revert PrecompileFailed(PAIRING);
        if (r[0] != 1) revert AggregateSignatureInvalid();
    }

    function _negG1(bytes memory pt) private pure returns (bytes memory out) {
        out = new bytes(128);
        uint256 yHi;
        uint256 yLo;
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(pt, 0x20), 64)
            yHi := mload(add(pt, 0x60)) // pad16 ‖ y-top16
            yLo := mload(add(pt, 0x80))
        }
        if (yHi == 0 && yLo == 0) return out; // infinity (x = 0 too) or y = 0
        unchecked {
            uint256 borrow = yLo > P_LO ? 1 : 0;
            uint256 nLo = P_LO - yLo;
            uint256 nHi = P_HI - yHi - borrow;
            assembly ("memory-safe") {
                mstore(add(out, 0x60), nHi)
                mstore(add(out, 0x80), nLo)
            }
        }
    }

    function _g2Generator() private pure returns (bytes memory) {
        return abi.encodePacked(
            bytes16(0),
            hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            bytes16(0),
            hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            bytes16(0),
            hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            bytes16(0),
            hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    /// @notice RFC 9380 hash_to_curve for G1 (BLS12381G1_XMD:SHA-256_SSWU_RO_) with an empty DST —
    ///         blst `hash_to` as Mithril calls it (`verify(.., dst = &[], ..)`).
    function hashToG1(bytes memory msg_) internal view returns (bytes memory) {
        // expand_message_xmd(msg, DST = "", len = 128); DST_prime = I2OSP(0, 1)
        bytes32 b0 = _sha256(abi.encodePacked(bytes32(0), bytes32(0), msg_, uint16(128), uint8(0), uint8(0)));
        bytes32 b1 = _sha256(abi.encodePacked(b0, uint8(1), uint8(0)));
        bytes32 b2 = _sha256(abi.encodePacked(b0 ^ b1, uint8(2), uint8(0)));
        bytes32 b3 = _sha256(abi.encodePacked(b0 ^ b2, uint8(3), uint8(0)));
        bytes32 b4 = _sha256(abi.encodePacked(b0 ^ b3, uint8(4), uint8(0)));
        bytes memory q0 = _mapToG1(_modP(b1, b2));
        bytes memory q1 = _mapToG1(_modP(b3, b4));
        bytes memory sum = new bytes(128);
        bytes memory input = bytes.concat(q0, q1);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x0b, add(input, 0x20), 256, add(sum, 0x20), 128)
        }
        if (!ok) revert PrecompileFailed(address(0x0b));
        return sum;
    }

    function _sha256(bytes memory data) private view returns (bytes32 h) {
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x02, add(data, 0x20), mload(data), 0x00, 0x20)
            h := mload(0x00)
        }
        if (!ok) revert PrecompileFailed(SHA256);
    }

    /// @dev (a ‖ b) mod p as a 64-byte EIP-2537 field element.
    function _modP(bytes32 a, bytes32 b) private view returns (bytes memory out) {
        bytes memory input = abi.encodePacked(
            uint256(64), uint256(1), uint256(48), a, b, uint8(1), bytes16(uint128(P_HI)), bytes32(P_LO)
        );
        out = new bytes(64);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(out, 0x30), 48)
        }
        if (!ok) revert PrecompileFailed(MODEXP);
    }

    function _mapToG1(bytes memory fp) private view returns (bytes memory out) {
        out = new bytes(128);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x10, add(fp, 0x20), 64, add(out, 0x20), 128)
        }
        if (!ok) revert PrecompileFailed(MAP_FP_TO_G1);
    }

    /// @notice The 48-byte compressed G1 encoding at `buf[encOff..]` is exactly the encoding of the
    ///         EIP-2537 point at `buf[ptOff..ptOff+128]` (all three flag bits), recomputed with the
    ///         existing {ClprBls12381.compressG1}. The point at infinity is rejected.
    function bindsG1(bytes memory buf, uint256 ptOff, uint256 encOff) internal pure returns (bool) {
        bytes memory pt = new bytes(128);
        bytes32 encHi;
        bytes16 encLo;
        assembly ("memory-safe") {
            mcopy(add(pt, 0x20), add(add(buf, 0x20), ptOff), 128)
            let c := add(add(buf, 0x20), encOff)
            encHi := mload(c)
            encLo := mload(add(c, 0x20))
        }
        bytes memory enc = ClprBls12381.compressG1(pt);
        if (uint8(enc[0]) & 0x40 != 0) return false;
        bytes32 h;
        bytes16 l;
        assembly ("memory-safe") {
            h := mload(add(enc, 0x20))
            l := mload(add(enc, 0x40))
        }
        return h == encHi && l == encLo;
    }

    /// @notice The 96-byte compressed G2 encoding (`x.c1 ‖ x.c0`, flags on the first byte) at
    ///         `buf[encOff..]` names the EIP-2537 point (`x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`) at `buf[ptOff..]`.
    function bindsG2(bytes memory buf, uint256 ptOff, uint256 encOff) internal pure returns (bool) {
        uint256 x0Hi;
        uint256 x0Lo;
        uint256 x1Hi;
        uint256 x1Lo;
        uint256 e1Hi;
        uint256 e1Lo;
        uint256 e0Hi;
        uint256 e0Lo;
        bool zero = true;
        assembly ("memory-safe") {
            let q := add(add(buf, 0x20), ptOff)
            x0Hi := mload(q)
            x0Lo := mload(add(q, 0x20))
            x1Hi := mload(add(q, 0x40))
            x1Lo := mload(add(q, 0x60))
            for { let k := 0 } lt(k, 8) { k := add(k, 1) } { if mload(add(q, shl(5, k))) { zero := 0 } }
            let c := add(add(buf, 0x20), encOff)
            e1Hi := shr(128, mload(c))
            e1Lo := mload(add(c, 0x10))
            e0Hi := shr(128, mload(add(c, 0x30)))
            e0Lo := mload(add(c, 0x40))
        }
        uint256 flags = e1Hi >> 125;
        if (flags & 0x4 == 0 || flags & 0x2 != 0 || zero) return false;
        return (e1Hi & ((1 << 125) - 1)) == x1Hi && e1Lo == x1Lo && e0Hi == x0Hi && e0Lo == x0Lo;
    }

    // ── small utils ──────────────────────────────────────────────────────────

    function _beUint(bytes memory b, uint256 off, uint256 n) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(sub(256, shl(3, n)), mload(add(add(b, 0x20), off)))
        }
    }

    function _word(bytes memory b, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), shl(5, i)))
        }
    }

    function _bswap(uint256 x) internal pure returns (uint256) {
        x = ((x & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
            | ((x >> 8) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff);
        x = ((x & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16)
            | ((x >> 16) & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff);
        x = ((x & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
            | ((x >> 32) & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff);
        x = ((x & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64)
            | ((x >> 64) & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff);
        return (x << 128) | (x >> 128);
    }

    function _b2b256(bytes memory data) private view returns (bytes32 out) {
        (out,) = _b2b(data, 32);
    }

    /// @dev BLAKE2b via the precompile (same as {ClprBlake2.b2b}, without the output masking).
    function _b2b(bytes memory data, uint256 outLen) private view returns (bytes32 lo, bytes32 hi) {
        bool ok = true;
        assembly ("memory-safe") {
            let b := mload(0x40) // temporary frame past the free pointer (not allocated)
            mstore(b, shl(224, 12))
            mstore(add(b, 4), xor(0x08c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5, shl(248, outLen)))
            mstore(add(b, 36), 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b)
            let len := mload(data)
            let src := add(data, 0x20)
            let blocks := div(add(len, 127), 128)
            if iszero(blocks) { blocks := 1 }
            for { let i := 0 } lt(i, blocks) { i := add(i, 1) } {
                let off := mul(i, 128)
                let last := eq(i, sub(blocks, 1))
                let n := 128
                if last { n := sub(len, off) }
                mstore(add(b, 68), 0)
                mstore(add(b, 100), 0)
                mstore(add(b, 132), 0)
                mstore(add(b, 164), 0)
                mcopy(add(b, 68), add(src, off), n)
                let t := add(off, n)
                mstore(add(b, 196), shl(248, and(t, 0xff)))
                mstore8(add(b, 197), and(shr(8, t), 0xff))
                mstore8(add(b, 198), and(shr(16, t), 0xff))
                mstore8(add(b, 199), and(shr(24, t), 0xff))
                mstore(add(b, 200), 0)
                mstore8(add(b, 212), last)
                if iszero(staticcall(gas(), 0x09, b, 213, add(b, 4), 64)) { ok := 0 }
            }
            lo := mload(add(b, 4))
            hi := mload(add(b, 36))
        }
        if (!ok) revert PrecompileFailed(address(0x09));
    }
}
