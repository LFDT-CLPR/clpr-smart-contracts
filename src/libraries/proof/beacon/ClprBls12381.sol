// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBls12381
/// @notice Shared BLS12-381 constants (EIP-2537 precompile addresses, point lengths, the field modulus,
///         the negated generators), G1 and G2 *compression* (uncompressed → ZCash/Ethereum compressed),
///         RFC 9380 hash-to-field, hash-to-G1 and hash-to-G2, and EIP-2537 precompile wrappers.
///
/// @dev Source-chain data (e.g. the beacon `SyncCommittee` SSZ root) commits to compressed points,
///      while the relayer supplies uncompressed ones; compression binds the two. It is the cheap
///      direction (no field square root — just read the y sign bit). On-chain *decompression* is
///      gas-infeasible and deliberately avoided (see ClprBeaconBls / the ethereum README).
///
/// @dev A field element is carried as `(hi, lo)` = `hi·2^256 + lo` (`hi < 2^128`).
/// @dev Consensus-critical, hand-rolled crypto: validated against the BLS12-381 G1 generator vector.
library ClprBls12381 {
    // ── Precompiles: EIP-2537 BLS12-381, and EIP-198 MODEXP for field reductions ──
    address internal constant MODEXP = address(0x05);
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_G2MSM = address(0x0e);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP_TO_G1 = address(0x10);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);

    // ── Point lengths: EIP-2537 uncompressed, and ZCash compressed ──
    uint256 internal constant G1_POINT_LENGTH = 128;
    uint256 internal constant G2_POINT_LENGTH = 256;
    uint256 internal constant G1_COMPRESSED_LENGTH = 48;
    uint256 internal constant G2_COMPRESSED_LENGTH = 96;

    /// @dev Base-field modulus p, 48 bytes. MODEXP returns a result as long as its modulus, so this
    ///      encoding yields a raw 48-byte Fp element and `FIELD_MODULUS_FP` a 64-byte EIP-2537 one.
    ///      Constant: https://eips.ethereum.org/EIPS/eip-2537#curve-parameters (p)
    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// @dev Base-field modulus p in EIP-2537 Fp encoding (64 bytes, top 16 bytes zero).
    bytes internal constant FIELD_MODULUS_FP =
        hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev The negated G1, where G1 is the BLS12-381 generator defined by EIP-2537:
    ///      https://eips.ethereum.org/EIPS/eip-2537#curve-parameters (Generators -> H1)
    ///      Negation keeps x and replaces y with p - y.
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// @dev The negated G2, where G2 is the BLS12-381 generator defined by EIP-2537:
    ///      https://eips.ethereum.org/EIPS/eip-2537#curve-parameters (Generators -> H2)
    ///      Negation keeps x unchanged and replaces y with p - y in Fp2.
    bytes internal constant G2_GENERATOR_NEG =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    // (p-1)/2 — a y coordinate is "negative" (sign bit set) iff it is > (p-1)/2.
    uint256 internal constant P_HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 internal constant P_HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;

    // Compressed-point flag bits (most-significant byte).
    uint8 internal constant FLAG_COMPRESSED = 0x80;
    uint8 internal constant FLAG_INFINITY = 0x40;
    uint8 internal constant FLAG_SIGN = 0x20;

    /// @dev Two 64-byte field elements (RFC 9380, L = 64).
    uint256 internal constant HASH_TO_G1_EXPAND_LENGTH = 128;
    /// @dev Two Fp2 elements, four 64-byte field elements (RFC 9380, L = 64).
    uint256 internal constant HASH_TO_G2_EXPAND_LENGTH = 256;

    error BadLength();
    /// @notice A MODEXP or EIP-2537 precompile call failed or returned the wrong length.
    error BlsPrecompileCallFailed();

    /// @dev a > b, 384-bit unsigned.
    function _gt(uint256 aHi, uint256 aLo, uint256 bHi, uint256 bLo) internal pure returns (bool) {
        if (aHi != bHi) return aHi > bHi;
        return aLo > bLo;
    }

    /// @dev 48-byte big-endian encoding of `hi·2^256 + lo`.
    function _toBytes48(uint256 hi, uint256 lo) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(bytes16(uint128(hi)), bytes32(lo)); // hi < 2^128 by construction
    }

    /// @notice Compress a 128-byte EIP-2537 G1 point (`pad16||x(48)||pad16||y(48)`) into the 48-byte
    ///         ZCash/Ethereum compressed encoding.
    function compressG1(bytes memory uncompressed) internal pure returns (bytes memory) {
        if (uncompressed.length != G1_POINT_LENGTH) revert BadLength();
        uint256 xHi;
        uint256 xLo;
        uint256 yHi;
        uint256 yLo;
        assembly ("memory-safe") {
            xHi := mload(add(uncompressed, 0x20)) // bytes[0..32): pad16 || x-top16  → x-top16
            xLo := mload(add(uncompressed, 0x40)) // bytes[32..64): x-low32
            yHi := mload(add(uncompressed, 0x60)) // bytes[64..96): pad16 || y-top16 → y-top16
            yLo := mload(add(uncompressed, 0x80)) // bytes[96..128): y-low32
        }
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) {
            bytes memory inf = new bytes(G1_COMPRESSED_LENGTH);
            inf[0] = bytes1(FLAG_COMPRESSED | FLAG_INFINITY);
            return inf;
        }
        // sign bit: y is "negative" iff y > (p-1)/2.
        uint8 flags = FLAG_COMPRESSED | (_gt(yHi, yLo, P_HALF_HI, P_HALF_LO) ? FLAG_SIGN : 0);
        bytes memory out = _toBytes48(xHi, xLo);
        out[0] = bytes1(uint8(out[0]) | flags); // x < p ⇒ its top 3 bits are clear
        return out;
    }

    /// @notice Compress a 256-byte EIP-2537 G2 point into the 96-byte ZCash compressed encoding.
    /// @dev Output is x.c1 ‖ x.c0 with flag bits in byte 0. The sign flag follows y.c1, or y.c0
    ///      when y.c1 is zero.
    function compressG2(bytes memory uncompressed) internal pure returns (bytes memory out) {
        if (uncompressed.length != G2_POINT_LENGTH) revert BadLength();
        uint256 x0Hi;
        uint256 x0Lo;
        uint256 x1Hi;
        uint256 x1Lo;
        uint256 y0Hi;
        uint256 y0Lo;
        uint256 y1Hi;
        uint256 y1Lo;
        assembly ("memory-safe") {
            let p := add(uncompressed, 0x20)
            x0Hi := mload(p)
            x0Lo := mload(add(p, 0x20))
            x1Hi := mload(add(p, 0x40))
            x1Lo := mload(add(p, 0x60))
            y0Hi := mload(add(p, 0x80))
            y0Lo := mload(add(p, 0xa0))
            y1Hi := mload(add(p, 0xc0))
            y1Lo := mload(add(p, 0xe0))
        }
        if ((x0Hi | x0Lo | x1Hi | x1Lo | y0Hi | y0Lo | y1Hi | y1Lo) == 0) {
            out = new bytes(G2_COMPRESSED_LENGTH);
            out[0] = bytes1(FLAG_COMPRESSED | FLAG_INFINITY);
            return out;
        }
        bool negative;
        if (y1Hi != 0 || y1Lo != 0) {
            negative = _gt(y1Hi, y1Lo, P_HALF_HI, P_HALF_LO);
        } else {
            negative = _gt(y0Hi, y0Lo, P_HALF_HI, P_HALF_LO);
        }
        uint8 flags = FLAG_COMPRESSED | (negative ? FLAG_SIGN : 0);
        out = abi.encodePacked(_toBytes48(x1Hi, x1Lo), _toBytes48(x0Hi, x0Lo));
        out[0] = bytes1(uint8(out[0]) | flags); // the top 3 bits of x.c1 are zero
    }

    // ── RFC 9380 hashing ─────────────────────────────────────────────────────

    /// @notice Hash `message` to a G1 point (128 bytes) with SHA-256 `expand_message_xmd`.
    /// @param dst Domain separation tag, at most 255 bytes.
    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory expanded = expandMessageXmd(message, dst, HASH_TO_G1_EXPAND_LENGTH);
        bytes memory q0 = mapFpToG1(fpElementAt(expanded, 0));
        bytes memory q1 = mapFpToG1(fpElementAt(expanded, 64));
        return g1Add(q0, q1);
    }

    /// @notice Hash `message` to a G2 point (256 bytes) with SHA-256 `expand_message_xmd`.
    /// @dev `BLS12_MAP_FP2_TO_G2` clears the cofactor of each mapped point, so the sum needs no
    ///      further clearing.
    /// @param dst Domain separation tag, at most 255 bytes.
    function hashToG2(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory expanded = expandMessageXmd(message, dst, HASH_TO_G2_EXPAND_LENGTH);
        bytes memory q0 = mapFp2ToG2(bytes.concat(fpElementAt(expanded, 0), fpElementAt(expanded, 64)));
        bytes memory q1 = mapFp2ToG2(bytes.concat(fpElementAt(expanded, 128), fpElementAt(expanded, 192)));
        return g2Add(q0, q1);
    }

    /// @dev RFC 9380 `expand_message_xmd` over SHA-256: b_in_bytes = 32, s_in_bytes = 64.
    ///      `lenInBytes` is at most 8,160 (255 blocks), the RFC limit; larger values are not checked.
    function expandMessageXmd(bytes memory msgBytes, bytes memory dst, uint256 lenInBytes)
        internal
        pure
        returns (bytes memory uniform)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        uint256 ell = (lenInBytes + 31) / 32;
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), msgBytes, uint16(lenInBytes), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        // Whole 32-byte blocks are written, so the buffer holds `ell` blocks and is then cut to `lenInBytes`.
        uniform = new bytes(ell * 32);
        assembly ("memory-safe") {
            mstore(add(uniform, 0x20), bi)
        }
        for (uint256 i = 2; i <= ell; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bi = sha256(abi.encodePacked(bi ^ b0, uint8(i), dstPrime));
            assembly ("memory-safe") {
                mstore(add(uniform, mul(i, 0x20)), bi)
            }
        }
        assembly ("memory-safe") {
            mstore(uniform, lenInBytes)
        }
    }

    /// @dev The 64-byte chunk at `offset`, reduced mod p, as a 64-byte EIP-2537 field element.
    function fpElementAt(bytes memory expanded, uint256 offset) internal view returns (bytes memory) {
        bytes memory base = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(base, 0x20), add(add(expanded, 0x20), offset), 64)
        }
        // MODEXP returns a result as long as its modulus, so the 64-byte modulus gives the EIP-2537 layout.
        bytes memory input =
            abi.encodePacked(uint256(64), uint256(1), uint256(64), base, bytes1(0x01), FIELD_MODULUS_FP);
        (bool ok, bytes memory out) = MODEXP.staticcall(input);
        if (!ok || out.length != 64) revert BlsPrecompileCallFailed();
        return out;
    }

    // ── EIP-2537 precompile wrappers ─────────────────────────────────────────

    /// @dev Map a 64-byte field element to a G1 point.
    function mapFpToG1(bytes memory fp) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_MAP_FP_TO_G1.staticcall(fp);
        if (!ok || res.length != G1_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Map a 128-byte Fp2 element to a G2 point.
    function mapFp2ToG2(bytes memory fp2) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_MAP_FP2_TO_G2.staticcall(fp2);
        if (!ok || res.length != G2_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != G1_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_G2ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != G2_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Input is `(G1 point ‖ 32-byte scalar)+`.
    function g1Msm(bytes memory input) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_G1MSM.staticcall(input);
        if (!ok || res.length != G1_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Input is `(G2 point ‖ 32-byte scalar)+`.
    function g2Msm(bytes memory input) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_G2MSM.staticcall(input);
        if (!ok || res.length != G2_POINT_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev True iff the product of the pairings of the `(G1 point ‖ G2 point)+` input is one.
    function pairing(bytes memory input) internal view returns (bool) {
        (bool ok, bytes memory res) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!ok) revert BlsPrecompileCallFailed();
        // The length check makes the bytes32 read exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        return res.length == 32 && uint256(bytes32(res)) == 1;
    }
}
