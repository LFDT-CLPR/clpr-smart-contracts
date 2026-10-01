// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title TezosSampler
/// @notice Reads the per-cycle delegate sampler that Tezos stores at
///         `cycle/<c>/delegate_sampler_state` and draws attestation-slot owners from it exactly as
///         octez `Delegate_sampler.Random.owner` does (src/proto_025_PsUshuai/lib_protocol).
///
/// Encoding (`Sampler.encoding Raw_context.consensus_pk_encoding`):
///   total:int64 ‖ support ‖ p ‖ alias, each array = length:int31 ‖ fallback ‖ u30(size) ‖ elements
///   support element = consensus_pk(tag ‖ key) ‖ opt(delegate pkh, 21) ‖ opt(companion BLS key, 48)
///   p element = int64, alias element = int31 (−1 encoded as 0xffffffff)
///
/// Slot draw for slot `s` of a level at position `pos` in its cycle:
///   state = BLAKE2b-256(seed ‖ int32 pos ‖ int32 s);  i = take(n);  e = take(total)
///   owner = e < p[i] ? i : alias[i]
/// where `take(bound)` reads successive big-endian int64 words of the state (rehashing it after
/// 32 bytes), maps min_int to 0, takes the absolute value and rejects values ≥ 2^63−1 − (2^63−1 mod bound).
library TezosSampler {
    uint256 internal constant PK_ED25519 = 0;
    uint256 internal constant PK_SECP256K1 = 1;
    uint256 internal constant PK_P256 = 2;
    uint256 internal constant PK_BLS = 3;

    error SamplerMalformed();

    struct Sampler {
        uint256 total; // mass bound
        uint256 n; // support size
        uint256[] entry; // memory address of each support element
        uint256 pAt; // memory address of p[0]
        uint256 aliasAt; // memory address of alias[0]
    }

    /// @dev Key length per consensus key tag (ed25519 32, secp256k1 33, p256 33, bls 48).
    function _pkLen(uint256 tag) private pure returns (uint256) {
        if (tag == PK_ED25519) return 32;
        if (tag == PK_SECP256K1 || tag == PK_P256) return 33;
        if (tag == PK_BLS) return 48;
        revert SamplerMalformed();
    }

    function _word(uint256 p) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(p)
        }
    }

    /// @notice Parse the encoded sampler (held in memory); option flags are 0x00 (none) and 0xff (some) into element addresses.
    function parse(bytes memory data) internal pure returns (Sampler memory s) {
        uint256 p;
        uint256 end;
        assembly ("memory-safe") {
            p := add(data, 0x20)
            end := add(p, mload(data))
        }
        if (data.length < 8) revert SamplerMalformed();
        s.total = _word(p) >> 192;
        if (s.total == 0 || s.total >= 1 << 63) revert SamplerMalformed();
        p += 8;
        // support
        uint256 n;
        (n, p) = _arrayHeader(p, end);
        p = _skipPk(p, end); // fallback
        uint256 listEnd;
        (listEnd, p) = _listBounds(p, end);
        s.n = n;
        s.entry = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            s.entry[i] = p;
            p = _skipPk(p, listEnd);
        }
        if (p != listEnd || n == 0) revert SamplerMalformed();
        // p array (int64)
        uint256 m;
        (m, p) = _arrayHeader(p, end);
        p += 8; // fallback
        (listEnd, p) = _listBounds(p, end);
        if (m != n || listEnd - p != 8 * n) revert SamplerMalformed();
        s.pAt = p;
        p = listEnd;
        // alias array (int31)
        (m, p) = _arrayHeader(p, end);
        p += 4; // fallback
        (listEnd, p) = _listBounds(p, end);
        if (m != n || listEnd - p != 4 * n || listEnd != end) revert SamplerMalformed();
        s.aliasAt = p;
    }

    function _arrayHeader(uint256 p, uint256 end) private pure returns (uint256 n, uint256 q) {
        if (p + 4 > end) revert SamplerMalformed();
        return (_word(p) >> 224, p + 4);
    }

    function _listBounds(uint256 p, uint256 end) private pure returns (uint256 listEnd, uint256 q) {
        if (p + 4 > end) revert SamplerMalformed();
        listEnd = p + 4 + (_word(p) >> 224);
        if (listEnd > end) revert SamplerMalformed();
        return (listEnd, p + 4);
    }

    function _skipPk(uint256 p, uint256 end) private pure returns (uint256) {
        if (p + 1 > end) revert SamplerMalformed();
        p += 1 + _pkLen(_word(p) >> 248);
        if (p + 1 > end) revert SamplerMalformed();
        if (_word(p) >> 248 == 0xff) p += 21;
        p += 1;
        if (p + 1 > end) revert SamplerMalformed();
        if (_word(p) >> 248 == 0xff) p += 48;
        p += 1;
        if (p > end) revert SamplerMalformed();
        return p;
    }

    /// @notice Consensus key of support element `i`: scheme tag and the address of the raw key.
    function key(Sampler memory s, uint256 i) internal pure returns (uint256 scheme, uint256 keyAt) {
        uint256 e = s.entry[i];
        return (_word(e) >> 248, e + 1);
    }

    /// @notice BLS companion key of support element `i` (address of the 48-byte key), 0 if none.
    function companion(Sampler memory s, uint256 i) internal pure returns (uint256 at) {
        uint256 e = s.entry[i];
        uint256 p = e + 1 + _pkLen(_word(e) >> 248);
        if (_word(p) >> 248 == 0xff) p += 21;
        p += 1;
        if (_word(p) >> 248 == 0xff) return p + 1;
        return 0;
    }

    /// @notice Count the slots in [0, committeeSize) owned by a support element flagged in `signer`
    ///         (one byte per support index, non-zero = signed), stopping once `threshold` is reached.
    ///         Returns the number of counted slots (≥ threshold, or the full count if it is not reached).
    function countSignedSlots(
        Sampler memory s,
        bytes32 seed,
        uint256 cyclePosition,
        uint256 committeeSize,
        uint256 threshold,
        bytes memory signer
    ) internal view returns (uint256 counted) {
        // Loop constants live in scratch memory (ctx = buf + 640) so the loop's stack stays shallow.
        uint256 dropN = _dropIfOver(s.n);
        uint256 dropT = _dropIfOver(s.total);
        uint256 n = s.n;
        uint256 total = s.total;
        uint256 pAt = s.pAt;
        uint256 aliasAt = s.aliasAt;
        assembly ("memory-safe") {
            // Scratch past the free pointer: [buf, +213) BLAKE2F input for one 40-byte block,
            // [+256, +320) its output (the draw state is the first 32 bytes), [+384, +597) rehash
            // input, [+640, +896) loop constants.
            let buf := mload(0x40)
            mstore(buf, shl(224, 12)) // rounds
            mstore(add(buf, 4), 0x28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5)
            mstore(add(buf, 36), 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b)
            mstore(add(buf, 68), seed) // m[0..32)
            mstore(add(buf, 100), shl(224, cyclePosition)) // m[32..36) int32 position, m[36..40) slot
            mstore(add(buf, 132), 0)
            mstore(add(buf, 164), 0)
            mstore(add(buf, 196), 0) // t = 40, f = 1
            mstore8(add(buf, 196), 40)
            mstore8(add(buf, 212), 1)
            mstore(add(buf, 640), n)
            mstore(add(buf, 672), total)
            mstore(add(buf, 704), dropN)
            mstore(add(buf, 736), dropT)
            mstore(add(buf, 768), pAt)
            mstore(add(buf, 800), aliasAt)
            mstore(add(buf, 832), add(signer, 0x20))
            mstore(add(buf, 864), threshold)

            for { let slot := 0 } lt(slot, committeeSize) { slot := add(slot, 1) } {
                mstore(add(buf, 104), shl(224, slot)) // bytes 40.. of the block stay zero
                if iszero(staticcall(gas(), 0x09, buf, 213, add(buf, 256), 64)) { revert(0, 0) }
                let i := mload(add(buf, 256))
                let e := and(shr(128, i), 0xffffffffffffffff)
                i := shr(192, i)
                if and(i, 0x8000000000000000) { i := and(sub(0x10000000000000000, i), 0x7fffffffffffffff) }
                if and(e, 0x8000000000000000) { e := and(sub(0x10000000000000000, e), 0x7fffffffffffffff) }
                switch and(lt(i, mload(add(buf, 704))), lt(e, mload(add(buf, 736))))
                case 1 {
                    // Fast path: the first two int64 words of the state are both accepted.
                    i := mod(i, mload(add(buf, 640)))
                    e := mod(e, mload(add(buf, 672)))
                }
                default {
                    // `take_int64` in full: successive words, rehashing the state after 32 bytes.
                    let off := 0
                    let k := 0
                    for {} lt(k, 2) {} {
                        if gt(off, 24) {
                            let rb := add(buf, 384)
                            mstore(rb, shl(224, 12))
                            mstore(add(rb, 4), 0x28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5)
                            mstore(add(rb, 36), 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b)
                            mstore(add(rb, 68), mload(add(buf, 256)))
                            mstore(add(rb, 100), 0)
                            mstore(add(rb, 132), 0)
                            mstore(add(rb, 164), 0)
                            mstore(add(rb, 196), 0)
                            mstore8(add(rb, 196), 32)
                            mstore8(add(rb, 212), 1)
                            if iszero(staticcall(gas(), 0x09, rb, 213, add(buf, 256), 64)) { revert(0, 0) }
                            off := 0
                        }
                        let r := shr(192, mload(add(add(buf, 256), off)))
                        if and(r, 0x8000000000000000) {
                            r := and(sub(0x10000000000000000, r), 0x7fffffffffffffff)
                        }
                        off := add(off, 8)
                        switch k
                        case 0 {
                            if lt(r, mload(add(buf, 704))) {
                                i := mod(r, mload(add(buf, 640)))
                                k := 1
                            }
                        }
                        default {
                            if lt(r, mload(add(buf, 736))) {
                                e := mod(r, mload(add(buf, 672)))
                                k := 2
                            }
                        }
                    }
                }
                // owner = e < p[i] ? i : alias[i]
                if iszero(lt(e, shr(192, mload(add(mload(add(buf, 768)), mul(i, 8)))))) {
                    i := shr(224, mload(add(mload(add(buf, 800)), mul(i, 4))))
                }
                if lt(i, mload(add(buf, 640))) {
                    if byte(0, mload(add(mload(add(buf, 832)), i))) {
                        counted := add(counted, 1)
                        if iszero(lt(counted, mload(add(buf, 864)))) { break }
                    }
                }
            }
        }
    }

    /// @dev 2^63−1 − ((2^63−1) mod bound): draws at or above it are rejected (octez `take_int64`).
    function _dropIfOver(uint256 bound) private pure returns (uint256) {
        uint256 maxInt = (1 << 63) - 1;
        return maxInt - (maxInt % bound);
    }
}
