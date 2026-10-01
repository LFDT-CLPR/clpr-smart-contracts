// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprAvalancheWarp
/// @notice Avalanche Warp Messaging (ACP-30 / ACP-118) primitives for an on-chain light verifier:
///         the serialized `UnsignedMessage` for a block-hash payload, the canonical validator set, and
///         the bit-set signer aggregation with the stake-weighted quorum check.
///
/// Everything here mirrors avalanchego (checked against `ava-labs/avalanchego` master of 2026-10-01,
/// commit 3b99241, and the v1.15.0 nodes serving Fuji):
///
/// - `vms/platformvm/warp/unsigned_message.go` + `codec.go`: `UnsignedMessage{NetworkID uint32,
///   SourceChainID [32]byte, Payload []byte}` serialized by the linear codec, version 0:
///   `u16(0) ‖ u32(networkID) ‖ sourceChainID ‖ u32(len(payload)) ‖ payload`.
/// - `vms/platformvm/warp/payload/{codec,hash}.go`: the block-hash payload is `payload.Hash`, type id 0
///   in the payload codec: `u16(0) ‖ u32(0) ‖ hash32` (38 bytes). Coreth/subnet-evm sign it only for an
///   ACCEPTED block whose id is the EVM block hash (`graft/coreth/warp/verifier_backend.go`,
///   `plugin/evm/vm.go#GetAcceptedBlock`). Snowman acceptance is final, so the signature attests finality.
/// - `snow/validators/warp.go#FlattenValidatorSet`: the canonical set holds only validators with a BLS
///   key, merges validators sharing a key (weights summed), and sorts by the 96-byte UNCOMPRESSED key
///   (`x ‖ y`). `TotalWeight` also counts validators without a key.
/// - `vms/platformvm/warp/signature.go#BitSetSignature.Verify`: `Signers` is a big-endian big.Int whose
///   bit i selects canonical validator i; the encoding must be minimal (no leading zero byte) and must
///   not name an index ≥ n; quorum is `quorumNum·totalWeight ≤ quorumDen·signedWeight`.
/// - `utils/crypto/bls`: signatures use `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` over the raw
///   UnsignedMessage bytes (public keys in G1, signatures in G2), as in {ClprBeaconBls}.
///
/// Validator-set wire format (`packed set`): `n × (x48 ‖ y48 ‖ weight8)` = 104 bytes per validator,
/// big-endian, in canonical order. `x ‖ y` is exactly avalanchego's uncompressed key bytes, so the
/// canonical order is plain lexicographic order of the entries' first 96 bytes. The 16-byte EIP-2537
/// limb padding is re-inserted in memory, keeping 24 bytes per key off the calldata.
library ClprAvalancheWarp {
    uint256 internal constant ENTRY_LENGTH = 104;
    uint256 internal constant KEY_LENGTH = 96;
    /// @dev avalanchego `WarpDefaultQuorumNumerator` / `WarpQuorumDenominator` (coreth precompile config).
    uint256 internal constant QUORUM_NUMERATOR = 67;
    uint256 internal constant QUORUM_DENOMINATOR = 100;
    /// @dev `payload.Hash` serialized length: codec version (2) + type id (4) + hash (32).
    uint32 internal constant HASH_PAYLOAD_LENGTH = 38;
    /// @dev Upper bound on the canonical set size. Avalanche mainnet has ~590 keys, Fuji ~71; 4096
    ///      entries would already be 416 KB, far beyond Hedera's 128 KB calldata limit.
    uint256 internal constant MAX_VALIDATORS = 4096;

    error InvalidValidatorSetLength(uint256 length);
    error ValidatorSetNotCanonical(uint256 index);
    error ZeroValidatorWeight(uint256 index);
    error ValidatorWeightExceedsTotal(uint256 keyedWeight, uint256 totalWeight);
    error ValidatorKeyNotOnCurve(uint256 index);
    error InvalidSignerBitSet();
    error InsufficientSignedWeight(uint256 signedWeight, uint256 totalWeight);

    /// @notice `UnsignedMessage` bytes for a `payload.Hash(blockHash)` from `sourceChainId` (80 bytes).
    function blockHashMessage(uint32 networkId, bytes32 sourceChainId, bytes32 blockHash)
        internal
        pure
        returns (bytes memory)
    {
        return
            abi.encodePacked(uint16(0), networkId, sourceChainId, HASH_PAYLOAD_LENGTH, uint16(0), uint32(0), blockHash);
    }

    /// @notice Number of validators in a packed set; reverts unless it is a non-empty multiple of 104
    ///         bytes and at most {MAX_VALIDATORS} entries.
    function count(bytes memory packedSet) internal pure returns (uint256 n) {
        uint256 len = packedSet.length;
        n = len / ENTRY_LENGTH;
        if (len == 0 || len % ENTRY_LENGTH != 0 || n > MAX_VALIDATORS) revert InvalidValidatorSetLength(len);
    }

    /// @notice Full well-formedness check, run once per set (config and rotation), never per bundle:
    ///         strictly ascending keys (canonical order, hence no duplicates — avalanchego merges
    ///         equal keys), non-zero weights, keyed weight ≤ `totalWeight`, and every key on the curve
    ///         (`BLS12_G1ADD` validates both of its inputs, two keys per 375-gas call).
    function validate(bytes memory packedSet, uint256 totalWeight) internal view {
        uint256 n = count(packedSet);
        uint256 keyed;
        bytes memory buf = new bytes(256);
        for (uint256 i = 0; i < n; i++) {
            uint256 w = weightAt(packedSet, i);
            if (w == 0) revert ZeroValidatorWeight(i);
            keyed += w;
            if (i > 0 && !_keyLess(packedSet, i - 1, i)) revert ValidatorSetNotCanonical(i);
            // Pair keys (i-1, i) for the curve check; an odd tail pairs with the point at infinity.
            if (i % 2 == 1) {
                _writeKey(buf, 0, packedSet, i - 1);
                _writeKey(buf, 128, packedSet, i);
                if (!_g1Add(buf)) revert ValidatorKeyNotOnCurve(i);
            } else if (i == n - 1) {
                _writeKey(buf, 0, packedSet, i);
                _zero128(buf, 128);
                if (!_g1Add(buf)) revert ValidatorKeyNotOnCurve(i);
            }
        }
        if (keyed > totalWeight) revert ValidatorWeightExceedsTotal(keyed, totalWeight);
    }

    /// @notice Aggregate the signers' keys and weight from an Avalanche `BitSetSignature.Signers`.
    /// @return aggregatePubkey 128-byte EIP-2537 G1 sum of the signers' keys (each add re-checks the
    ///         keys are on the curve; the pairing later subgroup-checks the sum).
    /// @return signedWeight Σ weight of the signers.
    function aggregateSigners(bytes memory packedSet, bytes memory signers)
        internal
        view
        returns (bytes memory aggregatePubkey, uint256 signedWeight)
    {
        uint256 n = count(packedSet);
        uint256 len = signers.length;
        // Minimal big-endian encoding (`len(BitsFromBytes(s).Bytes()) == len(s)`): no leading zero
        // byte; the empty bit set has no signers and can never reach quorum.
        if (len == 0 || uint8(signers[0]) == 0) revert InvalidSignerBitSet();
        // FilterValidators: BitLen() must not exceed n.
        uint256 bitLen = (len - 1) * 8 + _bitLength(uint8(signers[0]));
        if (bitLen > n) revert InvalidSignerBitSet();

        bytes memory buf = new bytes(256); // [acc(128) ‖ next(128)], acc starts at infinity (zeros)
        for (uint256 i = 0; i < bitLen; i++) {
            if ((uint8(signers[len - 1 - (i >> 3)]) >> (i & 7)) & 1 == 0) continue;
            signedWeight += weightAt(packedSet, i);
            _writeKey(buf, 128, packedSet, i);
            if (!_g1Add(buf)) revert ValidatorKeyNotOnCurve(i);
        }
        aggregatePubkey = new bytes(128);
        assembly ("memory-safe") {
            mcopy(add(aggregatePubkey, 0x20), add(buf, 0x20), 128)
        }
    }

    /// @notice avalanchego `VerifyWeight`: `quorumNum·total ≤ quorumDen·signed`.
    function requireQuorum(uint256 signedWeight, uint256 totalWeight) internal pure {
        if (QUORUM_NUMERATOR * totalWeight > QUORUM_DENOMINATOR * signedWeight) {
            revert InsufficientSignedWeight(signedWeight, totalWeight);
        }
    }

    /// @notice Weight (uint64, big-endian) of validator `i`.
    function weightAt(bytes memory packedSet, uint256 i) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := shr(192, mload(add(add(packedSet, 0x20), add(mul(i, ENTRY_LENGTH), KEY_LENGTH))))
        }
    }

    /// @notice Validator `i`'s key in EIP-2537 form (`pad16 ‖ x ‖ pad16 ‖ y`, 128 bytes).
    function keyAt(bytes memory packedSet, uint256 i) internal pure returns (bytes memory key) {
        key = new bytes(128);
        _writeKey(key, 0, packedSet, i);
    }

    // ── private ─────────────────────────────────────────────────────────────

    /// @dev key(a) < key(b), comparing the 96 key bytes as three big-endian words.
    function _keyLess(bytes memory packedSet, uint256 a, uint256 b) private pure returns (bool less) {
        assembly ("memory-safe") {
            let pa := add(add(packedSet, 0x20), mul(a, ENTRY_LENGTH))
            let pb := add(add(packedSet, 0x20), mul(b, ENTRY_LENGTH))
            for { let o := 0 } lt(o, KEY_LENGTH) { o := add(o, 0x20) } {
                let wa := mload(add(pa, o))
                let wb := mload(add(pb, o))
                if lt(wa, wb) {
                    less := 1
                    break
                }
                if gt(wa, wb) { break }
            }
        }
    }

    /// @dev Write validator `i`'s key, re-padded to EIP-2537 layout, at `buf[off..off+128)`.
    function _writeKey(bytes memory buf, uint256 off, bytes memory packedSet, uint256 i) private pure {
        assembly ("memory-safe") {
            let dst := add(add(buf, 0x20), off)
            let src := add(add(packedSet, 0x20), mul(i, ENTRY_LENGTH))
            mstore(dst, 0) // pad16 ‖ x[0..16) region cleared
            mcopy(add(dst, 16), src, 48) // x
            mstore(add(dst, 64), 0) // pad16 ‖ y[0..16) region cleared
            mcopy(add(dst, 80), add(src, 48), 48) // y
        }
    }

    function _zero128(bytes memory buf, uint256 off) private pure {
        assembly ("memory-safe") {
            let dst := add(add(buf, 0x20), off)
            mstore(dst, 0)
            mstore(add(dst, 0x20), 0)
            mstore(add(dst, 0x40), 0)
            mstore(add(dst, 0x60), 0)
        }
    }

    /// @dev `buf[0..128) := buf[0..128) + buf[128..256)` via BLS12_G1ADD; false if either input is not
    ///      a valid encoding of a point on the curve.
    function _g1Add(bytes memory buf) private view returns (bool ok) {
        assembly ("memory-safe") {
            let p := add(buf, 0x20)
            // Two statements: Yul evaluates arguments right-to-left, so a nested
            // `and(staticcall(..), eq(returndatasize(), 128))` would read returndatasize first.
            ok := staticcall(gas(), 0x0b, p, 256, p, 128) // 0x0b = BLS12_G1ADD (EIP-2537)
            ok := and(ok, eq(returndatasize(), 128))
        }
    }

    function _bitLength(uint8 b) private pure returns (uint256 l) {
        while (b != 0) {
            l++;
            b >>= 1;
        }
    }
}
