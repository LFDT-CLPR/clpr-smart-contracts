// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {MvxBlake2b} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxBlake2b.sol";
import {MvxBls} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxBls.sol";

/// @title MvxMetachainVerifier
/// @notice MultiversX metachain header proofs (Andromeda "equivalent proofs"): a header is final when
///         more than 2/3 of the epoch's metachain eligible validators sign BLAKE2b-256(header) with
///         the herumi BLS scheme of {MvxBls}, aggregated with KOSK (plain sum of keys).
///
///         This is the consensus half of a MultiversX → Hiero verifier only. It is not an
///         IClprVerifier: the state half (account and data tries) needs Merkle proofs that the public
///         gateways do not serve, and the epoch's eligible list is pinned at deployment instead of
///         being proven from the previous epoch (see src/verifiers/icpmvx/README.md, "Limits").
///
///         Pinned: the epoch and keccak256 of the eligible list in consensus order (n uncompressed
///         EIP-2537 G2 keys of 256 bytes, in the order the nodes coordinator sorts them).
contract MvxMetachainVerifier {
    uint32 public immutable EPOCH;
    uint256 public immutable N;
    bytes32 public immutable KEYS_HASH;

    error KeysMismatch();
    error BadBitmap();
    error BelowThreshold(uint256 signers, uint256 required);
    error WrongEpoch(uint32 epoch);
    error MalformedHeader();

    constructor(uint32 epoch, uint256 n, bytes32 keysHash) {
        EPOCH = epoch;
        N = n;
        KEYS_HASH = keysHash;
    }

    /// @notice Verify a metachain header and its proof.
    /// @param rawHeader Protobuf `MetaBlockV3` bytes (BLAKE2b-256 of them is the header hash).
    /// @param bitmap Signer bitmap over the eligible list (bit i of byte i/8 = validator i).
    /// @param signature Aggregated signature, uncompressed G1 (128 bytes).
    /// @param keys The pinned eligible list, n × 256 bytes.
    /// @return headerHash BLAKE2b-256(rawHeader).
    /// @return nonce Header nonce.
    /// @return signers Number of signers.
    function verifyHeader(
        bytes calldata rawHeader,
        bytes calldata bitmap,
        bytes calldata signature,
        bytes calldata keys
    ) external view returns (bytes32 headerHash, uint64 nonce, uint256 signers) {
        uint32 epoch;
        (nonce, epoch) = _nonceAndEpoch(rawHeader);
        if (epoch != EPOCH) revert WrongEpoch(epoch);
        headerHash = MvxBlake2b.hash256(rawHeader);
        signers = verifyHeaderHash(headerHash, bitmap, signature, keys);
    }

    /// @notice Verify an aggregated signature over `headerHash` by the bitmap's signers.
    function verifyHeaderHash(bytes32 headerHash, bytes calldata bitmap, bytes calldata signature, bytes calldata keys)
        public
        view
        returns (uint256 signers)
    {
        uint256 n = N;
        if (keys.length != n * MvxBls.G2_LEN || keccak256(keys) != KEYS_HASH) revert KeysMismatch();
        if (bitmap.length != (n + 7) / 8) revert BadBitmap();
        if (n % 8 != 0 && uint8(bitmap[bitmap.length - 1]) >> (n % 8) != 0) revert BadBitmap();

        bytes memory agg;
        for (uint256 i = 0; i < n; i++) {
            if ((uint8(bitmap[i >> 3]) >> (i & 7)) & 1 == 0) continue;
            bytes memory k = keys[i * 256:(i + 1) * 256];
            agg = signers == 0 ? k : MvxBls.addG2(agg, k);
            signers++;
        }
        uint256 required = n * 2 / 3 + 1; // mx-chain-core-go GetPBFTThreshold
        if (signers < required) revert BelowThreshold(signers, required);
        MvxBls.verify(agg, signature, abi.encodePacked(headerHash));
    }

    /// @notice Verify one validator signature (e.g. the leader's signature over the previous random
    ///         seed, which is the header's `randSeed`).
    function verifySignature(bytes calldata publicKey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool)
    {
        MvxBls.verify(publicKey, signature, message);
        return true;
    }

    /// @dev MetaBlockV3 fields 1 (Nonce, varint) and 2 (Epoch, varint).
    function _nonceAndEpoch(bytes calldata raw) internal pure returns (uint64 nonce, uint32 epoch) {
        bytes memory b = raw;
        uint256 off;
        bool haveNonce;
        bool haveEpoch;
        while (off < b.length && !(haveNonce && haveEpoch)) {
            (uint64 f, uint8 wt, uint256 o) = PB.decodeFieldKey(b, off);
            if (f == 1 && wt == 0) {
                (nonce, off) = PB.decodeVarint(b, o);
                haveNonce = true;
            } else if (f == 2 && wt == 0) {
                uint64 e;
                (e, off) = PB.decodeVarint(b, o);
                if (e > type(uint32).max) revert MalformedHeader();
                // forge-lint: disable-next-line(unsafe-typecast)
                epoch = uint32(e);
                haveEpoch = true;
            } else {
                off = PB.skipField(b, o, wt);
            }
        }
        if (!haveNonce || !haveEpoch) revert MalformedHeader();
    }
}
