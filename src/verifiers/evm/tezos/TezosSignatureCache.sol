// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {TezosKeys} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosKeys.sol";

/// @title TezosSignatureCache
/// @notice Permissionless cache of checked Tezos tz1 (Ed25519) and tz3 (P-256) signatures, used to
///         split a Tezos attestation quorum that is too expensive for one Hedera transaction.
///
///         Pure-Solidity Ed25519 costs ~640k gas and P-256 ~200k gas per signature. A relayer first
///         calls {record} in as many transactions as needed; {TezosVerifier} then accepts an attester
///         whose signature it finds here instead of checking it again.
///
///         The cache only stores facts it checked itself: "key `key` of scheme `scheme` signed the
///         BLAKE2b digest `digest`". It is keyed by `keccak256(scheme ‖ key ‖ digest)`, has no owner,
///         no configuration and no way to delete an entry. A verifier that reads it still derives the
///         signer's key from the Tezos context and the digest from the attested block, so an entry for
///         any other key or message is never consulted.
contract TezosSignatureCache {
    uint8 internal constant ED25519 = 0;
    uint8 internal constant P256 = 2;

    struct Entry {
        uint8 scheme; // 0 = Ed25519 (32-byte key), 2 = P-256 (33-byte compressed key)
        bytes key;
        bytes32 y; // P-256 only: affine y of the key
        bytes32 digest; // BLAKE2b-256 of watermark ‖ operation bytes
        bytes signature; // 64 bytes
    }

    IEd25519Verifier public immutable ED25519_VERIFIER;

    mapping(bytes32 => bool) public verified;

    event SignatureCached(uint8 indexed scheme, bytes32 indexed keyHash, bytes32 indexed digest);

    error InvalidSignature(uint256 index);
    error UnsupportedScheme(uint256 index);
    error ZeroVerifier();

    constructor(IEd25519Verifier ed25519) {
        if (address(ed25519) == address(0)) revert ZeroVerifier();
        ED25519_VERIFIER = ed25519;
    }

    /// @notice Cache key of a (scheme, key, digest) fact.
    function entryKey(uint8 scheme, bytes memory key, bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(scheme, key, digest));
    }

    /// @notice Check and cache every entry. Reverts on the first invalid one so a relayer never pays
    ///         for a partially useless batch; already cached entries are skipped.
    function record(Entry[] calldata entries) external {
        for (uint256 i = 0; i < entries.length; i++) {
            Entry calldata e = entries[i];
            bytes32 k = entryKey(e.scheme, e.key, e.digest);
            if (verified[k]) continue;
            bool ok;
            if (e.scheme == ED25519) {
                ok = e.key.length == 32
                    && ED25519_VERIFIER.verify(bytes32(e.key), abi.encodePacked(e.digest), e.signature);
            } else if (e.scheme == P256) {
                bytes memory key = e.key;
                uint256 keyAt;
                assembly ("memory-safe") {
                    keyAt := add(key, 0x20)
                }
                ok = key.length == 33 && TezosKeys.verifyP256(keyAt, e.y, e.digest, e.signature);
            } else {
                revert UnsupportedScheme(i);
            }
            if (!ok) revert InvalidSignature(i);
            verified[k] = true;
            emit SignatureCached(e.scheme, keccak256(e.key), e.digest);
        }
    }

    /// @notice Check one tz3 (P-256) signature without caching it. {TezosVerifier} calls this for
    ///         P-256 signatures supplied inline, which keeps the P-256 code out of its own bytecode.
    function checkP256(bytes memory key, bytes32 y, bytes32 digest, bytes memory signature)
        external
        view
        returns (bool)
    {
        if (key.length != 33) return false;
        uint256 keyAt;
        assembly ("memory-safe") {
            keyAt := add(key, 0x20)
        }
        return TezosKeys.verifyP256(keyAt, y, digest, signature);
    }

    /// @notice Whether `key` of `scheme` is recorded as having signed `digest`.
    function isVerified(uint8 scheme, bytes memory key, bytes32 digest) external view returns (bool) {
        return verified[entryKey(scheme, key, digest)];
    }
}
