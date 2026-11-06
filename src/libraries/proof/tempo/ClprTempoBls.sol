// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @title ClprTempoBls
/// @notice BLS12-381 checks for Tempo certificates. Tempo uses the MinSig variant: signatures in
///         G1, keys in G2.
/// @dev Verification hashes the message to G1 (RFC 9380, G1 POP tag) and runs one pairing check:
///      `e(sig, -G2) * e(H(m), key) == 1`. All points use the EIP-2537 uncompressed form. The code
///      never decompresses a point. It only compresses a point, to compare it with committed bytes.
library ClprTempoBls {
    /// @dev Domain separation tag of the MinSig variant.
    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    error BadLength();
    error BlsSignatureInvalid();

    /// @notice Verify `signature` (128 bytes, G1) over `message` under `publicKey` (256 bytes, G2).
    /// @dev A point off the curve or outside the subgroup makes the precompile fail.
    function verifyMinSig(bytes memory signature, bytes memory message, bytes memory publicKey) internal view {
        if (signature.length != ClprBls12381.G1_POINT_LENGTH || publicKey.length != ClprBls12381.G2_POINT_LENGTH) {
            revert BadLength();
        }
        bytes memory hashed = ClprBls12381.hashToG1(message, DST);
        bytes memory input = abi.encodePacked(signature, ClprBls12381.G2_GENERATOR_NEG, hashed, publicKey);
        if (!ClprBls12381.pairing(input)) revert BlsSignatureInvalid();
    }
}
