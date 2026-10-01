// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Design-phase gas benchmark for verifying Canton mediator-verdict signatures on Hedera.
/// Canton signs the 34-byte multihash `0x12 0x20 || SHA-256(int32BE(purpose) || bytes)`
/// (HashBuilderFromMessageDigest); SignedProtocolMessageSignature is purpose 38.
/// EcDsaSha256 signs SHA-256(multihash). Ed25519 (~640k gas/sig) is measured on feat/cometbft-verifier.
contract CantonSignatureGasTest is Test {
    uint32 internal constant SIGNED_PROTOCOL_MESSAGE_SIGNATURE = 38;
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _cantonMultihash(bytes memory content) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes2(0x1220), sha256(abi.encodePacked(SIGNED_PROTOCOL_MESSAGE_SIGNATURE, content)));
    }

    function _verdict() internal pure returns (bytes memory) {
        // Stand-in for a serialized TypedSignedProtocolMessageContent(ConfirmationResultMessage), ~200 B.
        return abi.encodePacked(keccak256("psid"), keccak256("rootHash"), new bytes(136));
    }

    function test_p256SolidityFallback() public {
        bytes32 digest = sha256(_cantonMultihash(_verdict()));
        uint256 pk = 0xC0FFEE;
        (bytes32 r, bytes32 s) = vm.signP256(pk, digest);
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s));
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);

        uint256 g = gasleft();
        bool ok = P256.verifySolidity(digest, r, s, bytes32(x), bytes32(y));
        uint256 used = g - gasleft();
        emit log_named_uint("P-256 (pure Solidity) gas per signature", used);
        assertTrue(ok);
        assertFalse(P256.verifySolidity(digest, r, bytes32(uint256(s) ^ 1), bytes32(x), bytes32(y)));
    }

    function test_secp256k1WithoutRecoveryId() public {
        // Canton secp256k1 signatures are DER (r,s) with no recovery id: try v = 27 and 28.
        bytes32 digest = sha256(_cantonMultihash(_verdict()));
        uint256 pk = 0xC0FFEE;
        address signer = vm.addr(pk);
        (, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        if (uint256(s) > K1_N / 2) s = bytes32(K1_N - uint256(s));

        uint256 g = gasleft();
        bool ok = ecrecover(digest, 27, r, s) == signer || ecrecover(digest, 28, r, s) == signer;
        uint256 used = g - gasleft();
        emit log_named_uint("secp256k1 (two ecrecover tries) gas per signature", used);
        assertTrue(ok);
    }
}
