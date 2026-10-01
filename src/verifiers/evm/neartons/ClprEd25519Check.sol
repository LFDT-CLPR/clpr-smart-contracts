// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";

/// @title ClprEd25519Check
/// @notice One Ed25519 signer check shared by the NEAR and TON verifiers: either the signature is
///         supplied (64 bytes, checked now by the external {IEd25519Verifier}) or it is empty and the
///         signer must already be recorded in the {ClprEd25519SignatureCache} for this exact message.
library ClprEd25519Check {
    error BadSignature(uint256 signerIndex);
    error SignatureNotCached(uint256 signerIndex);
    error SignatureCacheDisabled();

    function check(
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache cache,
        bytes32 pubKey,
        bytes memory message,
        bytes32 messageHash,
        bytes memory signature,
        uint256 signerIndex
    ) internal view {
        if (signature.length == 0) {
            if (address(cache) == address(0)) revert SignatureCacheDisabled();
            if (!cache.isVerified(pubKey, messageHash)) revert SignatureNotCached(signerIndex);
            return;
        }
        if (signature.length != 64 || !ed25519.verify(pubKey, message, signature)) revert BadSignature(signerIndex);
    }
}
