// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";

/// @title SignerReplayProfiles
/// @notice Deployment profiles for {SignerReplayVerifier}. Each value is taken from the chain's node
///         source or genesis file and checked against live headers (see the per-chain pages under
///         docs/chains/).
library SignerReplayProfiles {
    uint8 internal constant NO_TRAILER_SIGNER = type(uint8).max;

    /// @dev Immutable zkEVM: go-ethereum Clique (immutable/immutable-geth). Checkpoint every 30000
    ///      blocks lists the signers (20-byte entries); the seal covers every header field.
    function immutableZkEvm(uint64 chainId) internal pure returns (SignerReplayVerifier.Profile memory) {
        return SignerReplayVerifier.Profile({
            chainId: chainId,
            epochLength: 30000,
            boundaryOffset: 0,
            maxAnchorAge: 0,
            sealFields: 0,
            entrySize: 20,
            trailerSize: 0,
            trailerSignerOffset: NO_TRAILER_SIGNER
        });
    }

    /// @dev KUB Chain: Bitkub's Clique fork (kub-chain/bkc) in its PoS mode. The block before each
    ///      50-block span lists the span schedule as (address20 ‖ power20) entries, then three system
    ///      addresses; the third is the Basel "super node", which may also seal.
    function kub(uint64 chainId) internal pure returns (SignerReplayVerifier.Profile memory) {
        return SignerReplayVerifier.Profile({
            chainId: chainId,
            epochLength: 50,
            boundaryOffset: 1,
            maxAnchorAge: 0,
            sealFields: 0,
            entrySize: 40,
            trailerSize: 60,
            trailerSignerOffset: 40
        });
    }

    /// @dev GRX Chain: HECO Congress layout (node source not published). Epoch block every 200 blocks
    ///      lists the validators (20-byte entries); the seal covers the first 15 header fields only.
    function grx(uint64 chainId) internal pure returns (SignerReplayVerifier.Profile memory) {
        return SignerReplayVerifier.Profile({
            chainId: chainId,
            epochLength: 200,
            boundaryOffset: 0,
            maxAnchorAge: 0,
            sealFields: 15,
            entrySize: 20,
            trailerSize: 0,
            trailerSignerOffset: NO_TRAILER_SIGNER
        });
    }
}
