// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";

/// @title ClprEd25519SignatureCache
/// @notice Permissionless cache of checked Ed25519 signatures, used to split a consensus certificate
///         that is too expensive for one Hedera transaction across several.
///
///         Pure-Solidity Ed25519 costs ~640k gas per signature, so one 15M-gas transaction checks at
///         most ~21 signatures. NEAR mainnet needs 31–49 block-producer approvals per light-client block
///         (recorded fixtures) and TON mainnet 68–69 masterchain validator signatures per block. A relayer first calls
///         {record} in as many transactions as needed (~20 signatures each); the verifier then accepts
///         a signer whose signature it finds here instead of re-checking it.
///
///         The cache stores only facts it checked itself: "`pubKey` signed `message`". It is keyed by
///         `keccak256(pubKey ‖ keccak256(message))`, has no owner, no configuration and no way to delete
///         an entry. Trust is unchanged: a verifier that reads it still enforces the validator set,
///         the stake threshold and the exact message, so an entry recorded for any other key or
///         message is simply never consulted.
contract ClprEd25519SignatureCache {
    /// @notice Pure-Solidity (or precompile-backed) Ed25519 verifier used to check every entry.
    IEd25519Verifier public immutable ED25519;

    /// @notice `keccak256(pubKey ‖ keccak256(message))` → checked.
    mapping(bytes32 => bool) public verified;

    /// @notice Emitted once per newly cached signature.
    event SignatureCached(bytes32 indexed pubKey, bytes32 indexed messageHash);

    error LengthMismatch();
    error InvalidSignature(uint256 index);
    error ZeroVerifier();

    constructor(IEd25519Verifier ed25519) {
        if (address(ed25519) == address(0)) revert ZeroVerifier();
        ED25519 = ed25519;
    }

    /// @notice Check `signatures[i]` (64 bytes each, R ‖ S) by `pubKeys[i]` over the one `message` and
    ///         cache every valid one. Already cached signers are skipped. Reverts on the first invalid
    ///         signature so a relayer never pays for a partially useless batch.
    function record(bytes calldata message, bytes32[] calldata pubKeys, bytes calldata signatures) external {
        if (signatures.length != pubKeys.length * 64) revert LengthMismatch();
        bytes32 messageHash = keccak256(message);
        for (uint256 i = 0; i < pubKeys.length; i++) {
            bytes32 k = keccak256(abi.encodePacked(pubKeys[i], messageHash));
            if (verified[k]) continue;
            if (!ED25519.verify(pubKeys[i], message, signatures[i * 64:(i + 1) * 64])) revert InvalidSignature(i);
            verified[k] = true;
            emit SignatureCached(pubKeys[i], messageHash);
        }
    }

    /// @notice Whether `pubKey` is recorded as having signed the message with hash `messageHash`.
    function isVerified(bytes32 pubKey, bytes32 messageHash) external view returns (bool) {
        return verified[keccak256(abi.encodePacked(pubKey, messageHash))];
    }
}
