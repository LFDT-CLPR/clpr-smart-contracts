// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";
import {SubstrateEvmVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateEvmVerifierBase.sol";

/// @title GrandpaVerifier
/// @notice "Substrate solo chain → Hiero" verifier: GRANDPA finality (ed25519) plus Frontier EVM
///         storage through the Substrate state trie. Built for Bittensor (subtensor runtime:
///         Aura + GRANDPA + Frontier, pallet "EVM"); any solo chain with the same pieces is a
///         deploy-time profile. See README.md in this directory.
///
/// The light client (trust anchor, steps, set rotation) is {GrandpaLightClient}; this contract adds
/// the Frontier `AccountStorages` state layer of {SubstrateEvmVerifierBase}. The last step's J
/// provides `state_root`; a new anchor is returned iff the set changed.
contract GrandpaVerifier is SubstrateEvmVerifierBase, GrandpaLightClient {
    struct BundleProof {
        Step[] steps;
        bytes[] stateProof;
        bool lastMessageSlot;
        bytes bundleContent;
        bytes manifestPreimage;
    }

    struct ConfigProof {
        Step[] steps;
        bytes[] stateProof;
        bytes ledgerConfig;
    }

    /// @param ed25519Verifier          Pure-Solidity Ed25519 verifier (no ed25519 precompile on Hedera).
    /// @param evmPalletPrefix          twox128 of the Frontier EVM pallet name.
    /// @param chainId                  CAIP-2 id the peer ClprService reports, e.g. "eip155:964".
    /// @param bootstrapSetId           Weak-subjectivity checkpoint: GRANDPA set id …
    /// @param bootstrapAuthoritiesHash … keccak256 of its packed authority list …
    /// @param bootstrapMinHeight       … and the first block number it justifies.
    constructor(
        address ed25519Verifier,
        bytes16 evmPalletPrefix,
        string memory chainId,
        uint64 bootstrapSetId,
        bytes32 bootstrapAuthoritiesHash,
        uint32 bootstrapMinHeight
    )
        SubstrateEvmVerifierBase(evmPalletPrefix, chainId)
        GrandpaLightClient(ed25519Verifier, bootstrapSetId, bootstrapAuthoritiesHash, bootstrapMinHeight)
    {}

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof); trustAnchor = 44-byte {Anchor}.
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (proofBytes.length == 0) revert InvalidPayloadShape();
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (Anchor memory next, bytes32 stateRoot,) = _applySteps(p.steps, anchor);
        (metadata, newEndpointManifest) = _verifyChannelState(
            p.stateProof, stateRoot, ctx.remoteServiceAddress, ctx.channelId, p.lastMessageSlot, p.manifestPreimage
        );
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (next.setId != anchor.setId) {
            newTrustAnchor = _encodeAnchor(next);
            newTrustAnchorId = abi.encodePacked(next.setId);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), followed from the deploy-time bootstrap
    ///      checkpoint; endpointManifestProofBytes = the manifest preimage (or empty), proven against
    ///      the same state root as the config.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        (Anchor memory anchor, bytes32 stateRoot,) = _applySteps(p.steps, _bootstrapAnchor());
        ClprTypes.LedgerConfiguration memory lc;
        (lc, endpointManifest) = _verifyConfigState(p.stateProof, stateRoot, p.ledgerConfig, endpointManifestProofBytes);

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = _encodeAnchor(anchor);
        initialTrustAnchorId = abi.encodePacked(anchor.setId);
    }
}
