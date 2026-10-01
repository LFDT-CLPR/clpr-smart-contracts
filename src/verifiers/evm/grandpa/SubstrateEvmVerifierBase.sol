// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";
import {SubstrateVerifierErrors} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateVerifierErrors.sol";

/// @title SubstrateEvmVerifierBase
/// @notice The state half shared by the Substrate verifiers: once a finalized `state_root` is
///         authenticated (GRANDPA for a solo chain, BEEFY + relay state for a parachain), the CLPR
///         Service's storage is read from Frontier's `pallet_evm::AccountStorages` through the
///         Substrate trie.
///
/// Storage key (frontier frame/evm: StorageDoubleMap<_, Blake2_128Concat, H160, Blake2_128Concat,
/// H256, H256, ValueQuery>):
///   twox128(pallet) ‖ twox128("AccountStorages") ‖ blake2_128(address) ‖ address ‖
///   blake2_128(slot) ‖ slot                                                     (116 bytes)
/// The value is the raw 32-byte word. Frontier deletes a slot written with zero
/// (runner/stack.rs `set_storage`), so a proven-absent key reads as zero, like an EVM SLOAD.
///
/// The slot layout (channel slots, manifest commitment, `_config`) is inherited from
/// {ClprEvmBundleVerifier}: the CLPR Service is the same Solidity contract on every EVM.
abstract contract SubstrateEvmVerifierBase is ClprEvmBundleVerifier, SubstrateVerifierErrors {
    /// @dev twox128("AccountStorages").
    bytes16 internal constant ACCOUNT_STORAGES_PREFIX = 0xab1160471b1418779239ba8e2b847e42;
    /// @dev ClprService `_config.serviceAddress` (struct base 23 + member 2; storage-layout.json).
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;
    /// @dev ClprService `_config.nanosSinceEpoch` (struct base 23 + member 3).
    uint256 internal constant CONFIG_NANOS_SLOT = 26;

    /// @notice twox128 of the Frontier EVM pallet name (`twox128("EVM")` on Bittensor and Hydration).
    bytes16 public immutable EVM_PALLET_PREFIX;
    /// @notice keccak256 of the CAIP-2 chain id the peer ClprService must report (e.g. "eip155:964").
    bytes32 public immutable CHAIN_ID_HASH;

    error InvalidEvmProfile();
    error InvalidStorageValue();
    error ChainIdMismatch();
    error ServiceAddressSlotMismatch();
    error ConfigNanosMismatch();

    constructor(bytes16 evmPalletPrefix, string memory chainId) {
        if (evmPalletPrefix == bytes16(0) || bytes(chainId).length == 0) revert InvalidEvmProfile();
        EVM_PALLET_PREFIX = evmPalletPrefix;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
    }

    /// @notice The `AccountStorages` trie key of `slot` of EVM contract `account`.
    function accountStorageKey(address account, bytes32 slot) public view returns (bytes memory) {
        return abi.encodePacked(
            EVM_PALLET_PREFIX,
            ACCOUNT_STORAGES_PREFIX,
            Blake2b.hash128Address(account),
            account,
            Blake2b.hash128Word(slot),
            slot
        );
    }

    /// @dev Reads EVM storage words from an authenticated trie proof. Absent keys read as zero.
    function _readEvmSlots(SubstrateTrie.Proof memory proof, bytes32 stateRoot, address account, bytes32[] memory slots)
        internal
        view
        returns (bytes32[] memory values)
    {
        values = new bytes32[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            (bool exists, bytes memory v) = SubstrateTrie.get(proof, stateRoot, accountStorageKey(account, slots[i]));
            if (exists) {
                if (v.length != 32) revert InvalidStorageValue();
                // casting to 'bytes32' is safe: the length is checked to be exactly 32 above.
                // forge-lint: disable-next-line(unsafe-typecast)
                values[i] = bytes32(v);
            }
        }
    }

    /// @dev Channel queue metadata (+ optional endpoint manifest) of `service` at `stateRoot`.
    ///      The slots come from the CLPR storage layout and `channelId`, never from the proof.
    /// @param lastMessageSlot Also prove the last sent message's running-hash slot (the 6th entry of
    ///                        the MPT verifiers' storage proof; only valid once nextMessageId > 0).
    /// @param manifestPreimage `ClprProtobuf.encodeEndpointManifest(manifest)`; empty = no update.
    function _verifyChannelState(
        bytes[] memory nodes,
        bytes32 stateRoot,
        bytes memory serviceAddress,
        bytes32 channelId,
        bool lastMessageSlot,
        bytes memory manifestPreimage
    ) internal view returns (ClprTypes.QueueMetadata memory metadata, ClprTypes.ClprEndpointManifest memory manifest) {
        address service = _toAddress(serviceAddress);
        SubstrateTrie.Proof memory proof = SubstrateTrie.load(nodes);
        metadata = _buildQueueMetadata(_readEvmSlots(proof, stateRoot, service, _channelMetadataSlots(channelId)));

        if (lastMessageSlot) {
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            bytes32[] memory s = new bytes32[](1);
            s[0] = _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1));
            // The walk itself is the check (a missing proof node reverts); the value is not needed.
            _readEvmSlots(proof, stateRoot, service, s);
        }

        if (manifestPreimage.length > 0) {
            manifest = _verifyManifestPreimage(proof, stateRoot, service, manifestPreimage, serviceAddress);
        } else {
            manifest = _absentEndpointManifest();
        }
    }

    /// @dev Binds `preimage` to the proven `_endpointManifest.commitment` slot and decodes it.
    function _verifyManifestPreimage(
        SubstrateTrie.Proof memory proof,
        bytes32 stateRoot,
        address service,
        bytes memory preimage,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory manifest) {
        bytes32[] memory s = new bytes32[](1);
        s[0] = bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT);
        if (keccak256(preimage) != _readEvmSlots(proof, stateRoot, service, s)[0]) {
            revert ManifestCommitmentMismatch();
        }
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev Config binding: the claimed LedgerConfiguration's chain id must be this profile's, and
    ///      its service address and config timestamp must be the ones stored in that contract's
    ///      `_config` at the authenticated state root. Returns the decoded configuration.
    /// @param ledgerConfig `ClprMessagePayload{control{config_update}}` bytes (as EthMainnetVerifier).
    /// @param manifestPreimage Optional endpoint manifest, proven against the same state root.
    function _verifyConfigState(
        bytes[] memory nodes,
        bytes32 stateRoot,
        bytes memory ledgerConfig,
        bytes memory manifestPreimage
    ) internal view returns (ClprTypes.LedgerConfiguration memory lc, ClprTypes.ClprEndpointManifest memory manifest) {
        lc = ClprProtobuf.decodeControlMessage(ledgerConfig).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert ChainIdMismatch();
        address service = _toAddress(lc.serviceAddress);

        SubstrateTrie.Proof memory proof = SubstrateTrie.load(nodes);
        bytes32[] memory s = new bytes32[](2);
        s[0] = bytes32(SERVICE_ADDRESS_SLOT);
        s[1] = bytes32(CONFIG_NANOS_SLOT);
        bytes32[] memory v = _readEvmSlots(proof, stateRoot, service, s);
        // Short `bytes` (20 B) layout: data left-aligned, length*2 = 0x28 in the low byte.
        if (v[0] != bytes32(uint256(bytes32(bytes20(service))) | 0x28)) revert ServiceAddressSlotMismatch();
        if (uint256(v[1]) != lc.nanosSinceEpoch) revert ConfigNanosMismatch();

        if (manifestPreimage.length > 0) {
            manifest = _verifyManifestPreimage(proof, stateRoot, service, manifestPreimage, lc.serviceAddress);
        } else {
            manifest = _uninitializedEndpointManifest(lc.serviceAddress);
        }
    }
}
