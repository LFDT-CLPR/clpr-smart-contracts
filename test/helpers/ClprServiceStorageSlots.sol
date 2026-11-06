// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

/// @notice Top-level `ClprService` storage slots used by invariant tests (`vm.load`).
/// @dev Must stay aligned with committed `storage-layout.json` (CI checks that file).
///      Run `test/invariants/ClprStorageLayoutGuard.t.sol` after layout changes.
library ClprServiceStorageSlots {
    /// @dev `_bundleDecodeHelper` (lower 160 bits) and `_clprEnabled` (byte offset 20) share slot 2.
    uint256 internal constant PACKED_MISC = 2;
    uint256 internal constant CHANNEL_TO_COMMITMENT = 12;
    /// @dev `_peerEndpointManifests` (channelId => cached peer ClprEndpointManifest).
    uint256 internal constant PEER_ENDPOINT_MANIFESTS = 22;
    /// @dev Deprecated roster slots — reserved so `_channels` stays at slot 15
    ///      (pinned by the EVM verifiers' storage-slot derivation and the relay tooling).
    uint256 internal constant PEER_ENDPOINT_COUNT = 13;
    uint256 internal constant PEER_ENDPOINT_ACCOUNTS = 14;

    uint256 internal constant CHANNEL_EXISTS = 5;
    uint256 internal constant PENDING_COMMITMENTS = 6;
    uint256 internal constant CONNECTORS = 16;
    uint256 internal constant CONNECTOR_EXISTS = 7;
    uint256 internal constant CONNECTOR_INFLIGHT = 9;
    uint256 internal constant CONNECTOR_QUEUE_COUNTS = 10;
    uint256 internal constant CHANNEL_COUNT = 3;
    uint256 internal constant CONNECTOR_COUNT = 4;
    uint256 internal constant PENDING_WITHDRAWALS = 11;

    /// @dev `_endpointManifest` (ClprTypes.EndpointManifestState) base slot. Members:
    ///      version(0), commitment(1), entries mapping(2), liveAccounts array(3), liveCounter(4).
    uint256 internal constant ENDPOINT_MANIFEST = 17;
    /// @dev Slot of the `entries` (registrant => EndpointManifestEntry) mapping inside the struct.
    uint256 internal constant ENDPOINT_MANIFEST_ENTRIES = 19;
    /// @dev In-struct slot of `EndpointManifestEntry.bond` (endpoint occupies members 0-3, bond at 4).
    uint256 internal constant ENDPOINT_ENTRY_BOND_MEMBER = 4;
    /// @dev In-struct slot of `EndpointManifestEntry.status` (immediately after bond).
    uint256 internal constant ENDPOINT_ENTRY_STATUS_MEMBER = 5;
    /// @dev In-struct slot of `EndpointManifestState.commitment` (version at 0, commitment at 1).
    ///      Base 17 + member 1 = absolute slot 18 = ClprEvmBundleVerifier.ENDPOINT_MANIFEST_COMMITMENT_SLOT.
    uint256 internal constant ENDPOINT_MANIFEST_COMMITMENT_MEMBER = 1;

    /// @dev `_feeAsset` (ClprTypes.FeeAsset: token in the low 160 bits, decimals above it).
    ///      BundleLogic passes this slot to BundleLib, which reads it with a raw `sload`.
    uint256 internal constant FEE_ASSET = 38;

    /// @dev OpenZeppelin `Ownable._owner`, sequential slot after all `ClprServiceStorage`
    ///      vars. Read via raw `sload` in `ClprServiceStorage._getOwner()`; both must match.
    uint256 internal constant OWNER = 39;

    /// @dev Byte offset of `_clprEnabled` within `PACKED_MISC` (see storage-layout.json).
    uint256 internal constant CLPR_ENABLED_BYTE_OFFSET = 20;
    uint256 internal constant CLPR_ENABLED_BIT_SHIFT = CLPR_ENABLED_BYTE_OFFSET * 8;

    /// @dev Sequential slot of Ownable._owner, inherited after ClprServiceStorage fields.
    ///      Must match ClprServiceStorage._getOwner() hardcoded slot.
    uint256 internal constant OWNER_SLOT = 39;
}

/// @notice Storage slot derivations for mappings used in invariant `vm.load` reads.
library ClprStorageLayoutLib {
    function mapBytes32Slot(bytes32 key, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, slot));
    }

    function mapAddressSlot(address key, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, slot));
    }

    function nestedMapBytes32Bytes32Slot(bytes32 k1, bytes32 k2, uint256 slot) internal pure returns (bytes32) {
        bytes32 outer = keccak256(abi.encode(k1, slot));
        return keccak256(abi.encode(k2, outer));
    }
}
