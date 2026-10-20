// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ClprServiceStorageSlots} from "@test/helpers/ClprServiceStorageSlots.sol";

/// @notice Ensures invariant `vm.load` slot constants match committed `storage-layout.json`.
contract ClprStorageLayoutGuardTest is Test {
    using stdJson for string;

    string internal _layoutJson;

    function setUp() public {
        // forge-lint: disable-next-line(unsafe-cheatcode)
        _layoutJson = vm.readFile(string.concat(vm.projectRoot(), "/storage-layout.json"));
    }

    function test_topLevelSlotsMatchStorageLayoutJson() public {
        _assertStorageSlot("_channelExists", ClprServiceStorageSlots.CHANNEL_EXISTS);
        _assertStorageSlot("_pendingCommitments", ClprServiceStorageSlots.PENDING_COMMITMENTS);
        _assertStorageSlot("_connectors", ClprServiceStorageSlots.CONNECTORS);
        _assertStorageSlot("_connectorExists", ClprServiceStorageSlots.CONNECTOR_EXISTS);
        _assertStorageSlot("_connectorInflightCount", ClprServiceStorageSlots.CONNECTOR_INFLIGHT);
        _assertStorageSlot("_connectorQueueCounts", ClprServiceStorageSlots.CONNECTOR_QUEUE_COUNTS);
        _assertStorageSlot("_endpointManifest", ClprServiceStorageSlots.ENDPOINT_MANIFEST);
        _assertStorageSlot("_channelCount", ClprServiceStorageSlots.CHANNEL_COUNT);
        _assertStorageSlot("_connectorCount", ClprServiceStorageSlots.CONNECTOR_COUNT);
        _assertStorageSlot("_pendingWithdrawals", ClprServiceStorageSlots.PENDING_WITHDRAWALS);
        _assertStorageSlot("_bundleDecodeHelper", ClprServiceStorageSlots.PACKED_MISC);
        _assertStorageSlot("_channelIdToCommitment", ClprServiceStorageSlots.CHANNEL_TO_COMMITMENT);
        _assertStorageSlot("_peerEndpointManifests", ClprServiceStorageSlots.PEER_ENDPOINT_MANIFESTS);
        // Deprecated roster slots are reserved (not reused) so `_channels` stays at slot 15,
        // which the EVM verifiers' storage-slot derivation pins.
        _assertStorageSlot("_deprecatedPeerEndpointCount", ClprServiceStorageSlots.PEER_ENDPOINT_COUNT);
        _assertStorageSlot("_deprecatedPeerEndpointAccounts", ClprServiceStorageSlots.PEER_ENDPOINT_ACCOUNTS);
        // `_owner` (OZ Ownable) is read via a raw sload in ClprServiceStorage._getOwner(); pin it
        // so a storage layout shift above it (e.g. an added/removed config field) fails loudly.
        _assertStorageSlot("_feeAsset", ClprServiceStorageSlots.FEE_ASSET);
        _assertStorageSlot("_owner", ClprServiceStorageSlots.OWNER);
    }

    function test_clprEnabledPackedOffsetMatchesLayout() public {
        _assertStorageOffset("_clprEnabled", ClprServiceStorageSlots.CLPR_ENABLED_BYTE_OFFSET);
        _assertStorageSlot("_clprEnabled", ClprServiceStorageSlots.PACKED_MISC);
    }

    function test_ownerSlotMatchesGetOwnerAssembly() public {
        // If this test fails - need to update ClprServiceStorage.sol - bytes32 slot = bytes32(uint256(37));
        // with the right slot number
        _assertStorageSlot("_owner", ClprServiceStorageSlots.OWNER_SLOT);
    }

    /// @dev Pins `EndpointManifestState.commitment` to the slot the EVM verifiers hardcode
    ///      (`ClprEvmBundleVerifier.ENDPOINT_MANIFEST_COMMITMENT_SLOT` = base 17 + member 1 = 18):
    ///      a peer verifier proves the manifest preimage against this exact slot.
    function test_manifestCommitmentMemberSlotMatchesLayout() public view {
        string[] memory typeKeys = vm.parseJsonKeys(_layoutJson, ".types");
        string memory manifestTypeKey;
        for (uint256 i = 0; i < typeKeys.length; i++) {
            // Match the struct type only (not mapping wrappers that embed the struct name).
            if (_startsWith(typeKeys[i], "t_struct(EndpointManifestState)") && _contains(typeKeys[i], "_storage")) {
                manifestTypeKey = typeKeys[i];
                break;
            }
        }
        require(bytes(manifestTypeKey).length > 0, "EndpointManifestState struct type not found in storage-layout.json");

        string memory membersPrefix = string.concat(".types['", manifestTypeKey, "'].members");
        uint256 memberCount = _structMemberCount(membersPrefix);
        bool found;
        for (uint256 i = 0; i < memberCount; i++) {
            string memory labelPath = string.concat(membersPrefix, "[", vm.toString(i), "].label");
            if (keccak256(bytes(_layoutJson.readString(labelPath))) == keccak256("commitment")) {
                string memory slotPath = string.concat(membersPrefix, "[", vm.toString(i), "].slot");
                assertEq(
                    _layoutJson.readUint(slotPath),
                    ClprServiceStorageSlots.ENDPOINT_MANIFEST_COMMITMENT_MEMBER,
                    "EndpointManifestState.commitment struct slot"
                );
                found = true;
                break;
            }
        }
        assertTrue(found, "EndpointManifestState.commitment not found in layout types");
    }

    /// @dev Pins every `Channel` struct member the EVM verifiers prove and decode.
    function test_channelProvenMemberSlotsMatchLayout() public view {
        string memory membersPrefix = _structMembersPrefix("t_struct(Channel)");
        // slot +1: verifier(20) | status(1) | nextMessageId(8)
        _assertStructMember(membersPrefix, "verifier", 1, 0);
        _assertStructMember(membersPrefix, "status", 1, 20);
        _assertStructMember(membersPrefix, "nextMessageId", 1, 21);
        // slot +2: ackedMessageId(8) | receivedMessageId(8) | nextExpectedReplyId(8)
        _assertStructMember(membersPrefix, "ackedMessageId", 2, 0);
        _assertStructMember(membersPrefix, "receivedMessageId", 2, 8);
        // slots +4 / +5: running hashes
        _assertStructMember(membersPrefix, "sentRunningHash", 4, 0);
        _assertStructMember(membersPrefix, "receivedRunningHash", 5, 0);
        // slot +16: endpointManifestVersion (QueueMetadata proto field 7)
        _assertStructMember(membersPrefix, "endpointManifestVersion", 16, 0);
    }

    /// @dev Locate the `.types` key of a struct (e.g. "t_struct(Channel)") and return the
    ///      JSON path prefix of its members array.
    function _structMembersPrefix(string memory structTypePrefix) internal view returns (string memory) {
        string[] memory typeKeys = vm.parseJsonKeys(_layoutJson, ".types");
        for (uint256 i = 0; i < typeKeys.length; i++) {
            if (_startsWith(typeKeys[i], structTypePrefix) && _contains(typeKeys[i], "_storage")) {
                return string.concat(".types['", typeKeys[i], "'].members");
            }
        }
        revert(string.concat(structTypePrefix, " not found in storage-layout.json"));
    }

    function _assertStructMember(
        string memory membersPrefix,
        string memory label,
        uint256 expectedSlot,
        uint256 expectedOffset
    ) internal view {
        uint256 memberCount = _structMemberCount(membersPrefix);
        for (uint256 i = 0; i < memberCount; i++) {
            string memory basePath = string.concat(membersPrefix, "[", vm.toString(i), "]");
            if (keccak256(bytes(_layoutJson.readString(string.concat(basePath, ".label")))) != keccak256(bytes(label)))
            {
                continue;
            }
            assertEq(
                _layoutJson.readUint(string.concat(basePath, ".slot")), expectedSlot, string.concat(label, " slot")
            );
            assertEq(
                _layoutJson.readUint(string.concat(basePath, ".offset")),
                expectedOffset,
                string.concat(label, " offset")
            );
            return;
        }
        revert(string.concat(label, " not found in struct layout"));
    }

    function _storageEntryCount() internal view returns (uint256) {
        for (uint256 i = 0; i < 128; i++) {
            if (!vm.keyExistsJson(_layoutJson, string.concat(".storage[", vm.toString(i), "].label"))) {
                return i;
            }
        }
        revert("storage-layout.json: .storage array too large");
    }

    function _assertStorageSlot(string memory label, uint256 expectedSlot) internal {
        uint256 n = _storageEntryCount();
        for (uint256 i = 0; i < n; i++) {
            string memory labelPath = string.concat(".storage[", vm.toString(i), "].label");
            if (keccak256(bytes(_layoutJson.readString(labelPath))) != keccak256(bytes(label))) continue;
            string memory slotPath = string.concat(".storage[", vm.toString(i), "].slot");
            assertEq(_layoutJson.readUint(slotPath), expectedSlot, label);
            return;
        }
        fail(string.concat("storage-layout.json missing label: ", label));
    }

    function _assertStorageOffset(string memory label, uint256 expectedOffset) internal {
        uint256 n = _storageEntryCount();
        for (uint256 i = 0; i < n; i++) {
            string memory labelPath = string.concat(".storage[", vm.toString(i), "].label");
            if (keccak256(bytes(_layoutJson.readString(labelPath))) != keccak256(bytes(label))) continue;
            string memory offsetPath = string.concat(".storage[", vm.toString(i), "].offset");
            assertEq(_layoutJson.readUint(offsetPath), expectedOffset, label);
            return;
        }
        fail(string.concat("storage-layout.json missing label: ", label));
    }

    function _structMemberCount(string memory membersPrefix) internal view returns (uint256) {
        for (uint256 i = 0; i < 32; i++) {
            if (!vm.keyExistsJson(_layoutJson, string.concat(membersPrefix, "[", vm.toString(i), "].label"))) {
                return i;
            }
        }
        revert("struct members array too large");
    }

    function _startsWith(string memory haystack, string memory prefix) internal pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory p = bytes(prefix);
        if (p.length > h.length) return false;
        for (uint256 i = 0; i < p.length; i++) {
            if (h[i] != p[i]) return false;
        }
        return true;
    }

    function _contains(string memory haystack, string memory needle) internal pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        if (n.length == 0 || n.length > h.length) return false;
        for (uint256 i = 0; i <= h.length - n.length; i++) {
            bool matchAll = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (h[i + j] != n[j]) {
                    matchAll = false;
                    break;
                }
            }
            if (matchAll) return true;
        }
        return false;
    }
}
