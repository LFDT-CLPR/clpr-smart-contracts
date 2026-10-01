// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CosmWasmVerifier} from "@hiero-ledger/clpr/verifiers/evm/provenance/CosmWasmVerifier.sol";

/// @title CosmosModuleVerifier
/// @notice "Cosmos SDK chain with a native x/clpr module → Hiero" verifier. Built for dYdX v4
///         (no contract runtime, so the CLPR Service is a native module); any CometBFT + Cosmos SDK
///         chain that adds the same module fits through the deploy-time profile.
///         See README.md in this directory and modules/x-clpr.
///
/// Same verification chain as {CosmWasmVerifier} (CometBFT commit, multistore proof under app_hash,
/// IAVL proof of one queue record per channel, optional manifest binding); only the key layout of
/// the module's own IAVL store (profile `storeKey`, "clpr") differs:
///
///   0x01 ‖ channel_id(32)                      queue record, 90 B (same encoding as CosmWasm)
///   0x02 ‖ channel_id(32) ‖ message_id u64 BE   ClprMessageValue{1 payload, 2 running_hash_after_processing}
///   0x03                                       service item: module address(20) ‖ manifest commitment(32)
///
/// The service address is the module account, `sha256("clpr")[:20]` (Cosmos SDK
/// `authtypes.NewModuleAddress`); the service item binds it, as wasmd's contract prefix binds a
/// contract address. Source of the layout: modules/x-clpr/x/clpr/types/keys.go.
contract CosmosModuleVerifier is CosmWasmVerifier {
    uint8 internal constant QUEUE_RECORD_PREFIX = 0x01;
    uint8 internal constant MESSAGE_PREFIX = 0x02;
    uint8 internal constant SERVICE_ITEM_PREFIX = 0x03;

    error InvalidMessageValue();

    constructor(Profile memory p) CosmWasmVerifier(p) {}

    /// @notice Prove one outbound queue entry (`0x02 ‖ channelId ‖ messageId`) under a verified
    ///         commit. The entry must exist.
    /// @param proofBytes  CosmWasmProof{2 header, 3 hops, 4 multistore proof, 5 entry}.
    /// @param trustAnchor validatorSetHash(32) ‖ height(8).
    /// @return payload    Serialized ClprMessagePayload, exactly the bytes that entered the running hash.
    /// @return runningHashAfter Running hash after this message: sha256(prev ‖ sha256(payload)).
    /// @return height     Height of the header whose app_hash commits to that state.
    function verifyQueueMessage(
        bytes calldata proofBytes,
        bytes calldata trustAnchor,
        bytes32 channelId,
        uint64 messageId
    ) external view returns (bytes memory payload, bytes32 runningHashAfter, uint64 height) {
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        Payload memory p = _parsePayload(proofBytes);
        (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) = _verifiedStoreRoot(p, anchorHash, anchorHeight);
        (bool exists, bytes memory value) = _proveEntry(p.entry, storeRoot, messageKey(channelId, messageId));
        if (!exists) revert EntryNotFound();
        (payload, runningHashAfter) = _decodeMessageValue(value);
        height = h.height;
    }

    /// @notice Prove any raw key of the module's store (existence or absence) under a verified commit.
    function verifyModuleEntry(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata key)
        external
        view
        returns (bool exists, bytes memory value, uint64 height)
    {
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        Payload memory p = _parsePayload(proofBytes);
        (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) = _verifiedStoreRoot(p, anchorHash, anchorHeight);
        (exists, value) = _proveEntry(p.entry, storeRoot, key);
        height = h.height;
    }

    /// @notice Store key of a queued message.
    function messageKey(bytes32 channelId, uint64 messageId) public pure returns (bytes memory) {
        return abi.encodePacked(MESSAGE_PREFIX, channelId, messageId);
    }

    function _queueKey(bytes memory, bytes32 channelId) internal pure override returns (bytes memory) {
        return abi.encodePacked(QUEUE_RECORD_PREFIX, channelId);
    }

    function _serviceKey(bytes memory) internal pure override returns (bytes memory) {
        return abi.encodePacked(SERVICE_ITEM_PREFIX);
    }

    /// @dev A module account address is 20 bytes.
    function _checkAddress(bytes memory a) internal pure override {
        if (a.length != 20) revert InvalidServiceAddressLength();
    }

    /// @dev ClprMessageValue{1 payload bytes, 2 running_hash_after_processing bytes(32)}; both required.
    function _decodeMessageValue(bytes memory v) internal pure returns (bytes memory payload, bytes32 runningHash) {
        bytes memory rh;
        uint256 off;
        while (off < v.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(v, off);
            off = off2;
            if (wt != 2) off = PB.skipField(v, off, wt);
            else if (fn_ == 1) (payload, off) = PB.decodeLengthDelimited(v, off);
            else if (fn_ == 2) (rh, off) = PB.decodeLengthDelimited(v, off);
            else off = PB.skipField(v, off, wt);
        }
        if (payload.length == 0 || rh.length != 32) revert InvalidMessageValue();
        // rh.length == 32 is checked above.
        // forge-lint: disable-next-line(unsafe-typecast)
        runningHash = bytes32(rh);
    }
}
