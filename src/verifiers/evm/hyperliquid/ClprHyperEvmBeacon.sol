// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord as QueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";

/// @title ClprHyperEvmBeacon
/// @notice Deployed on HyperEVM next to the ClprService. HyperEVM headers carry no state root
///         (`stateRoot = 0x0`) and the RPC has no `eth_getProof`, so channel storage cannot be proven.
///         Receipts are committed (`receiptsRoot`), so this contract turns the service's live state
///         into an event: `publish` reads the channel, the configuration and the endpoint manifest in
///         the same transaction and emits them as a ClprQueueRecord. Anyone may call it; the
///         record is whatever the service holds at that point of the block.
/// @dev Reference implementation for {HyperEvmVerifier}; not deployed by these tests on HyperEVM.
contract ClprHyperEvmBeacon {
    /// @notice topic0 = keccak256("ClprQueueRecord(address,bytes32,bytes)")
    event ClprQueueRecord(address indexed service, bytes32 indexed channelId, bytes record);

    IClprService public immutable SERVICE;

    constructor(IClprService service) {
        SERVICE = service;
    }

    /// @notice Emit the record for `channelId`, or a service-level record (config and manifest only)
    ///         for channel 0.
    function publish(bytes32 channelId) external returns (bytes memory record) {
        QueueRecord.Record memory r;
        r.channelId = channelId;
        if (channelId != bytes32(0)) {
            ClprTypes.Channel memory c = SERVICE.getChannel(channelId);
            r.state = uint8(c.status);
            r.nextMessageId = c.nextMessageId;
            r.receivedMessageId = c.receivedMessageId;
            r.sentRunningHash = c.sentRunningHash;
            r.receivedRunningHash = c.receivedRunningHash;
            r.endpointManifestVersion = c.endpointManifestVersion;
        }
        r.manifestCommitment = keccak256(ClprProtobuf.encodeEndpointManifest(SERVICE.getEndpointManifest()));
        r.configHash = keccak256(ClprProtobuf.encodeControlMessage(SERVICE.getLedgerConfiguration()));
        record = QueueRecord.encode(r);
        emit ClprQueueRecord(address(SERVICE), channelId, record);
    }
}
