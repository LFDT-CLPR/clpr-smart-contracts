// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @title IClprTronAttestor
/// @notice ABI of the TRON-side attestation contract that {TronVerifier} reads out of proven
///         transactions. The verifier decodes the calldata of a successful `TriggerSmartContract`
///         to this contract, so the selectors and argument order are part of the proof format.
interface IClprTronAttestor {
    /// @notice Succeeds iff every argument equals the live state of `service`'s channel.
    function attestQueue(
        address service,
        bytes32 channelId,
        uint8 status,
        uint64 nextMessageId,
        bytes32 sentRunningHash,
        uint64 receivedMessageId,
        bytes32 receivedRunningHash,
        uint64 endpointManifestVersion,
        bytes32 manifestCommitment
    ) external;

    /// @notice Succeeds iff `manifestCommitment` equals the commitment of `service`'s live
    ///         endpoint manifest (used at channel setup, before a channel exists).
    function attestManifest(address service, bytes32 manifestCommitment) external;
}

/// @title ClprTronAttestor
/// @notice Reference implementation of {IClprTronAttestor}, to be deployed on TRON next to an
///         unmodified ClprService (compiled with TRON's solc fork). Not deployed by this repo.
///
/// @dev Why this exists: TRON blocks commit to transactions (txTrieRoot) but not to contract
///      storage or event logs (accountStateRoot is disabled and never covers storage; there is no
///      receipts root and no eth_getProof). What a TRON block *does* commit to is each transaction
///      together with `ret[0].contractRet`, which every validating node re-executes and compares
///      (TransactionTrace.check: "different resultCode" rejects the block). So a successful call to
///      a function that reverts unless its arguments equal the current storage proves that storage
///      held those values at that point of that block. The CLPR queue state crosses to Hiero as such
///      a call, confirmed by 19 of 27 Super Representatives.
///
///      Anyone may call it; it costs the caller TRON energy (~ the cost of `getChannel` plus one
///      manifest encode) and changes no state other than emitting an event for indexers.
contract ClprTronAttestor is IClprTronAttestor {
    /// @notice The ClprService whose state this contract attests. Immutable: the Hiero-side trust
    ///         anchor pins this attestor's address, and through it this service.
    IClprService public immutable SERVICE;

    event QueueAttested(bytes32 indexed channelId, uint64 nextMessageId, uint64 receivedMessageId);
    event ManifestAttested(bytes32 manifestCommitment);

    error WrongService();
    error UnknownChannel();
    error QueueMismatch();
    error ManifestMismatch();

    constructor(IClprService service) {
        SERVICE = service;
    }

    /// @inheritdoc IClprTronAttestor
    function attestQueue(
        address service,
        bytes32 channelId,
        uint8 status,
        uint64 nextMessageId,
        bytes32 sentRunningHash,
        uint64 receivedMessageId,
        bytes32 receivedRunningHash,
        uint64 endpointManifestVersion,
        bytes32 manifestCommitment
    ) external {
        if (service != address(SERVICE)) revert WrongService();
        ClprTypes.Channel memory c = SERVICE.getChannel(channelId);
        if (c.channelId != channelId) revert UnknownChannel();
        if (
            uint8(c.status) != status || c.nextMessageId != nextMessageId || c.sentRunningHash != sentRunningHash
                || c.receivedMessageId != receivedMessageId || c.receivedRunningHash != receivedRunningHash
                || c.endpointManifestVersion != endpointManifestVersion
        ) revert QueueMismatch();
        if (_manifestCommitment() != manifestCommitment) revert ManifestMismatch();
        emit QueueAttested(channelId, nextMessageId, receivedMessageId);
    }

    /// @inheritdoc IClprTronAttestor
    function attestManifest(address service, bytes32 manifestCommitment) external {
        if (service != address(SERVICE)) revert WrongService();
        if (_manifestCommitment() != manifestCommitment) revert ManifestMismatch();
        emit ManifestAttested(manifestCommitment);
    }

    /// @dev Same commitment ManifestLib keeps in storage: keccak256 of the protobuf manifest.
    function _manifestCommitment() private returns (bytes32) {
        return keccak256(ClprProtobuf.encodeEndpointManifest(SERVICE.getEndpointManifest()));
    }
}
