// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {LogicModuleBase} from "@hiero-ledger/clpr/logic/base/LogicModuleBase.sol";

/// @title BundleLogic
/// @notice Bundle submission: delegates proof processing to BundleLib.
/// @dev Isolated from MessagingLogic to keep both contracts below the EIP-170
///      24 KB bytecode limit. Executed via delegatecall from ClprService.
contract BundleLogic is LogicModuleBase {
    constructor() {}

    /// @notice Submit a proof bundle for a channel, advancing the acknowledged
    ///         message cursor and crediting submitter rewards.
    /// @dev Permissionless: any caller may submit. Bundle correctness is secured by
    ///      the channel's verifier; the submitter (msg.sender) is the recipient of
    ///      connector charges and slash proceeds for messages in this bundle.
    /// @param proofBytes Encoded proof blob; format is defined by the channel's verifier.
    function submitBundle(bytes32 _channelId, bytes calldata proofBytes) external nonReentrant onlyService whenEnabled {
        uint256 connectorCountSlot;
        assembly {
            connectorCountSlot := _connectorCount.slot
        }
        BundleLib.processBundle(
            _channels,
            _channelExists,
            _messageQueues,
            _connectors,
            _connectorExists,
            _connectorInflightCount,
            _connectorQueueCounts,
            _pendingWithdrawals,
            _peerEndpointManifests,
            connectorCountSlot,
            proofBytes,
            BundleLib.ProcessBundleParams({
                channelId: _channelId,
                bundleSubmitter: msg.sender,
                decodeHelperAddr: _bundleDecodeHelper,
                fallbackRecipient: _getOwner(),
                config: _config,
                econ: economicConfig,
                feeAsset: _feeAsset
            })
        );
    }
}
