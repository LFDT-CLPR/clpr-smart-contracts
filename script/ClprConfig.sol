// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title ClprConfig
/// @notice Default initial values for ClprService LedgerConfiguration and EconomicConfig.
/// @dev Values mirror the test defaults so deployed contracts behave identically to
///      what the test suite exercises. Operators can override individual fields via
///      env vars in `script/deploy/cli.ts`.
library ClprConfig {
    function defaultThrottles() internal pure returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }

    /// @dev Amounts are in wei. A service with a fee token counts them in the token's base units and needs its own.
    function defaultEconomicConfig() internal pure returns (ClprTypes.EconomicConfig memory) {
        return ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            maxChannels: 0,
            maxConnectors: 0,
            connectorPaymentGasLimit: 200_000
        });
    }

    function emptySeedEndpoints() internal pure returns (ClprTypes.Endpoint[] memory) {
        return new ClprTypes.Endpoint[](0);
    }
}
