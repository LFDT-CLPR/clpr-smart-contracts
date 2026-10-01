// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @dev Test helper for the live XRPL spec: encodes the LedgerConfiguration control message a
///      channel opener supplies (XRPL publishes none; see XrplVerifier.verifyConfig).
contract XrplLiveHarness {
    function controlMessage(string calldata chainId, bytes calldata serviceAddress, uint96 nanos)
        external
        pure
        returns (bytes memory)
    {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = serviceAddress;
        lc.nanosSinceEpoch = nanos;
        lc.throttles = ClprTypes.Throttles(10, 800, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }
}
