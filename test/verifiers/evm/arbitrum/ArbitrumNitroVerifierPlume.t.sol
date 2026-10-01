// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ArbitrumNitroVerifierLiveTest} from "./ArbitrumNitroVerifier.t.sol";

/// @notice The whole ArbitrumNitroVerifier live suite (real BLS light client, every negative case) on
///         the Plume mainnet profile: Ethereum mainnet sync committee → Plume's RollupProxy
///         0x4eD3…6eE8 → a confirmed BoLD assertion → Plume L2 header → WPLUME storage.
///         Fixture: test/verifiers/evm/arbitrum/fixtures/plume-live.json, generated from
///         test/e2e/fixtures/plume-live/capture.json by
///         `npx tsx test/e2e/relay/buildArbitrumLiveProof.ts --network plume [--refresh]`.
contract ArbitrumNitroVerifierPlumeLiveTest is ArbitrumNitroVerifierLiveTest {
    function _fixture() internal pure override returns (string memory) {
        return "/test/verifiers/evm/arbitrum/fixtures/plume-live.json";
    }
}
