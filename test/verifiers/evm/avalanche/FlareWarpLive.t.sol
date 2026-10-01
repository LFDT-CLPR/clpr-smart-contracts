// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AvalancheWarpLiveTest} from "./AvalancheWarpLive.t.sol";

/// @dev The same live suite as AvalancheWarpLiveTest, replayed on Flare data
///      (test/e2e/fixtures/flare-live/, written by `npm run flare-live:refresh`). The Warp signatures
///      were aggregated by our own ava-labs/icm-services signature-aggregator, which requested ACP-118
///      signatures from the Flare validators over p2p. Weights are checked with exact P-Chain values;
///      Flare mainnet's total stake exceeds uint64.
contract FlareWarpLiveCoston2Test is AvalancheWarpLiveTest {
    function _vectorsPath() internal pure override returns (string memory) {
        return "test/e2e/fixtures/flare-live/coston2/vectors.json";
    }
}

contract FlareWarpLiveMainnetTest is AvalancheWarpLiveTest {
    function _vectorsPath() internal pure override returns (string memory) {
        return "test/e2e/fixtures/flare-live/flare/vectors.json";
    }
}
