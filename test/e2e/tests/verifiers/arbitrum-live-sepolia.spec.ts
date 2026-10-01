import {ARBITRUM_SEPOLIA} from "../../relay/buildArbitrumLiveProof.js";
import {arbitrumLiveSuite} from "./arbitrumLiveSuite.js";

/// ArbitrumNitroVerifier on live Arbitrum Sepolia data settled on Ethereum Sepolia
/// (test/e2e/fixtures/arbitrum-live/capture.json). Run: forge build && npm run test:e2e:arbitrum-live
arbitrumLiveSuite(ARBITRUM_SEPOLIA, Number(process.env.CLPR_ANVIL_PORT_A ?? 8617));
