import {PLUME_MAINNET} from "../../relay/buildArbitrumLiveProof.js";
import {arbitrumLiveSuite} from "./arbitrumLiveSuite.js";

/// ArbitrumNitroVerifier, Plume profile, on live Plume mainnet data settled on Ethereum mainnet
/// (test/e2e/fixtures/plume-live/capture.json): Ethereum's sync committee → Plume's RollupProxy → a
/// confirmed BoLD assertion → Plume L2 header → WPLUME storage, plus a real sync-committee rotation.
/// Run: forge build && npm run test:e2e:plume-live
arbitrumLiveSuite(PLUME_MAINNET, Number(process.env.CLPR_ANVIL_PORT_B ?? 8618));
