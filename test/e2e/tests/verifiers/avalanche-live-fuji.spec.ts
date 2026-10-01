import {AVALANCHE_LIVE_FIXTURE} from "../../relay/buildAvalancheLiveProof.js";
import {describeWarpLive} from "./avalancheLiveSuite.js";

/// AvalancheWarpVerifier on real Fuji data (public Ava Labs aggregator). See avalancheLiveSuite.ts.
describeWarpLive({
    fixture: AVALANCHE_LIVE_FIXTURE,
    networkId: 5,
    sourceChainId: "0x7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5",
    anvilPort: Number(process.env.CLPR_ANVIL_PORT_A ?? 8611)
});
