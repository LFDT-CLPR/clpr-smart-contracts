import path from "node:path";
import {NETWORKS} from "../../relay/buildAvalancheLiveProof.js";
import {describeWarpLive} from "./avalancheLiveSuite.js";

/// AvalancheWarpVerifier on real Flare data: Coston2 and Flare mainnet. The Warp signatures were
/// aggregated by our own ava-labs/icm-services signature-aggregator, which requested ACP-118
/// signatures from the Flare validators over p2p (src/verifiers/evm/avalanche/README.md, "Flare live
/// test"). Re-capture: `npm run flare-live:refresh`. See avalancheLiveSuite.ts for the cases.
describeWarpLive({
    fixture: path.join(NETWORKS.coston2.fixtureDir, "capture.json"),
    networkId: 114,
    sourceChainId: "0x78db5c30bed04c05ce209179812850bbb3fe6d46d7eef3744d814c0da5552479",
    anvilPort: Number(process.env.CLPR_ANVIL_PORT_A ?? 8611)
});

describeWarpLive({
    fixture: path.join(NETWORKS.flare.fixtureDir, "capture.json"),
    networkId: 14,
    sourceChainId: "0x77d3074dc510f43b09ac5be77edee276ef3b55f0097d504846aa8eec613fc625",
    anvilPort: Number(process.env.CLPR_ANVIL_PORT_B ?? 8612)
});
