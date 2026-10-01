/**
 * buildZigchainLiveFixture.ts — record a live ZIGChain (zigchain-1) bundle for CosmWasmVerifier.
 *
 *   npm run zigchain-live:refresh
 *
 * Same capture as buildProvenanceLiveFixture.ts (rotation header R signed by the old set, header
 * B = R+2 signed by the new set, ABCI ICS-23 proofs from the `wasm` store at R-1 and B-1), on
 * ZIGChain. ZIGChain v5.1.2 runs upstream CometBFT v0.38.25, wasmd v0.60.9 and IAVL v1.2.8 (read
 * from the node's /cosmos/base/tendermint/v1beta1/node_info build deps), so contract storage is
 * `0x03 ‖ contract(32 B) ‖ key` in IAVL store "wasm" (wasmd x/wasm/types/keys.go).
 *
 * Contract: the cw721-base instance of code 63 (cw2 "crates.io:cw721-base" 0.20.0). Its
 * cw-storage-plus Map "tokens" holds token "1". The CLPR queue record key is absent (no CLPR
 * Service on ZIGChain), so it is proven by non-existence.
 *
 * Writes test/e2e/fixtures/zigchain-live/zigchain.json.
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {keccak256, type Hex} from "viem";
import {capture, type CosmWasmChainSpec} from "./buildProvenanceLiveFixture.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/zigchain-live");

export const ZIGCHAIN: CosmWasmChainSpec = {
    name: "zigchain",
    // Listed in ZIGChain/networks zigchain-1/rpc-nodes.txt; serves ABCI proofs from genesis (earliest height 0).
    rpc: "https://zigchain-rpc.polkachu.com",
    channelId: keccak256(new TextEncoder().encode("clpr-zigchain-live")) as Hex,
    contract: "zig1ue76v4feau5mpkh0rf9fyh0zqsps8mw5awqp2wayltaqvqlgrufswxrqjv",
    mapNamespace: "tokens",
    mapKey: "1"
};

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture(ZIGCHAIN);
    writeFileSync(path.join(FIXTURE_DIR, "zigchain.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("zigchain:", JSON.stringify(f.meta));
}
