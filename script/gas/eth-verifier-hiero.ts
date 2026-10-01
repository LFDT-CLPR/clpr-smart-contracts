/// Measure EthMainnetVerifier.verifyBundle (recorded live Sepolia bundle) on a Hiero network.
///
///   npm run gas:eth-verifier:solo      # local Solo side B (relay :37547, mirror :39082)
///   npm run gas:eth-verifier:testnet   # Hedera testnet (chain 296), spends real testnet HBAR
///
/// Flags:
///   --network solo|testnet   target (default solo)
///   --verifier 0x...         reuse an existing EthMainnetVerifier (skips the deploy tx)
///   --env <file>             env file with CLPR_TESTNET_PRIVATE_KEY (default ~/clpr/.env)
///   --out <file>             write the JSON report (default test/e2e/fixtures/sepolia-live/hiero-gas-<network>.json)
///
/// Testnet reads CLPR_TESTNET_PRIVATE_KEY, HEDERA_TESTNET_RPC_URL, HEDERA_TESTNET_MIRROR_URL.
/// Solo funds a fresh throwaway key from the Solo ecdsa-alias funder of side B.
import {writeFileSync} from "node:fs";
import os from "node:os";
import path from "node:path";
import {config as loadEnv} from "dotenv";
import type {Hex} from "viem";
import {generatePrivateKey, privateKeyToAccount} from "viem/accounts";
import {REPO_ROOT} from "../deploy/artifacts.js";
import {
    formatMeasurement,
    measureEthVerifierOnHiero,
    type HieroTarget
} from "../../test/e2e/lib/ethVerifierOnHiero.js";

function arg(name: string): string | undefined {
    const i = process.argv.indexOf(`--${name}`);
    return i >= 0 ? process.argv[i + 1] : undefined;
}

async function soloTarget(): Promise<HieroTarget> {
    const {fundSoloSide} = await import("../../test/e2e/backend/solo/fund.js");
    const {resolveRelayUrl, resolveMirrorUrl} = await import("../../test/e2e/backend/solo/state.js");
    const rpcUrl = process.env.CLPR_SOLO_RPC ?? (await resolveRelayUrl("b"))!;
    const mirrorUrl = process.env.CLPR_SOLO_MIRROR_URL ?? (await resolveMirrorUrl("b"))!;
    const privateKey = generatePrivateKey();
    await fundSoloSide("b", privateKeyToAccount(privateKey).address);
    return {network: "solo-b", rpcUrl, mirrorUrl, privateKey};
}

function testnetTarget(): HieroTarget {
    loadEnv({path: arg("env") ?? path.join(os.homedir(), "clpr", ".env"), quiet: true});
    const pk = process.env.CLPR_TESTNET_PRIVATE_KEY;
    if (!pk) throw new Error("CLPR_TESTNET_PRIVATE_KEY missing (see --env)");
    return {
        network: "hedera-testnet",
        rpcUrl: process.env.HEDERA_TESTNET_RPC_URL ?? "https://testnet.hashio.io/api",
        mirrorUrl: process.env.HEDERA_TESTNET_MIRROR_URL ?? "https://testnet.mirrornode.hedera.com",
        privateKey: (pk.startsWith("0x") ? pk : `0x${pk}`) as Hex
    };
}

async function main() {
    const network = arg("network") ?? "solo";
    const target = network === "testnet" ? testnetTarget() : await soloTarget();
    const report = await measureEthVerifierOnHiero({target, verifier: arg("verifier") as Hex | undefined});

    if (report.deploy) console.log(formatMeasurement("deploy EthMainnetVerifier", report.deploy));
    console.log(formatMeasurement("verifyBundle", report.verify));
    console.log(`eth_call verifyBundle accepted: ${report.ethCallOk}; EIP-2537 precompiles: ${report.eip2537}`);
    if (!report.eip2537) {
        console.log("verifyBundle cannot pass here: the sync-committee BLS check needs EIP-2537 " +
            "(BlsPrecompileCallFailed). Hedera testnet (HAPI 0.77.2) has it; Solo consensus v0.74 does not.");
    }

    const out = arg("out") ??
        path.join(REPO_ROOT, "test", "e2e", "fixtures", "sepolia-live", `hiero-gas-${report.network}.json`);
    writeFileSync(out, JSON.stringify(report, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
    console.log(`report → ${path.relative(REPO_ROOT, out)}`);
    if (!report.ethCallOk || report.verify.status !== "success") process.exitCode = 1;
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
});
