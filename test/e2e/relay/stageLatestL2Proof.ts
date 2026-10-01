import {keccak256, type Hex} from "viem";
import {rpc} from "./buildEthLiveProof.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";

/// For L2 RPCs that serve `eth_getProof` only at "latest" (reth with `--rpc.eth-proof-window 0`, e.g.
/// X Layer's public dRPC endpoint): wait until block `target` is about to be the head, then keep several
/// `eth_getProof(…, "latest")` requests in flight and keep the response whose account-proof root equals
/// `target`'s state root. Returns null if none matched within `windowMs` of the target header appearing.
///
/// Measured on X Layer (1 s blocks): dRPC's "latest" lags the sequencer RPC by ~2 blocks, a request
/// takes 0.5–2 s, and sequential polling skips blocks; overlapping requests cover every block.
export interface StagedL2Proof {
    blockNumber: string;
    header: {hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex};
    proof: EthGetProofResult & {storageHash: Hex};
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function stageLatestL2Proof(url: string, account: Hex, keys: Hex[], target: bigint, opts: {
    /// Where to read headers and the head (defaults to `url`).
    headerRpc?: string;
    intervalMs?: number;
    maxInFlight?: number;
    windowMs?: number;
    log?: (s: string) => void;
} = {}): Promise<StagedL2Proof | null> {
    const log = opts.log ?? ((s: string) => console.error(s));
    const headerRpc = opts.headerRpc ?? url;
    const head = async () => BigInt(await rpc<Hex>(headerRpc, "eth_blockNumber", []).catch(() => "0x0"));
    // Coarse wait: sleep until a few blocks before the target.
    for (;;) {
        const h = await head();
        if (h > target) return null;
        if (h >= target - 3n) break;
        const gap = target - 3n - h;
        log(`head ${h}, target ${target}: ${gap} blocks to go`);
        await sleep(Math.min(Number(gap) * 800, 60_000));
    }
    const proofs: (EthGetProofResult & {storageHash: Hex})[] = [];
    let header: StagedL2Proof["header"] | null = null;
    let headerAt = 0;
    let inFlight = 0;
    let errors = 0;
    const fire = () => {
        inFlight++;
        rpc<EthGetProofResult & {storageHash: Hex}>(url, "eth_getProof", [account, keys, "latest"])
            .then((p) => proofs.push(p))
            .catch((err) => {
                if (++errors <= 5) log(`eth_getProof: ${String(err).slice(0, 100)}`);
            })
            .finally(() => inFlight--);
    };
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
        if (inFlight < (opts.maxInFlight ?? 6)) fire();
        if (!header) {
            const h = await rpc<{hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex} | null>(
                headerRpc, "eth_getBlockByNumber", ["0x" + target.toString(16), false]).catch(() => null);
            if (h) {
                header = {hash: h.hash, stateRoot: h.stateRoot, withdrawalsRoot: h.withdrawalsRoot};
                headerAt = Date.now();
            }
        }
        if (header) {
            const hit = proofs.find((p) => keccak256(p.accountProof[0] as Hex) === header!.stateRoot.toLowerCase());
            if (hit) return {blockNumber: target.toString(), header, proof: hit};
            if (Date.now() - headerAt > (opts.windowMs ?? 20_000)) break;
        }
        await sleep(opts.intervalMs ?? 200);
    }
    log(`no "latest" proof matched block ${target} (${proofs.length} proofs, ${errors} errors)`);
    return null;
}
