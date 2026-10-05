// Estimate a transaction's Hedera contract trace data and compare it with the consensus node's
// `contracts.maxSerializedTraceDataBytes` (default 262,144). See docs/hedera-trace-cap.md.
//
// Run it against any JSON-RPC endpoint that serves `debug_traceTransaction` with the `callTracer` and
// `prestateTracer` (for example an anvil fork of a Hiero network on which the transaction was rehearsed):
//
//   npm run trace:size -- <rpc url> <tx hash> [<tx hash> ...]
//   (or directly:  tsx script/trace/trace-size.ts <rpc url> <tx hash> [...])
//
// The estimate is the raw bytes Hiero records (every call frame's input and output, precompile calls
// included) plus a per-frame and per-storage-slot allowance for the protobuf fields around them. It is meant
// to be conservative, not exact. Exit code 1 if any transaction is above THRESHOLD of the limit.
//
// Environment:
//   HEDERA_TRACE_LIMIT      the cap in bytes (default 262144)
//   HEDERA_TRACE_THRESHOLD  the share of the cap that fails the check (default 0.9)

import process from "node:process";

const LIMIT = Number(process.env.HEDERA_TRACE_LIMIT ?? 262144);
const THRESHOLD = Number(process.env.HEDERA_TRACE_THRESHOLD ?? 0.9);
// Call type, caller and recipient ids, gas, gas used, depth, operation type, length prefixes.
const PER_ACTION = 96;
// Slot key, value read, value written, length prefixes.
const PER_SLOT = 112;

interface CallFrame {
    input?: string;
    output?: string;
    calls?: CallFrame[];
}

type Prestate = Record<string, {storage?: Record<string, string>}>;

const [rpc, ...hashes] = process.argv.slice(2).filter((a) => a !== "--");
if (!rpc || hashes.length === 0) {
    console.error("usage: trace-size.ts <rpc url> <tx hash> [<tx hash> ...]");
    process.exit(2);
}

async function call<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(rpc, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}),
    });
    const body = (await res.json()) as {result?: T; error?: unknown};
    if (body.error !== undefined) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result as T;
}

const hexLen = (h?: string): number => (h && h.length > 2 ? (h.length - 2) / 2 : 0);

let worst = 0;
for (const hash of hashes) {
    const root = await call<CallFrame>("debug_traceTransaction", [hash, {tracer: "callTracer"}]);
    let actions = 0;
    let raw = 0;
    const walk = (f: CallFrame): void => {
        actions++;
        raw += hexLen(f.input) + hexLen(f.output);
        for (const c of f.calls ?? []) walk(c);
    };
    walk(root);

    // Every storage slot read or written (Hiero records reads as well as writes).
    const pre = await call<Prestate>("debug_traceTransaction", [hash, {tracer: "prestateTracer"}]);
    const slots = new Set<string>();
    for (const [addr, acc] of Object.entries(pre)) {
        for (const key of Object.keys(acc.storage ?? {})) slots.add(`${addr}:${key}`);
    }

    const estimate = raw + actions * PER_ACTION + slots.size * PER_SLOT;
    worst = Math.max(worst, estimate / LIMIT);
    console.log(
        `${hash} actions ${actions}, raw ${raw} B, storage slots ${slots.size} -> ~${estimate} B ` +
            `(${((100 * estimate) / LIMIT).toFixed(1)} % of ${LIMIT})`,
    );
}
process.exit(worst > THRESHOLD ? 1 : 0);
