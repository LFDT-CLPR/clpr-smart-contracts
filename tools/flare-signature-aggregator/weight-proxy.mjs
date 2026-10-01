// JSON-RPC proxy in front of a Flare node's public API for Ava Labs' signature-aggregator.
// avalanchego v1.15 parses P-Chain weights as uint64; Flare mainnet's total stake (2.2e19 nFLR)
// overflows it. This proxy divides every P-Chain weight in validator-set replies by SCALE so the
// aggregator's quorum bookkeeping fits in uint64. Relative weights are kept to within 1 unit in
// 10^15, and the resulting aggregate is re-checked with exact big-integer weights offline.
// Everything else (info.*, other platform.* calls) is forwarded unchanged.
import http from "node:http";
const [, , upstream, portArg, scaleArg] = process.argv;
const PORT = Number(portArg ?? 18482);
const SCALE = BigInt(scaleArg ?? 16);
const SCALED = new Set(["platform.getAllValidatorsAt", "platform.getValidatorsAt", "platform.getCurrentValidators"]);
const scale = (o) => {
    if (Array.isArray(o)) return o.forEach(scale);
    if (o && typeof o === "object") {
        for (const [k, v] of Object.entries(o)) {
            if ((k === "weight" || k === "totalWeight") && typeof v === "string" && /^\d+$/.test(v)) {
                o[k] = (BigInt(v) / SCALE).toString();
            } else scale(v);
        }
    }
};
http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    let method = "";
    try { method = JSON.parse(body.toString()).method ?? ""; } catch {}
    try {
        const r = await fetch(upstream + req.url, {method: req.method, headers: {"content-type": "application/json"},
            body: req.method === "GET" ? undefined : body});
        let text = await r.text();
        if (SCALED.has(method)) {
            const j = JSON.parse(text);
            scale(j.result);
            text = JSON.stringify(j);
        }
        res.writeHead(r.status, {"content-type": "application/json"});
        res.end(text);
    } catch (e) {
        res.writeHead(502); res.end(String(e));
    }
}).listen(PORT, "127.0.0.1", () => console.log(`weight-proxy ${upstream} on :${PORT}, scale 1/${SCALE}`));
