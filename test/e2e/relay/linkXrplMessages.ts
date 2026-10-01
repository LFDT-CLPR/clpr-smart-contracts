/// Link the XRPL outbox message fixture (messages.json, recorded by tools/xrpl-clpr-emitter on
/// branch feat/xrpl-design without validations) to a UNL-validated testnet ledger captured later
/// (testnet.json): fetch the binary headers of the message ledgers and, over the peer protocol, the
/// validated ledger's LedgerHashes skip list (keylet::skip(), the last 256 ledger hashes) with its
/// SHAMap path. The verifier then proves each message ledger from the validated one.
///
/// Usage: tsx test/e2e/relay/linkXrplMessages.ts   (run right after captureXrplLive.ts testnet,
/// while the message ledgers are still within 256 ledgers of the captured one)
import {readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {ledgerHash, parseHeader, sha512Half} from "./xrplCodec.js";
import {XrplPeer, fetchStateProof} from "./xrplPeer.js";

const dir = path.join(import.meta.dirname, "..", "fixtures", "xrpl-live");
const RPC = "https://s.altnet.rippletest.net:51234";
const SKIP_KEY = sha512Half(Buffer.from([0, 0x73]));

async function rpc(method: string, params: object): Promise<any> {
    const r = await fetch(RPC, {method: "POST", body: JSON.stringify({method, params: [params]})});
    return ((await r.json()) as any).result;
}

const cap = JSON.parse(readFileSync(path.join(dir, "testnet.json"), "utf8"));
const msgs = JSON.parse(readFileSync(path.join(dir, "messages.json"), "utf8"));
const headers: Record<string, string> = {};
for (const [seq, l] of Object.entries<any>(msgs.ledgers)) {
    const L = (await rpc("ledger", {ledger_index: Number(seq), binary: true})).ledger;
    const h = Buffer.from(L.ledger_data, "hex");
    if (!ledgerHash(h).equals(Buffer.from(l.ledger_hash, "hex"))) throw new Error(`header ${seq} mismatch`);
    headers[seq] = h.toString("hex");
}
const hdr = parseHeader(Buffer.from(cap.ledger.header, "hex"));
const peer = new XrplPeer("s.altnet.rippletest.net", 51235, 1);
await peer.connect();
const sp = await fetchStateProof(peer, Buffer.from(cap.ledger.hash, "hex"), hdr.accountHash, SKIP_KEY);
peer.close();
cap.messageLink = {
    messages: "messages.json",
    headers,
    skipList: {key: SKIP_KEY.toString("hex"), inners: sp.inners.map((k) => Buffer.concat(k).toString("hex")), leaf: sp.leafData.toString("hex")}
};
writeFileSync(path.join(dir, "testnet.json"), JSON.stringify(cap, null, 1) + "\n");
console.log(`linked ${Object.keys(headers).length} message ledgers via skip list (depth ${sp.inners.length}, ${sp.leafData.length} B) at ${hdr.seq}`);
