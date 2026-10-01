/// Capture a live XRPL fixture: the UNL, >= quorum full validations of one validated ledger, that
/// ledger's header and every tx+meta in it (to rebuild the tx tree), a memo-carrying AccountSet or
/// Payment (tesSUCCESS) to prove, the parent header chain, and a SHAMap state proof of the memo
/// sender's AccountRoot fetched over the peer protocol.
///
/// Usage: tsx test/e2e/relay/captureXrplLive.ts [mainnet|testnet] [--account <r-address>]
/// Writes test/e2e/fixtures/xrpl-live/<network>.json. Public endpoints only, no keys.
import WebSocket from "ws";
import {writeFileSync, mkdirSync} from "node:fs";
import path from "node:path";
import {walk, top, ledgerHash, parseHeader, txId, sha512Half} from "./xrplCodec.js";
import {XrplPeer, fetchStateProof, xrplBase58Decode, xrplBase58} from "./xrplPeer.js";

const NETS = {
    mainnet: {ws: "wss://xrplcluster.com", rpc: "https://xrplcluster.com", vl: "https://vl.ripple.com", peer: "r.ripple.com", networkId: 0},
    testnet: {
        ws: "wss://s.altnet.rippletest.net:51233",
        rpc: "https://s.altnet.rippletest.net:51234",
        vl: "https://vl.altnet.rippletest.net",
        peer: "s.altnet.rippletest.net",
        networkId: 1
    }
} as const;

const network = (process.argv[2] ?? "mainnet") as keyof typeof NETS;
const accountArg = process.argv.indexOf("--account");
/// Optional classic address whose AccountRoot to prove (default: the memo transaction's sender).
const stateAccount = accountArg > 0 ? xrplBase58Decode(process.argv[accountArg + 1]).subarray(1) : undefined;
const net = NETS[network];

async function rpc(method: string, params: object): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(net.rpc, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({method, params: [params]})});
            const j = (await r.json()) as any;
            if (j.result?.status === "error") throw new Error(`${method}: ${j.result.error}`);
            return j.result;
        } catch (e) {
            if (attempt >= 4) throw e;
            await new Promise((r) => setTimeout(r, 1500));
        }
    }
}

type UnlEntry = {master: string; signing: string; seq: number; manifest: string};

function decodeManifest(m: Buffer): UnlEntry {
    const fs = walk(m);
    const master = top(fs, 7, 1)!.value; // sfPublicKey
    const signing = top(fs, 7, 3)!.value; // sfSigningPubKey
    const seq = top(fs, 2, 4)!.value.readUInt32BE(0); // sfSequence
    return {master: master.toString("hex"), signing: signing.toString("hex"), seq, manifest: m.toString("hex")};
}

async function loadUnl(): Promise<{entries: UnlEntry[]; vlSequence: number}> {
    const vl = (await (await fetch(net.vl)).json()) as any;
    const blob = JSON.parse(Buffer.from(vl.blob, "base64").toString());
    const entries: UnlEntry[] = [];
    for (const v of blob.validators) {
        let man = Buffer.from(v.manifest, "base64");
        // Prefer the latest manifest the network knows (a validator may have rotated its key).
        try {
            const r = await rpc("manifest", {public_key: xrplNodePublic(Buffer.from(v.validation_public_key, "hex"))});
            if (r.manifest) {
                const latest = Buffer.from(r.manifest, "base64");
                if (decodeManifest(latest).seq > decodeManifest(man).seq) man = latest;
            }
        } catch {
            /* keep the list's manifest */
        }
        entries.push(decodeManifest(man));
    }
    return {entries, vlSequence: blob.sequence};
}

const xrplNodePublic = (pk: Buffer) => xrplBase58(Buffer.concat([Buffer.from([28]), pk]));

function memoCandidate(tx: Buffer, meta: Buffer): boolean {
    const fs = walk(tx);
    const type = top(fs, 1, 2)?.value.readUInt16BE(0);
    if (type !== 0 && type !== 3) return false; // Payment or AccountSet
    if (!fs.some((f) => f.depth === 0 && f.type === 15 && f.field === 9)) return false; // Memos
    if (!top(fs, 2, 4) || top(fs, 2, 4)!.value.readUInt32BE(0) === 0) return false; // Sequence-numbered
    if (fs.some((f) => f.depth === 0 && f.type === 18)) return false; // no Paths
    return meta.subarray(meta.length - 3).equals(Buffer.from([0x03, 0x10, 0x00])); // tesSUCCESS
}

async function main() {
    const unl = await loadUnl();
    const signingSet = new Set(unl.entries.map((e) => e.signing));
    const quorum = Math.ceil(unl.entries.length * 0.8);
    console.log(`${network}: UNL ${unl.entries.length} validators (vl seq ${unl.vlSequence}), quorum ${quorum}`);

    const vals = new Map<string, Map<string, string>>(); // ledgerHash -> signingKey -> data
    const ws = new WebSocket(net.ws);
    await new Promise((r) => ws.once("open", r));
    ws.send(JSON.stringify({command: "subscribe", streams: ["validations", "ledger"]}));
    const closed: {hash: string; index: number}[] = [];
    ws.on("message", (raw) => {
        const j = JSON.parse(raw.toString());
        if (j.type === "validationReceived" && j.data) {
            const data = Buffer.from(j.data, "hex");
            const fs = walk(data);
            const spk = top(fs, 7, 3)!.value.toString("hex");
            const flags = top(fs, 2, 2)!.value.readUInt32BE(0);
            if (!signingSet.has(spk) || !(flags & 1)) return;
            const lh = top(fs, 5, 1)!.value.toString("hex").toUpperCase();
            if (!vals.has(lh)) vals.set(lh, new Map());
            vals.get(lh)!.set(spk, j.data);
        } else if (j.type === "ledgerClosed") {
            closed.push({hash: j.ledger_hash, index: j.ledger_index});
        }
    });

    const deadline = Date.now() + 10 * 60_000;
    while (Date.now() < deadline) {
        const c = closed.shift();
        if (!c) {
            await new Promise((r) => setTimeout(r, 500));
            continue;
        }
        const L = (await rpc("ledger", {ledger_hash: c.hash, transactions: true, expand: true, binary: true})).ledger;
        const txs = (L.transactions as any[]).map((t) => ({tx: Buffer.from(t.tx_blob, "hex"), meta: Buffer.from(t.meta, "hex")}));
        const pick = txs.findIndex((t) => memoCandidate(t.tx, t.meta));
        if (pick < 0) continue;
        // wait for a quorum of UNL validations of this ledger
        const until = Date.now() + 30_000;
        while ((vals.get(c.hash)?.size ?? 0) < quorum && Date.now() < until) await new Promise((r) => setTimeout(r, 300));
        const got = vals.get(c.hash);
        if (!got || got.size < quorum) {
            console.log(`ledger ${c.index}: only ${got?.size ?? 0} UNL validations, next`);
            continue;
        }
        await new Promise((r) => setTimeout(r, 4000)); // late validations
        const header = Buffer.from(L.ledger_data, "hex");
        if (!ledgerHash(header).equals(Buffer.from(c.hash, "hex"))) throw new Error("header hash mismatch");
        const hdr = parseHeader(header);
        // two parent headers for the header-chain proof
        const parents: string[] = [];
        let ph = hdr.parentHash;
        for (let k = 0; k < 2; k++) {
            const P = (await rpc("ledger", {ledger_hash: ph.toString("hex"), binary: true})).ledger;
            const pb = Buffer.from(P.ledger_data, "hex");
            if (!ledgerHash(pb).equals(ph)) throw new Error("parent hash mismatch");
            parents.push(pb.toString("hex"));
            ph = parseHeader(pb).parentHash;
        }
        const chosen = txs[pick];
        const sender = top(walk(chosen.tx), 8, 1)!.value;
        const stateOf = stateAccount ?? sender;
        const acctKey = sha512Half(Buffer.concat([Buffer.from([0, 0x61]), stateOf]));
        const peer = new XrplPeer(net.peer, 51235, net.networkId || undefined);
        await peer.connect();
        const sp = await fetchStateProof(peer, Buffer.from(c.hash, "hex"), hdr.accountHash, acctKey);
        peer.close();
        ws.close();
        const out = {
            network,
            networkId: net.networkId,
            capturedAt: new Date().toISOString(),
            sources: {ws: net.ws, rpc: net.rpc, vl: net.vl, peer: `${net.peer}:51235`},
            unl: {vlSequence: unl.vlSequence, quorum, entries: unl.entries},
            ledger: {index: hdr.seq, hash: c.hash, header: header.toString("hex"), parents},
            validations: [...got.entries()].map(([signing, data]) => ({signing, data})),
            txs: txs.map((t) => ({tx: t.tx.toString("hex"), meta: t.meta.toString("hex")})),
            memoTx: {index: pick, id: txId(chosen.tx).toString("hex").toUpperCase(), sender: sender.toString("hex")},
            accountState: {account: stateOf.toString("hex"), key: acctKey.toString("hex"), inners: sp.inners.map((k) => Buffer.concat(k).toString("hex")), leaf: sp.leafData.toString("hex")}
        };
        const dir = path.join(import.meta.dirname, "..", "fixtures", "xrpl-live");
        mkdirSync(dir, {recursive: true});
        writeFileSync(path.join(dir, `${network}.json`), JSON.stringify(out, null, 1) + "\n");
        console.log(
            `ledger ${hdr.seq}: ${got.size}/${unl.entries.length} validations, ${txs.length} txs, memo tx ${out.memoTx.id}, state depth ${sp.inners.length}`
        );
        process.exit(0);
    }
    throw new Error("no suitable ledger within 10 minutes");
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
