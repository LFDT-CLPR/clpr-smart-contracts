import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
    concat,
    createPublicClient,
    createWalletClient,
    encodePacked,
    http,
    keccak256,
    toHex,
    type Address,
    type Hex,
    type PublicClient,
    type TypedDataDomain,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {CantonLedger, T} from "../../relay/cantonLedger.js";
import {
    buildHieroBundle,
    CantonOperator,
    encodeBundle,
    encodeTrustAnchor,
    nextRunningHash,
    operatorSetView,
    packSignatures,
    readChannel,
    readQueueHead,
    readRules,
    runningHashChain,
    UnverifiedHieroProofChecker,
    verifierDomain,
    ZERO32,
    type ChannelPayload,
    type OperatorSetView
} from "../../relay/cantonRelay.js";

/// Canton <-> Hiero end to end, release-today trust model (t-of-n CLPR operators):
///   Canton sandbox (Daml SDK 3.5, JSON Ledger API v2)  <-- operator relay -->  anvil (CantonAttestedVerifier)
///
/// Needs a running Canton with the JSON Ledger API reachable at CANTON_JSON_API
/// (test/e2e/backend/canton/start-canton.sh) and `dpm build --all` in daml/clpr. Skipped otherwise.
/// Run: npm run test:e2e:canton

const CANTON = process.env.CANTON_JSON_API;
const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8611);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DAR = path.join(REPO_ROOT, "daml", "clpr", "main", ".daml", "dist", "clpr-0.1.0.dar");
const CANTON_CHAIN_ID = "canton:sandbox";

const opKey = (i: number): Hex => keccak256(toHex(`canton-e2e-operator-${i}`));
const strip = (h: Hex) => h.slice(2).toLowerCase();

function varint(n: number): Hex {
    const out: number[] = [];
    do {
        out.push((n & 0x7f) | (n >= 0x80 ? 0x80 : 0));
        n = Math.floor(n / 128);
    } while (n > 0);
    return toHex(Uint8Array.from(out));
}

/// Canonical protobuf of ClprMessagePayload{message: ClprMessage{...}}, written independently of
/// the Daml encoder so the on-ledger bytes are cross-checked.
function dataMessage(connector: Hex, target: Hex, sender: Hex, data: Hex): Hex {
    const len = (v: Hex) => (v.length - 2) / 2;
    const field = (n: number, v: Hex): Hex => (len(v) === 0 ? "0x" : concat([varint(n * 8 + 2), varint(len(v)), v]));
    const inner = concat([field(1, connector), field(2, target), field(3, sender), field(4, data)]);
    return concat(["0x0a", varint(len(inner)), inner]);
}

describe.skipIf(!CANTON)("Canton <-> Hiero with CantonAttestedVerifier (t-of-n CLPR operators)", () => {
    const ledger = new CantonLedger(CANTON ?? "");
    const verifierArt = loadArtifact("CantonAttestedVerifier");
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Address;
    let domain: TypedDataDomain;

    let clpr: string;
    let alice: string;
    const parties: string[] = []; // op1..op4
    const ops: CantonOperator[] = [];
    let rulesCid: string;
    let set0: OperatorSetView;
    let channelIdHex: string;
    let channelCtx: Hex;
    let anchor0: Hex;
    const gas: Record<string, bigint> = {};

    const asOp = (i: number) => ops[i - 1];
    const confirmAndRun = async (signers: number[], action: unknown) => {
        const cids: string[] = [];
        for (const i of signers) {
            const evs = await ledger.exercise(parties[i - 1], [clpr], T.rules, rulesCid, "ClprRules_Confirm", {
                confirmer: parties[i - 1],
                action
            });
            cids.push(evs[0].contractId);
        }
        return cids;
    };

    async function verifyBundle(proof: Hex, trustAnchor: Hex) {
        return (await pub.readContract({
            address: verifier,
            abi: verifierArt.abi as never,
            functionName: "verifyBundle",
            args: [proof, trustAnchor, channelCtx]
        })) as [
            {nextMessageId: bigint; sentRunningHash: Hex; receivedMessageId: bigint; receivedRunningHash: Hex; state: number},
            Hex[],
            Hex,
            Hex,
            {version: bigint}
        ];
    }

    async function measure(label: string, proof: Hex, trustAnchor: Hex) {
        gas[label] = await pub.estimateContractGas({
            address: verifier,
            abi: verifierArt.abi as never,
            functionName: "verifyBundle",
            args: [proof, trustAnchor, channelCtx]
        });
    }

    async function send(data: Hex) {
        const chan = await readChannel(ledger, clpr, channelIdHex);
        const req = await ledger.create(alice, T.sendRequest, {
            sender: alice,
            clpr,
            channelId: channelIdHex,
            connectorId: strip(keccak256(toHex("canton-connector"))),
            targetApplication: strip("0x00000000000000000000000000000000000c1a55"),
            messageData: strip(data)
        });
        await ledger.exercise(parties[1], [clpr], T.rules, rulesCid, "ClprRules_Enqueue", {
            executor: parties[1],
            requestCid: req,
            channelCid: chan.contractId
        });
    }

    beforeAll(async () => {
        expect(await ledger.version()).toMatch(/^3\./);
        await ledger.uploadDar(readFileSync(DAR));
        const run = Date.now().toString(36);
        clpr = await ledger.allocateParty(`clpr-${run}`);
        alice = await ledger.allocateParty(`alice-${run}`);
        for (let i = 1; i <= 4; i++) parties.push(await ledger.allocateParty(`op${i}-${run}`));
        for (let i = 1; i <= 4; i++) ops.push(new CantonOperator(parties[i - 1], opKey(i), ledger, clpr));

        // 2-of-3 operator set (op1..op3), epoch 0.
        rulesCid = await ledger.create(clpr, T.rules, {
            clpr,
            operators: parties.slice(0, 3),
            attestationKeys: ops.slice(0, 3).map((o) => strip(o.address)),
            threshold: "2",
            epoch: "0"
        });
        set0 = operatorSetView((await readRules(ledger, clpr)).payload);

        // Open the channel with a quorum (spec running hash, ADR 2026-08-01).
        channelIdHex = strip(keccak256(toHex(`canton-e2e-channel-${run}`)));
        const open = {
            channelId: channelIdHex,
            peerChainId: "hedera:localnet",
            hashScheme: "SpecDirect",
            endpointManifestVersion: "1"
        };
        const cids = await confirmAndRun([1, 2], {tag: "OpenChannel", value: open});
        await ledger.exercise(parties[0], [clpr], T.rules, rulesCid, "ClprRules_OpenChannel", {
            executor: parties[0],
            confirmationCids: cids,
            ...open
        });

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 15_000;
        for (;;) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        const hash = await wallet.deployContract({
            abi: verifierArt.abi as never,
            bytecode: verifierArt.bytecode,
            args: [
                {cantonParty: set0.cantonParty, epoch: 0n, threshold: set0.threshold, operators: set0.operators},
                CANTON_CHAIN_ID
            ],
            account: wallet.account!,
            chain: null
        });
        verifier = (await pub.waitForTransactionReceipt({hash})).contractAddress!;
        domain = verifierDomain(await pub.getChainId(), verifier);
        channelCtx = encodePacked(["bytes32", "bytes"], [`0x${channelIdHex}`, toHex(clpr)]);
        anchor0 = encodeTrustAnchor(set0);
    }, 300_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (Object.keys(gas).length) console.log("CantonAttestedVerifier gas (eth_estimateGas):", gas);
    });

    it("Canton: enqueues messages with the spec running hash computed on-ledger", async () => {
        for (const d of ["0x01", "0x0202", toHex("hello hiero")] as Hex[]) await send(d);
        const head = await readQueueHead(ledger, clpr, channelIdHex, 0n);
        expect(head.head.messageId).toBe(3n);
        expect(head.payloads).toHaveLength(3);
        // Recomputed off-ledger with SHA-256(prev || payload) - spec §4.1.
        expect(head.head.runningHash).toBe(runningHashChain("SpecDirect", ZERO32, head.payloads));
        // The payload is the canonical ClprMessagePayload with the Canton party as sender.
        expect(head.payloads[2]).toBe(
            dataMessage(
                keccak256(toHex("canton-connector")),
                "0x00000000000000000000000000000000000c1a55",
                toHex(alice),
                toHex("hello hiero")
            )
        );
    });

    it("Canton -> Hiero: t operators attest the queue head and CantonAttestedVerifier accepts it on anvil", async () => {
        const {proof, attested} = await buildHieroBundle([asOp(1), asOp(3)], domain, set0, channelIdHex, 0n);
        const [meta, payloads, newAnchor] = await verifyBundle(proof, anchor0);
        expect(meta.nextMessageId).toBe(4n);
        expect(meta.sentRunningHash).toBe(attested.head.runningHash);
        expect(meta.state).toBe(1); // ACTIVE
        expect(payloads).toEqual(attested.payloads);
        expect(newAnchor).toBe("0x");
        await measure("bundle 2-of-3, 3 msgs", proof, anchor0);
    });

    it("Canton -> Hiero: rejects one signature, a non-operator signer and a tampered payload", async () => {
        const head = await readQueueHead(ledger, clpr, channelIdHex, 0n);
        const s1 = await asOp(1).signHead(domain, set0, head);
        await expect(verifyBundle(encodeBundle(head, [], packSignatures([s1])), anchor0)).rejects.toThrow();

        // op4 is not in the epoch-0 set: its signature recovers to an unknown address.
        const s4raw = await asOp(4).account.signTypedData({
            domain,
            types: (await import("../../relay/cantonRelay.js")).EIP712_TYPES,
            primaryType: "QueueHead",
            message: {cantonParty: set0.cantonParty, epoch: 0n, ...head.head, payloads: head.payloads, manifest: "0x"}
        });
        await expect(
            verifyBundle(encodeBundle(head, [], packSignatures([s1, {index: 2, sig: s4raw}])), anchor0)
        ).rejects.toThrow();

        const s2 = await asOp(2).signHead(domain, set0, head);
        const tampered = {...head, payloads: [...head.payloads.slice(0, 2), "0x0a00" as Hex]};
        await expect(verifyBundle(encodeBundle(tampered, [], packSignatures([s1, s2])), anchor0)).rejects.toThrow();
    });

    it("operator-set rotation: quorum-signed on Canton and on Hiero; the old set is then refused", async () => {
        // Canton: op1..op3 (2-of-3) -> op2..op4 (2-of-3), epoch 0 -> 1.
        const newParties = parties.slice(1, 4);
        const newKeys = ops.slice(1, 4).map((o) => strip(o.address));
        const rot = {newOperators: newParties, newAttestationKeys: newKeys, newThreshold: "2"};
        const cids = await confirmAndRun([1, 3], {tag: "RotateOperators", value: rot});
        const evs = await ledger.exercise(parties[0], [clpr], T.rules, rulesCid, "ClprRules_RotateOperators", {
            executor: parties[0],
            confirmationCids: cids,
            ...rot
        });
        rulesCid = evs.find((e) => e.templateId.endsWith(":Clpr.Rules:ClprRules"))!.contractId;
        const set1 = operatorSetView((await readRules(ledger, clpr)).payload);
        expect(set1.epoch).toBe(1n);

        // Hiero: the old quorum signs the rotation, the new quorum signs the head.
        const rs = await Promise.all([asOp(1), asOp(2)].map((o) => o.signRotation(domain, set0, 2, set1.operators)));
        const rotation = {newThreshold: 2, newOperators: set1.operators, signatures: packSignatures(rs)};
        await send(toHex("after rotation"));
        const {proof} = await buildHieroBundle([asOp(3), asOp(4)], domain, set1, channelIdHex, 3n, [rotation]);
        const [meta, payloads, newAnchor, newAnchorId] = await verifyBundle(proof, anchor0);
        expect(meta.nextMessageId).toBe(5n);
        expect(payloads).toHaveLength(1);
        expect(newAnchor).toBe(encodeTrustAnchor(set1));
        expect(newAnchorId).toBe("0x0000000000000001");
        await measure("bundle 2-of-3 + 1 rotation, 1 msg", proof, anchor0);

        // Against the advanced anchor, epoch-0 signatures (op1 + op2) are refused...
        const head = await readQueueHead(ledger, clpr, channelIdHex, 3n);
        const old = await Promise.all([asOp(1), asOp(2)].map((o) => o.signHead(domain, set0, head)));
        await expect(verifyBundle(encodeBundle(head, [], packSignatures(old)), newAnchor)).rejects.toThrow();
        // ...and the new set alone works without re-sending the rotation.
        const fresh = await buildHieroBundle([asOp(2), asOp(4)], domain, set1, channelIdHex, 3n);
        await verifyBundle(fresh.proof, newAnchor);
    });

    it("Hiero -> Canton: operators confirm an inbound message and it is delivered at t (Hiero proof check stubbed)", async () => {
        const chan = async () => (await readChannel(ledger, clpr, channelIdHex)) as {contractId: string; payload: ChannelPayload};
        const checker = new UnverifiedHieroProofChecker(async () => `0x${(await chan()).payload.receivedRunningHash}` as Hex, "SpecDirect");
        const payload = dataMessage(keccak256(toHex("hiero-connector")), toHex(alice), "0x0000000000000000000000000000000000000abc", toHex("ping from hiero"));
        const msg = {
            channelId: `0x${channelIdHex}` as Hex,
            messageId: 1n,
            payload,
            runningHashAfter: nextRunningHash("SpecDirect", ZERO32, payload),
            peerReceivedMessageId: 4n
        };

        // A message whose running hash does not chain is refused by the checker.
        await expect(asOp(2).confirmInbound(rulesCid, checker, {...msg, runningHashAfter: ZERO32}, alice)).rejects.toThrow(
            /does not chain/
        );

        const c3 = await asOp(3).confirmInbound(rulesCid, checker, msg, alice);
        expect(c3.check.proofVerified).toBe(false); // stub: no Hiero proof source yet
        // One confirmation is below t = 2.
        await expect(asOp(3).executeInbound(rulesCid, (await chan()).contractId, [c3.confirmationCid], msg, alice)).rejects.toThrow();
        const c4 = await asOp(4).confirmInbound(rulesCid, checker, msg, alice);
        await asOp(2).executeInbound(rulesCid, (await chan()).contractId, [c3.confirmationCid, c4.confirmationCid], msg, alice);

        const ch = (await chan()).payload;
        expect(ch.receivedMessageId).toBe("1");
        expect(ch.receivedRunningHash).toBe(strip(msg.runningHashAfter));
        expect(ch.ackedMessageId).toBe("4");
        const inbound = await ledger.query<{payloadHex: string; messageId: string}>(alice, T.inbound);
        expect(inbound.map((c) => c.payload.payloadHex)).toEqual([strip(payload)]);

        // The same message cannot be delivered twice, even with a fresh quorum that skips the checker:
        // Canton itself enforces message_id == received_message_id + 1.
        const replay = await confirmAndRun([3, 4], {
            tag: "DeliverInbound",
            value: {
                channelId: channelIdHex,
                messageId: "1",
                payloadHex: strip(payload),
                runningHashAfter: strip(msg.runningHashAfter),
                peerReceivedMessageId: "4",
                recipient: alice
            }
        });
        await expect(asOp(2).executeInbound(rulesCid, (await chan()).contractId, replay, msg, alice)).rejects.toThrow(
            /received_message_id \+ 1/
        );
    });
});
