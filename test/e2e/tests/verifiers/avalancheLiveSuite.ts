import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    keccak256,
    toHex,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {bls12_381} from "@noble/curves/bls12-381";
import {
    attest,
    buildAvalancheLiveProof,
    canonicalSet,
    encodeTrustAnchor,
    loadLiveCapture,
    reencodeBundle,
    validatorSetDigest,
    type AvalancheLiveProof,
    type LiveCapture
} from "../../relay/buildAvalancheLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";

/// AvalancheWarpVerifier against REAL Warp data, replayed offline from a capture.json. Shared by
/// avalanche-live-fuji.spec.ts (Fuji, public aggregator) and flare-live.spec.ts (Coston2 and Flare
/// mainnet, our own signature-aggregator). Re-capture: `npm run avalanche-live:refresh`,
/// `npm run flare-live:refresh`.
///
/// Real inputs: the C-Chain header (hash re-derived from coreth's RLP layout), the Primary Network
/// validator set at two P-Chain heights (a real set change between them), the validators' Warp
/// BitSetSignature over the block hash (ACP-118, aggregated at the newer height) and eth_getProof for
/// WAVAX at the same block. No ClprService exists on Fuji, so the channel slots are MPT exclusion
/// proofs (zeroed metadata). The only synthetic input is the rotation attestation, which the verifier
/// trusts by design (test attestor keys, 2-of-3).
///
/// Run: forge build && npm run test:e2e:avalanche-live (or test:e2e:flare-live)

export interface LiveSuite {
    fixture: string;
    networkId: number;
    sourceChainId: Hex;
    anvilPort: number;
}

const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VERIFIER = "AvalancheWarpVerifier";

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

/// Overwrite `anchor[off..off+bytes.length)`.
function patchAnchor(anchor: Hex, off: number, bytes: Buffer): Hex {
    const a = hexToBuf(anchor);
    bytes.copy(a, off);
    return ("0x" + a.toString("hex")) as Hex;
}

export function describeWarpLive(s: LiveSuite): void {
describe(`AvalancheWarpVerifier on live ${s.fixture.split("/").slice(-2, -1)[0]} data (fixture replay)`, () => {
    const ANVIL_PORT = s.anvilPort;
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    let capture: LiveCapture;
    let live: AvalancheLiveProof;
    const art = loadArtifact(VERIFIER);

    function verifyBundle(proofBytes: Hex, trustAnchor: Hex, channelContext: Hex = live.channelContext) {
        return pub.readContract({
            address: verifier,
            abi: art.abi as never,
            functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        }) as Promise<[{state: number; nextMessageId: bigint; receivedMessageId: bigint;
            sentRunningHash: Hex; receivedRunningHash: Hex}, Hex[], Hex, Hex, unknown]>;
    }

    async function measure(proofBytes: Hex, trustAnchor: Hex): Promise<{gas: bigint; calldata: number; calldataGas: number}> {
        const args = [proofBytes, trustAnchor, live.channelContext];
        const gas = await pub.estimateContractGas({
            address: verifier, abi: art.abi as never, functionName: "verifyBundle", args, account: wallet.account!
        });
        const cd = hexToBuf(encodeFunctionData({abi: art.abi, functionName: "verifyBundle", args} as never));
        return {gas, calldata: cd.length, calldataGas: cd.reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0)};
    }

    beforeAll(async () => {
        capture = loadLiveCapture(s.fixture);
        live = await buildAvalancheLiveProof(capture);

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--hardfork", "prague"], {stdio: "ignore"});
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
            abi: art.abi as never, bytecode: art.bytecode, args: [], account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        verifier = r.contractAddress;
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("builder: live inputs are consistent (C-Chain id, canonical set, ≥67% signed)", () => {
        expect(capture.networkId).toBe(s.networkId);
        expect(live.sourceChainId).toBe(s.sourceChainId);
        expect(byteLen(live.trustAnchor)).toBe(220);
        expect(live.meta.signedWeightBps).toBeGreaterThanOrEqual(6700);
        expect(live.set.height).toBeGreaterThan(live.previousSet.height);
        expect(live.set.setHash).not.toBe(live.previousSet.setHash);
    });

    it("verifyBundle succeeds on the real header, Warp signature and account proof", async () => {
        const [metadata, payloads, newAnchor, newAnchorId] = await verifyBundle(live.proofBytes, live.trustAnchor);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(newAnchor).toBe("0x");
        expect(newAnchorId).toBe("0x");
        const m = await measure(live.proofBytes, live.trustAnchor);
        console.log(
            `[avalanche-live] ${live.meta.network} block ${live.meta.blockNumber}: ${live.meta.signers}/${live.meta.validators} ` +
            `signers (${live.meta.signedWeightBps / 100}% stake) | verifyBundle eth_estimateGas ${m.gas} = 21000 base + ` +
            `${m.calldataGas} calldata + ~${m.gas - 21000n - BigInt(m.calldataGas)} execution | proofBytes ` +
            `${byteLen(live.proofBytes)} B, calldata ${m.calldata} B`
        );
    });

    it("real validator-set rotation: P-Chain @previous → @current, then the bundle verifies under the new set", async () => {
        const [, , newAnchor, newAnchorId] = await verifyBundle(live.rotationProofBytes, live.previousTrustAnchor);
        expect(newAnchor).toBe(live.trustAnchor);
        expect(BigInt(newAnchorId)).toBe(live.set.height);
        const m = await measure(live.rotationProofBytes, live.previousTrustAnchor);
        console.log(
            `[avalanche-live] rotation @${live.previousSet.height} (${live.meta.previousValidators} keys) → ` +
            `@${live.set.height} (${live.meta.validators} keys): eth_estimateGas ${m.gas}, calldata ${m.calldata} B`
        );
    });

    it("rejects a replayed rotation (P-Chain height not newer than the anchor)", async () => {
        await expect(verifyBundle(live.rotationProofBytes, live.trustAnchor)).rejects.toThrow(/RotationNotNewer/);
    });

    it("rejects a rotation with fewer attestations than the threshold", async () => {
        const digest = validatorSetDigest(live.networkId, hexToBuf(live.sourceChainId), live.set.height,
            live.set.timestamp, live.set.setHash, live.set.totalWeight);
        const rot = [...live.parts.rotation];
        rot[5] = await attest(digest, 1);
        const proof = reencodeBundle(live.parts, {rotationItem: rot});
        await expect(verifyBundle(proof, live.previousTrustAnchor)).rejects.toThrow(/InsufficientAttestations/);
    });

    it("the real signature under the previous set: rejected if keys changed, accepted on a weight-only change", async () => {
        // Previous set with a window wide enough that only the signature check can fail.
        const anchor = patchAnchor(live.previousTrustAnchor, 180, Buffer.from("00000000ffffffff", "hex"));
        const proof = reencodeBundle(live.parts, {validatorSet: live.parts.previousValidatorSet});
        const keysOf = (p: Buffer) => Buffer.concat([...Array(p.length / 104).keys()].map((i) => p.subarray(i * 104, i * 104 + 96)));
        if (keysOf(live.parts.previousValidatorSet).equals(keysOf(live.parts.validatorSet))) {
            // Flare's set changes with every delegation. Same keys → the bit set names the same
            // signers, and they still hold ≥67% of the previous weights: accepting is correct.
            await verifyBundle(proof, anchor);
        } else {
            await expect(verifyBundle(proof, anchor))
                .rejects.toThrow(/BlsSignatureInvalid|InsufficientSignedWeight|InvalidSignerBitSet/);
        }
    });

    it("rejects the real signature under a set where one signer's key was replaced", async () => {
        // Swap the first signer's BLS key for an unrelated one, rebuild the canonical set and an anchor
        // that commits to it: the bit set now selects a different aggregate key.
        const v = structuredClone(capture.set.validators);
        const signerKey = canonicalSet(v).keys[[...Array(8 * live.parts.warpSignature[0].length).keys()]
            .find((i) => (BigInt("0x" + live.parts.warpSignature[0].toString("hex")) >> BigInt(i)) & 1n)!];
        const victim = Object.values(v).find((x) => x.publicKey &&
            bls12_381.G1.ProjectivePoint.fromHex(x.publicKey.replace(/^0x/, "")).equals(signerKey))!;
        victim.publicKey = "0x" + Buffer.from(bls12_381.getPublicKey(bls12_381.utils.randomPrivateKey())).toString("hex");
        const forged = canonicalSet(v);
        const a = hexToBuf(live.trustAnchor);
        const anchor = encodeTrustAnchor({
            networkId: a.readUInt32BE(0), sourceChainId: a.subarray(4, 36), channelId: live.channelId,
            codeHash: live.codeHash, setHash: keccak256(forged.packed), totalWeight: forged.totalWeight,
            pChainHeight: live.set.height, pChainTimestamp: live.set.timestamp, maxSetAge: live.maxSetAge,
            attestorsHash: ("0x" + a.subarray(188, 220).toString("hex")) as Hex
        });
        const proof = reencodeBundle(live.parts, {validatorSet: forged.packed});
        await expect(verifyBundle(proof, anchor))
            .rejects.toThrow(/BlsSignatureInvalid|InsufficientSignedWeight|InvalidSignerBitSet/);
    });

    it("rejects a validator set the anchor does not commit to", async () => {
        const proof = reencodeBundle(live.parts, {validatorSet: live.parts.previousValidatorSet});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/ValidatorSetMismatch/);
    });

    it("rejects a tampered signature", async () => {
        const sig = Buffer.from(live.parts.warpSignature[1]);
        sig[255] ^= 1;
        const proof = reencodeBundle(live.parts, {warpSignature: [live.parts.warpSignature[0], sig]});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    it("rejects a dropped signer (stake falls below 67% or the aggregate no longer matches)", async () => {
        const bits = Buffer.from(live.parts.warpSignature[0]);
        const last = bits.length - 1;
        const firstSet = [...Array(8 * bits.length).keys()].find((i) => (bits[last - (i >> 3)] >> (i & 7)) & 1)!;
        bits[last - (firstSet >> 3)] &= ~(1 << (firstSet & 7));
        const proof = reencodeBundle(live.parts, {warpSignature: [bits, live.parts.warpSignature[1]]});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/InsufficientSignedWeight|BlsSignatureInvalid/);
    });

    it("rejects a header whose state root was swapped (block hash no longer signed)", async () => {
        const h = Buffer.from(live.parts.header);
        const sr = h.indexOf(hexToBuf(capture.block.stateRoot));
        h[sr] ^= 1;
        const proof = reencodeBundle(live.parts, {header: h});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/BlsSignatureInvalid/);
    });

    it("rejects the block once the validator set is older than maxSetAge (stale set)", async () => {
        const anchor = patchAnchor(live.trustAnchor, 180, Buffer.from("0000000000000001", "hex"));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/ValidatorSetExpired/);
    });

    it("fails only at the codeHash binding when another (e.g. ClprService) code hash is pinned", async () => {
        const anchor = patchAnchor(live.trustAnchor, 68, hexToBuf(keccak256(toHex("other-runtime-code"))));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects a Warp signature from another network id", async () => {
        const anchor = patchAnchor(live.trustAnchor, 0, Buffer.from("00000001", "hex"));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/BlsSignatureInvalid/);
    });
});
}
