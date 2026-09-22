import {encodeAbiParameters, getAddress, keccak256, type Hex} from "viem";
import {rlpDecode} from "./rlp.js";

/// The set commitment the anchor stores: keccak256(abi.encode(address[] sortedUniqueMembers)).
/// Must match QbftValidators.commit over the sorted, deduped set.
export function setCommitment(validators: Hex[]): Hex {
    const sorted = [...new Set(validators.map((v) => getAddress(v)))]
        .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
    return keccak256(encodeAbiParameters([{type: "address[]"}], [sorted]));
}

/// ABI-encode the 4-word header-mode trust anchor stored in Channel.trustAnchor. Must match
/// QbftHeaderModeVerifier._decodeTrustAnchor:
/// abi.encode(uint8 mode = 0, bytes32 setCommitment, bytes32 codeHash, uint64 anchorBlockNumber).
export function encodeTrustAnchor(validators: Hex[], codeHash: Hex, anchorBlockNumber: bigint): Hex {
    return encodeAbiParameters(
        [{type: "uint8"}, {type: "bytes32"}, {type: "bytes32"}, {type: "uint64"}],
        [0, setCommitment(validators), codeHash, anchorBlockNumber]
    ) as Hex;
}

/// The validator list a QBFT header carries in extraData (item 1 of
/// [vanity, validators[], vote, round, committedSeals[]]).
export function headerValidators(headerRlp: Uint8Array): Hex[] {
    const header = rlpDecode(headerRlp) as Uint8Array[];
    const extra = rlpDecode(header[12] as Uint8Array) as unknown[];
    const validators = extra[1] as Uint8Array[];
    return validators.map((v) => getAddress(("0x" + Buffer.from(v).toString("hex")) as Hex));
}

let _rpcId = 0;

export async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[] = []): Promise<T> {
    const body = JSON.stringify({jsonrpc: "2.0", method, params, id: ++_rpcId});
    const res = await fetch(rpcUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body
    });
    const json = (await res.json()) as {result?: T; error?: {message: string}};
    if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
    return json.result as T;
}

export async function waitForBlock(rpcUrl: string, minBlock = 1, timeoutMs = 60_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            const latest = await rpcCall<string>(rpcUrl, "eth_blockNumber");
            if (parseInt(latest, 16) >= minBlock) return;
        } catch {
            // node not ready yet
        }
        await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`chain at ${rpcUrl} did not reach block ${minBlock} within ${timeoutMs}ms`);
}
