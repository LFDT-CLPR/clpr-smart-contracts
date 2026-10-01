import {AnvilNode} from "./anvil/AnvilNode.js";
import {AvalancheNode} from "./avalanche/AvalancheNode.js";
import {BesuNode} from "./besu/BesuNode.js";
import {SoloNode} from "./solo/SoloNode.js";
import {Driver} from "./Driver.js";
import {parseBackendSpec, type Backend, type BackendKind} from "./Backend.js";

export {
    Backend,
    CANONICAL_MIXED_BESU_SOLO,
    isMixedBesuSolo,
    parseBackendSpec,
    parseInfraComponents
} from "./Backend.js";

function makeNode(kind: BackendKind, slot: "a" | "b"): AnvilNode | AvalancheNode | BesuNode | SoloNode {
    if (kind === "avalanche") return new AvalancheNode(slot);
    if (kind === "besu") return new BesuNode(slot);
    if (kind === "solo") return new SoloNode(slot);
    // CLPR_ANVIL_PORT_A / CLPR_ANVIL_PORT_B let parallel checkouts avoid port clashes.
    const port = Number(process.env[`CLPR_ANVIL_PORT_${slot.toUpperCase()}`] ?? (slot === "a" ? 8545 : 8546));
    return new AnvilNode(port, slot === "a" ? 1337 : 1338);
}

export function createBackend(): Backend {
    const {kindA, kindB} = parseBackendSpec();
    return new Driver(makeNode(kindA, "a"), makeNode(kindB, "b"));
}

export function withOverrideEnvs<T>(envs: Record<string, string>, fn: () => T): T {
    const saved: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(envs)) {
        saved[k] = process.env[k];
        process.env[k] = v;
    }
    try {
        return fn();
    } finally {
        for (const k of Object.keys(envs)) {
            if (saved[k] === undefined) delete process.env[k];
            else process.env[k] = saved[k];
        }
    }
}
