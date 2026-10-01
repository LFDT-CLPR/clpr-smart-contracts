/// Generates tools/zkrollup/LineaPoseidon2.yul, a stand-alone contract that hashes 32-byte
/// words with Linea's state-trie hash: Poseidon2 over KoalaBear (p = 2^31 - 2^24 + 1), width 16, x^3
/// S-box, 6 full and 21 partial rounds, Merkle-Damgard with the feed-forward compression
/// `h' = m + perm(h ‖ m)[8..16]` from h = 0.
///
/// Interface: calldata = n ≥ 1 words w0..w(n-1); returns the 32-byte hash. Reverts on empty calldata or
/// a length that is not a multiple of 32.
///
/// Why a Yul object: the permutation keeps its 16 limbs at fixed memory words 0x00..0x1e0 (one PUSH per
/// access) and is fully unrolled. As inline assembly inside a Solidity contract the same code either
/// needs a base pointer on every access or 17 stack variables, which the via-IR stack evader handles
/// very slowly; the Yul optimizer also takes minutes on it. So the object is compiled here with solc
/// 0.8.30 `--strict-assembly` WITHOUT the optimizer (the code is already scheduled by hand), and the
/// creation bytecode is written to src/libraries/proof/linea/LineaPoseidon2Code.sol, which deploys it.
/// The .yul file stays outside src/ so Foundry does not compile it again. Re-running this script must
/// reproduce both files byte for byte (set SOLC to the solc 0.8.30 binary if it is not found).
///
/// Lazy reduction: every S-box is a `mulmod`, which reduces any 256-bit input, so limbs are not reduced
/// between S-boxes. Bounds: inputs are < 2^32; after an external matrix every limb is < 35·B for input
/// bound B (M4 output < 7B, plus a column sum < 28B), so after a full round limbs are < 35p < 2^37; a
/// partial round maps a bound B to < 20B (sum of 16 limbs plus at most 4B), so after 21 partial rounds
/// limbs are < 2^37 · 20^21 < 2^128. All sums fit in 256 bits. Only the 8 output limbs are reduced, by
/// the feed-forward `addmod`.
///
/// Round constants and the internal-matrix diagonal come from test/e2e/relay/linea.ts (taken from the
/// Apache-2.0 Poseidon2.sol of Consensys/linea-monorepo). The TypeScript reference is checked against
/// Linea mainnet state roots; the Foundry tests check this contract against vectors from it.
///
///   npx tsx script/zkrollup/generatePoseidon2.ts
import {execFileSync} from "node:child_process";
import {existsSync, writeFileSync} from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {FULL_ROUND_KEYS, INTERNAL_DIAG, KOALABEAR_P, PARTIAL_ROUND_KEYS} from "../../test/e2e/relay/linea.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, "../../tools/zkrollup/LineaPoseidon2.yul");
const OUT_SOL = path.resolve(__dirname, "../../src/libraries/proof/linea/LineaPoseidon2Code.sol");
const SOLC_VERSION = "0.8.30";

function findSolc(): string {
    const candidates = [
        process.env.SOLC,
        path.join(os.homedir(), "Library/Application Support/svm", SOLC_VERSION, `solc-${SOLC_VERSION}`),
        path.join(os.homedir(), ".svm", SOLC_VERSION, `solc-${SOLC_VERSION}`)
    ].filter((c): c is string => !!c);
    for (const c of candidates) if (existsSync(c)) return c;
    throw new Error(`solc ${SOLC_VERSION} not found; set SOLC (tried ${candidates.join(", ")})`);
}

const A = (i: number) => "0x" + (32 * i).toString(16);
const ld = (i: number) => `mload(${A(i)})`;
const L: string[] = [];
const emit = (indent: number, line: string) => L.push(" ".repeat(indent) + line);
const IND = 16;

/// circ(2·M4, M4, M4, M4) on the state, unreduced; with `keys`, each limb first gets its round key and
/// the S-box (a full round). Results are stored to memory.
function external(keys?: bigint[]): void {
    for (let g = 0; g < 4; g++) {
        emit(IND, "{");
        const n = ["a", "b", "c", "d"];
        for (let j = 0; j < 4; j++) {
            const i = 4 * g + j;
            if (keys) {
                emit(IND + 4, `let x${j} := add(${ld(i)}, ${keys[i]})`);
                emit(IND + 4, `let ${n[j]} := ${sbox(`x${j}`)}`);
            } else {
                emit(IND + 4, `let ${n[j]} := ${ld(i)}`);
            }
        }
        emit(IND + 4, "let t01 := add(a, b)");
        emit(IND + 4, "let t23 := add(c, d)");
        emit(IND + 4, "let t0123 := add(t01, t23)");
        emit(IND + 4, "let t01123 := add(t0123, b)");
        emit(IND + 4, "let t01233 := add(t0123, d)");
        emit(IND + 4, `mstore(${A(4 * g)}, add(t01, t01123))`);
        emit(IND + 4, `mstore(${A(4 * g + 1)}, add(add(c, c), t01123))`);
        emit(IND + 4, `mstore(${A(4 * g + 2)}, add(t23, t01233))`);
        emit(IND + 4, `mstore(${A(4 * g + 3)}, add(add(a, a), t01233))`);
        emit(IND, "}");
    }
    emit(IND, "{");
    for (let j = 0; j < 4; j++) {
        emit(IND + 4, `let t${j} := add(add(${ld(j)}, ${ld(4 + j)}), add(${ld(8 + j)}, ${ld(12 + j)}))`);
    }
    for (let i = 0; i < 16; i++) emit(IND + 4, `mstore(${A(i)}, add(${ld(i)}, t${i % 4}))`);
    emit(IND, "}");
}

/// x^3 mod p; `x` must be a variable (it is read three times).
const sbox = (x: string) => `mulmod(mulmod(${x}, ${x}, P), ${x}, P)`;

function partialRound(key: bigint): void {
    emit(IND, "{");
    emit(IND + 4, `let x := add(${ld(0)}, ${key})`);
    emit(IND + 4, `let a := ${sbox("x")}`);
    let sum = "a";
    for (let i = 1; i < 16; i++) sum = `add(${sum}, ${ld(i)})`;
    emit(IND + 4, `let sum := ${sum}`);
    for (let i = 0; i < 16; i++) {
        const d = INTERNAL_DIAG[i];
        const x = i === 0 ? "a" : ld(i);
        let term: string;
        if (d === 1n) term = x;
        else if (d === 2n) term = `shl(1, ${x})`;
        else if (d === 4n) term = `shl(2, ${x})`;
        else if (d === 3n) term = `mul(${x}, 3)`;
        else term = `mulmod(${x}, ${d}, P)`;
        emit(IND + 4, `mstore(${A(i)}, add(sum, ${term}))`);
    }
    emit(IND, "}");
}

// Load h ‖ m (16 limbs) into memory, then the permutation.
for (let i = 0; i < 8; i++) emit(IND, `mstore(${A(i)}, ${i === 0 ? "shr(224, h)" : `and(shr(${224 - 32 * i}, h), 0xffffffff)`})`);
for (let i = 0; i < 8; i++) emit(IND, `mstore(${A(8 + i)}, ${i === 0 ? "shr(224, m)" : `and(shr(${224 - 32 * i}, m), 0xffffffff)`})`);
external();
for (let r = 0; r < 3; r++) external(FULL_ROUND_KEYS[r]);
for (const k of PARTIAL_ROUND_KEYS) partialRound(k);
for (let r = 3; r < 6; r++) external(FULL_ROUND_KEYS[r]);
// Feed-forward on the rate half: out_i = (s_{8+i} + m_i) mod p.
emit(IND, `r := shl(224, addmod(${ld(8)}, shr(224, m), P))`);
for (let i = 1; i < 8; i++) {
    emit(IND, `r := or(r, shl(${224 - 32 * i}, addmod(${ld(8 + i)}, and(shr(${224 - 32 * i}, m), 0xffffffff), P)))`);
}

const P = KOALABEAR_P;
const yul = `// SPDX-License-Identifier: Apache-2.0
// GENERATED by script/zkrollup/generatePoseidon2.ts — do not edit by hand.
//
// LineaPoseidon2: Linea's state-trie hash. Poseidon2 over KoalaBear (p = 2^31 - 2^24 + 1), state width
// 16, x^3 S-box, 6 full and 21 partial rounds; a 32-byte word is 8 field elements (big-endian 32-bit
// limbs). Calldata: n >= 1 words; returns their Merkle-Damgard hash with the compression
// h' = m + perm(h || m)[8..16] (limb-wise mod p), from h = 0. Round constants and the internal-matrix
// diagonal are those of Poseidon2.sol in Consensys/linea-monorepo (Apache-2.0, ConsenSys Software Inc.);
// the permutation code is generated separately (unrolled, lazy reduction; bounds in the generator).
object "LineaPoseidon2" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let n := calldatasize()
            if or(iszero(n), and(n, 31)) { revert(0, 0) }
            let acc := 0
            for { let off := 0 } lt(off, n) { off := add(off, 32) } {
                acc := compress(acc, calldataload(off))
            }
            mstore(0, acc)
            return(0, 32)

            function compress(h, m) -> r {
${L.join("\n").replaceAll(", P)", `, ${P})`)}
            }
        }
    }
}
`;
writeFileSync(OUT, yul);
console.log(`wrote ${path.relative(process.cwd(), OUT)} (${L.length} lines)`);

const solc = findSolc();
const version = execFileSync(solc, ["--version"], {encoding: "utf8"});
if (!version.includes(`Version: ${SOLC_VERSION}`)) throw new Error(`${solc} is not solc ${SOLC_VERSION}`);
const compiled = execFileSync(solc, ["--strict-assembly", "--evm-version", "osaka", "--bin", OUT], {encoding: "utf8"});
const m = /Binary representation:\s*\n([0-9a-f]+)/.exec(compiled);
if (!m) throw new Error("no bytecode in solc output");
const creation = m[1];
const sol = `// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// GENERATED by script/zkrollup/generatePoseidon2.ts — do not edit by hand.

/// @title LineaPoseidon2Code
/// @notice Creation code of the LineaPoseidon2 hasher: Linea's state-trie hash (Poseidon2 over KoalaBear,
///         width 16, x^3 S-box, 6 full + 21 partial rounds, Merkle-Damgard with the compression
///         \`h' = m + perm(h ‖ m)[8..16]\` from 0). The deployed contract takes n >= 1 32-byte words as calldata
///         and returns their 32-byte hash; it reverts on empty calldata or a length not a multiple of 32.
/// @dev Source: tools/zkrollup/LineaPoseidon2.yul, compiled with solc ${SOLC_VERSION} \`--strict-assembly
///      --evm-version osaka\` without the optimizer. Round constants and the internal-matrix diagonal are those
///      of Poseidon2.sol in Consensys/linea-monorepo (Apache-2.0, ConsenSys Software Inc.).
library LineaPoseidon2Code {
    bytes internal constant CREATION_CODE =
        hex"${creation}";

    /// @notice Deploy a LineaPoseidon2 hasher.
    function deploy() internal returns (address hasher) {
        bytes memory code = CREATION_CODE;
        assembly ("memory-safe") {
            hasher := create(0, add(code, 0x20), mload(code))
        }
        require(hasher != address(0) && hasher.code.length != 0, "LineaPoseidon2 deploy failed");
    }
}
`;
writeFileSync(OUT_SOL, sol);
console.log(`wrote ${path.relative(process.cwd(), OUT_SOL)} (${creation.length / 2} B creation code, solc ${SOLC_VERSION})`);
