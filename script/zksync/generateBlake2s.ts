/// Generates the unrolled Blake2s compression rounds and the empty-subtree table used by
/// src/verifiers/evm/zksync/ZkSyncStateTreeVerifier.sol, and splices them into that file between the
/// `<generated:…>` markers. Run after changing the layout:  npx tsx script/zksync/generateBlake2s.ts
///
/// Lane layout (see the contract's NatSpec): a state row (v[4r..4r+3]) lives in one 256-bit word, word i
/// of the row in bits [64·i, 64·i+32). Message word k is kept zero-padded in its own 32-byte memory slot
/// at M_BASE + 32·k, so `mload(M_BASE + 32·k + 8·i)` yields m[k] already placed in lane i.
import {execFileSync} from "node:child_process";
import {readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {blake2s} from "@noble/hashes/blake2.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.resolve(__dirname, "../../src/verifiers/evm/zksync/ZkSyncStateTreeVerifier.sol");
const HARNESS = path.resolve(__dirname, "../../test/verifiers/evm/zksync/Blake2sHarness.sol");

/// RFC 7693 §2.7 message schedule (Blake2s uses the first 10 rows).
export const SIGMA: number[][] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];

const M_BASE = 0x2100;
const hex = (n: number) => "0x" + n.toString(16);

/// The packed lane vector (m[ks[0]] in lane 0, … m[ks[3]] in lane 3).
function vector(ks: number[]): string {
    const loads = ks.map((k, i) => `mload(${hex(M_BASE + 32 * k + 8 * i)})`);
    return `or(or(${loads[0]}, ${loads[1]}), or(${loads[2]}, ${loads[3]}))`;
}

/// One G over all four lanes: rotations 16, 12, 8, 7 (RFC 7693 §3.1, Blake2s), each as
/// `and(shr(n, mul(x, 0x100000001)), M)` — the multiply copies each clean 32-bit lane into its upper
/// half, so a right shift by n leaves rotr32(x, n) in the low half.
function g(mx: string, my: string, lastB: string[]): string[] {
    return [
        `a := and(add(add(a, b), ${mx}), M)`,
        `d := and(shr(16, mul(xor(d, a), 0x100000001)), M)`,
        `c := and(add(c, d), M)`,
        `b := and(shr(12, mul(xor(b, c), 0x100000001)), M)`,
        `a := and(add(add(a, b), ${my}), M)`,
        `d := and(shr(8, mul(xor(d, a), 0x100000001)), M)`,
        `c := and(add(c, d), M)`,
        ...lastB
    ];
}

/// Row B's last rotation (rotr 7) merged with its lane rotation for the diagonal step: with
/// y = mul(x, 0x100000001), rotr7 is bits [7, 39) of each 64-bit lane, so shifting y by 64 ± 7 moves the
/// rotated word one lane over directly (lane 3 / lane 0 wrap through the second shift).
const B_ROTR7_INTO_DIAGONAL = [`y := mul(xor(b, c), 0x100000001)`, `b := and(or(shr(71, y), shl(185, y)), M)`];
const B_ROTR7_OUT_OF_DIAGONAL = [`y := mul(xor(b, c), 0x100000001)`, `b := and(or(shl(57, y), shr(199, y)), M)`];

export function roundsYul(indent: string): string {
    const out: string[] = [];
    SIGMA.forEach((s, r) => {
        out.push(`// round ${r}: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals`);
        out.push(...g(vector([s[0], s[2], s[4], s[6]]), vector([s[1], s[3], s[5], s[7]]), B_ROTR7_INTO_DIAGONAL));
        out.push(`c := or(shr(128, c), shl(128, c))`, `d := or(shl(64, d), shr(192, d))`);
        out.push(`// round ${r}: diagonals; then rows 1-3 rotate back`);
        out.push(...g(vector([s[8], s[10], s[12], s[14]]), vector([s[9], s[11], s[13], s[15]]), B_ROTR7_OUT_OF_DIAGONAL));
        out.push(`c := or(shr(128, c), shl(128, c))`, `d := or(shr(64, d), shl(192, d))`);
    });
    return out.map((l) => indent + l).join("\n");
}

/// Initial rows for a single final block (RFC 7693 §3.2): h = IV with h[0] ^= 0x01010020 (32-byte digest,
/// no key); v[12] ^= t (bytes hashed), v[14] ^= 0xffffffff (final block).
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
function laneConst(words: number[]): string {
    let v = 0n;
    words.forEach((w, i) => (v |= BigInt(w >>> 0) << BigInt(64 * i)));
    return "0x" + v.toString(16).padStart(64, "0");
}
export const ROW_A = laneConst([IV[0] ^ 0x01010020, IV[1], IV[2], IV[3]]);
export const ROW_B = laneConst(IV.slice(4));
export const ROW_C = laneConst(IV.slice(0, 4));
export const rowD = (t: number) => laneConst([IV[4] ^ t, IV[5], ~IV[6], IV[7]]);

/// The Yul helpers shared by ZkSyncStateTreeVerifier and its test harness.
export function helpersYul(indent: string): string {
    const lines = `/// Byte-reverse every 4-byte group: standard bytes <-> W-form.
function bswapWords(x) -> y {
    y := or(shr(8, and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)), shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)))
    y := or(shr(16, and(y, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)), shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)))
}
/// W-form word -> eight zero-padded message slots at \`base\`.
function spreadW(w, base) {
    mstore(base, shr(224, w))
    mstore(add(base, 0x20), and(shr(192, w), 0xffffffff))
    mstore(add(base, 0x40), and(shr(160, w), 0xffffffff))
    mstore(add(base, 0x60), and(shr(128, w), 0xffffffff))
    mstore(add(base, 0x80), and(shr(96, w), 0xffffffff))
    mstore(add(base, 0xa0), and(shr(64, w), 0xffffffff))
    mstore(add(base, 0xc0), and(shr(32, w), 0xffffffff))
    mstore(add(base, 0xe0), and(w, 0xffffffff))
}
/// Lane-form hash -> eight zero-padded message slots at \`base\`.
function spreadLanes(l0, l1, base) {
    mstore(base, and(l0, 0xffffffff))
    mstore(add(base, 0x20), and(shr(64, l0), 0xffffffff))
    mstore(add(base, 0x40), and(shr(128, l0), 0xffffffff))
    mstore(add(base, 0x60), shr(192, l0))
    mstore(add(base, 0x80), and(l1, 0xffffffff))
    mstore(add(base, 0xa0), and(shr(64, l1), 0xffffffff))
    mstore(add(base, 0xc0), and(shr(128, l1), 0xffffffff))
    mstore(add(base, 0xe0), shr(192, l1))
}
/// Standard 32-byte hash -> lane form.
function lanesOf(x) -> l0, l1 {
    let w := bswapWords(x)
    l0 := or(or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))), or(shl(128, and(shr(160, w), 0xffffffff)), shl(192, and(shr(128, w), 0xffffffff))))
    l1 := or(or(and(shr(96, w), 0xffffffff), shl(64, and(shr(64, w), 0xffffffff))), or(shl(128, and(shr(32, w), 0xffffffff)), shl(192, and(w, 0xffffffff))))
}
/// Lane form -> standard 32-byte hash.
function standardOf(l0, l1) -> x {
    let w := or(or(shl(224, and(l0, 0xffffffff)), shl(192, and(shr(64, l0), 0xffffffff))), or(shl(160, and(shr(128, l0), 0xffffffff)), shl(128, shr(192, l0))))
    w := or(w, or(or(shl(96, and(l1, 0xffffffff)), shl(64, and(shr(64, l1), 0xffffffff))), or(shl(32, and(shr(128, l1), 0xffffffff)), shr(192, l1))))
    x := bswapWords(w)
}
/// Blake2s final-block compression of the message in slots 0x${M_BASE.toString(16)}.. (t = 64 or 40).
function compress(t) -> o0, o1 {
    let M := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
    let a := ${ROW_A}
    let b := ${ROW_B}
    let c := ${ROW_C}
    let d := xor(${rowD(0)}, t)
    let y
${roundsYul("    ")}
    o0 := xor(xor(a, c), ${ROW_A})
    o1 := xor(xor(b, d), ${ROW_B})
}`.split("\n");
    return lines.map((l) => (l.length ? indent + l : l)).join("\n");
}

/// W-form of a 32-byte hash: each 4-byte group byte-reversed, i.e. the eight little-endian message
/// words of the hash packed big-endian.
export function toWordForm(h: Uint8Array): Buffer {
    const out = Buffer.alloc(32);
    for (let j = 0; j < 8; j++) for (let b = 0; b < 4; b++) out[4 * j + b] = h[4 * j + 3 - b];
    return out;
}

export function emptySubtreeHashes(): Uint8Array[] {
    const e: Uint8Array[] = [blake2s(new Uint8Array(40))];
    for (let d = 1; d < 256; d++) e.push(blake2s(Buffer.concat([e[d - 1], e[d - 1]])));
    return e;
}

/// Replace the body between every `// <generated:tag>` / `// </generated:tag>` pair.
function splice(src: string, tag: string, body: string): string {
    const re = new RegExp(`(// <generated:${tag}>)[\\s\\S]*?\\n([ \\t]*// </generated:${tag}>)`, "g");
    if (!re.test(src)) throw new Error(`marker ${tag} not found`);
    return src.replace(re, (_m, open: string, close: string) => `${open}\n${body}\n${close}`);
}

function main(): void {
    writeFileSync(HARNESS, splice(readFileSync(HARNESS, "utf8"), "yul-helpers", helpersYul(" ".repeat(12))));
    let src = readFileSync(TARGET, "utf8");
    src = splice(src, "yul-helpers", helpersYul(" ".repeat(12)));
    const table = emptySubtreeHashes().map((h) => toWordForm(h).toString("hex")).join("");
    const lines: string[] = [];
    for (let i = 0; i < table.length; i += 64 * 2) lines.push(`        hex"${table.slice(i, i + 128)}"`);
    src = splice(src, "empty-subtrees", "    bytes internal constant EMPTY_SUBTREE_HASHES =\n" + lines.join("\n") + ";");
    writeFileSync(TARGET, src);
    // Keep the spliced files in `forge fmt` form so the CI format check stays green.
    execFileSync("forge", ["fmt", TARGET, HARNESS], {stdio: "inherit"});
    console.log(`spliced the Yul helpers and ${table.length / 64} empty-subtree hashes into ${path.relative(process.cwd(), TARGET)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
