#!/usr/bin/env python3
"""Generates src/libraries/crypto/ClprSha512t256Hasher.sol: SHA-512/256 as hand-scheduled EVM bytecode.

Why bytecode: Stacks MARF proofs hash ~17 KB Node256 nodes (≈133 SHA-512 compressions each). The Yul
library (Sha512t256.sol) costs ≈49k gas per compression because via-IR cannot keep the eight working
variables on the stack, and a fully unrolled Yul version made solc use more than 10 GB. Here the 80
rounds and the message schedule are unrolled with the working variables on the EVM stack (their roles
rotate symbolically, so a round only replaces `d` and `h`), round constants are PUSH8 immediates and
every schedule address is a constant.

Calling convention: STATICCALL with the raw message as calldata; returns the 32-byte digest.
Memory: W[80] at 0x0000, H[8] at 0x0A00, the padded message from 0x0B00.

EVM operand order reminder: for SUB/SHL/SHR/MSTORE/… the FIRST operand is the stack top.
"""
import os

K = """428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817""".split()
IV = "22312194fc2bf72c 9f555fa3c84c64c2 2393b86b6f53b151 963877195940eabd 96283ee2a88effe3 be5e1e2553863992 2b0199fc2c85b8aa 0eb72ddc81c52ca2".split()
W_BASE, H_BASE, MSG = 0x0000, 0x0A00, 0x0B00
M64 = (1 << 64) - 1

OPS = dict(ADD=0x01, SUB=0x03, LT=0x10, AND=0x16, OR=0x17, XOR=0x18, SHL=0x1b, SHR=0x1c, CALLDATASIZE=0x36,
           CALLDATACOPY=0x37, POP=0x50, MLOAD=0x51, MSTORE=0x52, MSTORE8=0x53, JUMP=0x56, JUMPI=0x57,
           JUMPDEST=0x5b, RETURN=0xf3)
# (pops, pushes)
ARITY = dict(ADD=(2, 1), SUB=(2, 1), LT=(2, 1), AND=(2, 1), OR=(2, 1), XOR=(2, 1), SHL=(2, 1), SHR=(2, 1),
             CALLDATASIZE=(0, 1), CALLDATACOPY=(3, 0), POP=(1, 0), MLOAD=(1, 1), MSTORE=(2, 0), MSTORE8=(2, 0),
             JUMP=(1, 0), JUMPI=(2, 0), JUMPDEST=(0, 0), RETURN=(2, 0))


class Asm:
    def __init__(self):
        self.code = bytearray()
        self.st = []  # symbolic stack, top = last
        self.fix = []
        self.labels = {}

    def op(self, name, out="_"):
        self.code.append(OPS[name])
        pops, pushes = ARITY[name]
        for _ in range(pops):
            self.st.pop()
        if pushes:
            self.st.append(out)

    def push(self, v, out="_"):
        n = max(1, (v.bit_length() + 7) // 8)
        self.code.append(0x5f + n)
        self.code += v.to_bytes(n, "big")
        self.st.append(out)

    def push_label(self, label):
        self.code.append(0x61)
        self.fix.append((len(self.code), label))
        self.code += b"\0\0"
        self.st.append("lbl")

    def label(self, name):
        self.labels[name] = len(self.code)
        self.op("JUMPDEST")

    def depth(self, name):
        for i in range(len(self.st) - 1, -1, -1):
            if self.st[i] == name:
                return len(self.st) - 1 - i
        raise KeyError((name, self.st))

    def dup(self, name, out=None):
        d = self.depth(name)
        assert d < 16, (name, self.st)
        self.code.append(0x80 + d)
        self.st.append(out or name + "'")

    def swap(self, d):
        assert 1 <= d <= 16, d
        self.code.append(0x8f + d)
        self.st[-1], self.st[-1 - d] = self.st[-1 - d], self.st[-1]

    def name_top(self, n):
        self.st[-1] = n

    def drop(self, name):
        """Remove `name` from the stack (swap it to the top, then POP)."""
        d = self.depth(name)
        if d:
            self.swap(d)
        self.op("POP")

    def replace(self, target):
        """Move the top value into `target`'s slot, dropping `target`. The top keeps its new name."""
        d = self.depth(target)
        self.swap(d)
        self.op("POP")

    def bytes(self):
        for pos, lbl in self.fix:
            self.code[pos:pos + 2] = self.labels[lbl].to_bytes(2, "big")
        return bytes(self.code)


def shr_of(a, src, n, out):  # out = src >> n
    a.dup(src); a.push(n); a.op("SHR", out)


def doubled(a, src, out):  # out = src | (src << 64)
    a.dup(src); a.dup(src); a.push(64); a.op("SHL"); a.op("OR", out)


def big_sigma(a, src, r, out):
    doubled(a, src, "xx")
    shr_of(a, "xx", r[0], "s1")
    shr_of(a, "xx", r[1], "s2")
    a.op("XOR", "s12")
    a.swap(1)  # xx on top
    a.push(r[2]); a.op("SHR", "s3")
    a.op("XOR", out)


def small_sigma(a, addr, r, s, out):
    a.push(addr); a.op("MLOAD", "w")
    doubled(a, "w", "xx")
    shr_of(a, "xx", r[0], "s1")
    a.swap(1); a.push(r[1]); a.op("SHR", "s2")  # consumes xx
    a.op("XOR", "s12")
    a.swap(1)  # w on top
    a.push(s); a.op("SHR", "s3")
    a.op("XOR", out)


def gen():
    a = Asm()
    # ── padding: copy the message, append 0x80, OR the bit length into the last word ──
    a.op("CALLDATASIZE", "len")
    a.dup("len"); a.push(0); a.push(MSG); a.op("CALLDATACOPY")
    a.push(0x80); a.dup("len"); a.push(MSG); a.op("ADD"); a.op("MSTORE8")
    a.dup("len"); a.push(144); a.op("ADD"); a.push(7); a.op("SHR"); a.push(7); a.op("SHL")
    a.push(MSG); a.op("ADD", "end")  # end of the padded message
    a.push(32); a.dup("end"); a.op("SUB", "la")  # la = end - 32
    a.dup("len"); a.push(3); a.op("SHL")  # len*8
    a.dup("la"); a.op("MLOAD"); a.op("OR", "lw")
    a.swap(1)  # la on top
    a.op("MSTORE")
    a.drop("len")
    for i, v in enumerate(IV):
        a.push(int(v, 16)); a.push(H_BASE + 32 * i); a.op("MSTORE")
    a.push(MSG, "p")
    a.label("block")
    # ── message schedule (W[i] at W_BASE + 32 i) ──
    for i in range(16):
        a.dup("p"); a.push(8 * i); a.op("ADD"); a.op("MLOAD"); a.push(192); a.op("SHR")
        a.push(W_BASE + 32 * i); a.op("MSTORE")
    for i in range(16, 80):
        small_sigma(a, W_BASE + 32 * (i - 15), (1, 8), 7, "sg0")
        small_sigma(a, W_BASE + 32 * (i - 2), (19, 61), 6, "sg1")
        a.op("ADD")
        a.push(W_BASE + 32 * (i - 7)); a.op("MLOAD"); a.op("ADD")
        a.push(W_BASE + 32 * (i - 16)); a.op("MLOAD"); a.op("ADD")
        a.push(M64); a.op("AND")
        a.push(W_BASE + 32 * i); a.op("MSTORE")
    # ── working variables a..h from H ──
    names = ["a", "b", "c", "d", "e", "f", "g", "h"]
    for i, n in enumerate(names):
        a.push(H_BASE + 32 * i); a.op("MLOAD", n)
    for i in range(80):
        A, B, C, D, E, F, G, Hh = names
        # T1 = h + Σ1(e) + Ch(e,f,g) + W[i] + K[i]
        big_sigma(a, E, (14, 18, 41), "S1")
        a.dup(Hh); a.op("ADD", "t")
        a.dup(G); a.dup(F); a.dup(G); a.op("XOR"); a.dup(E); a.op("AND"); a.op("XOR", "ch")
        a.op("ADD", "t")
        a.push(W_BASE + 32 * i); a.op("MLOAD"); a.op("ADD")
        a.push(int(K[i], 16)); a.op("ADD", "T1")
        # e' = (d + T1) mod 2^64 → d's slot
        a.dup("T1"); a.dup(D); a.op("ADD"); a.push(M64); a.op("AND", "nE")
        a.replace(D)
        # a' = (T1 + Σ0(a) + Maj(a,b,c)) mod 2^64 → h's slot
        big_sigma(a, A, (28, 34, 39), "S0")
        a.dup(A); a.dup(B); a.op("OR"); a.dup(C); a.op("AND"); a.dup(A); a.dup(B); a.op("AND"); a.op("OR", "maj")
        a.op("ADD")
        a.op("ADD")
        a.push(M64); a.op("AND", "nA")
        a.replace(Hh)
        ren = {"a": "b", "b": "c", "c": "d", "e": "f", "f": "g", "g": "h", "nA": "a", "nE": "e"}
        a.st = [ren.get(x, x) for x in a.st]
        assert sorted(x for x in a.st if x in names) == names and len(a.st) == 10, a.st
    # ── H_i = (H_i + v_i) mod 2^64 ──
    while a.st[-1] in names:
        i = names.index(a.st[-1])
        a.push(H_BASE + 32 * i); a.op("MLOAD"); a.op("ADD"); a.push(M64); a.op("AND")
        a.push(H_BASE + 32 * i); a.op("MSTORE")
    assert a.st == ["end", "p"], a.st
    # ── next block ──
    a.push(128); a.op("ADD", "p")
    a.dup("end"); a.dup("p"); a.op("LT")  # p < end
    a.push_label("block"); a.op("JUMPI")
    # ── digest = H0 ‖ H1 ‖ H2 ‖ H3 ──
    a.push(H_BASE); a.op("MLOAD"); a.push(192); a.op("SHL")
    a.push(H_BASE + 32); a.op("MLOAD"); a.push(128); a.op("SHL"); a.op("OR")
    a.push(H_BASE + 64); a.op("MLOAD"); a.push(64); a.op("SHL"); a.op("OR")
    a.push(H_BASE + 96); a.op("MLOAD"); a.op("OR")
    a.push(0); a.op("MSTORE")
    a.push(32); a.push(0); a.op("RETURN")
    return a.bytes()


SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprSha512t256Hasher
/// @notice SHA-512/256 as a stand-alone contract: STATICCALL it with the message as calldata and it
///         returns the 32-byte digest. Its runtime is hand-scheduled EVM bytecode generated by
///         script/gen/gen_sha512_evm.py (edit the generator): the 80 rounds and the message schedule are
///         unrolled with the working variables on the stack, about {gas} gas per 128-byte block —
///         {ratio}x cheaper than the Yul library {{Sha512t256}}, which it is tested against.
/// @dev Runtime: {size} bytes. Deploy once per network and pass its address to the verifiers.
contract ClprSha512t256Hasher {{
    constructor() {{
        bytes memory runtime =
            hex"{hex}";
        assembly ("memory-safe") {{
            return(add(runtime, 0x20), mload(runtime))
        }}
    }}
}}

/// @title Sha512t256Call
/// @notice Calls a {{ClprSha512t256Hasher}}.
library Sha512t256Call {{
    error Sha512HasherFailed();

    function hash(address hasher, bytes memory data) internal view returns (bytes32 out) {{
        bool ok;
        assembly ("memory-safe") {{
            ok := staticcall(gas(), hasher, add(data, 0x20), mload(data), 0x00, 0x20)
            out := mload(0x00)
        }}
        if (!ok || hasher.code.length == 0) revert Sha512HasherFailed();
    }}
}}
"""

if __name__ == "__main__":
    import sys
    code = gen()
    gas = sys.argv[1] if len(sys.argv) > 1 else "?"
    ratio = sys.argv[2] if len(sys.argv) > 2 else "?"
    root = os.path.join(os.path.dirname(__file__), "..", "..", "src", "libraries", "crypto")
    open(os.path.join(root, "ClprSha512t256Hasher.sol"), "w").write(
        SOL.format(hex=code.hex(), size=len(code), gas=gas, ratio=ratio))
    print("runtime bytes", len(code))
