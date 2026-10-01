#!/usr/bin/env python3
"""Offline check that Osmosis serves standard ICS-23 proofs for CosmWasm contract storage.

Fetches `abci_query /store/wasm/key?prove=true` for the key `0x03 || contract(32 B) || subkey` at
height H, recomputes the IAVL root and the multistore root (store "wasm"), and compares the result
with the `app_hash` of header H+1. These are the same two proof steps `CosmWasmVerifier` runs on
Hedera (ICS-23 IAVL spec, then the Tendermint simple-Merkle spec).

Usage: python3 script/hard51/osmosis_wasm_proof_check.py <osmo1 contract> [height] [subkey]
Default subkey: contract_info (the cw2 Item every cw2 contract writes).
Standard library only. Public RPC: https://osmosis-rpc.polkachu.com (override with OSMOSIS_RPC).
"""

import base64
import hashlib
import json
import os
import sys
import urllib.request

RPC = os.environ.get("OSMOSIS_RPC", "https://osmosis-rpc.polkachu.com")
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "clpr-probe"})
    return json.load(urllib.request.urlopen(req, timeout=30))


def bech32_payload(addr):
    data = addr.rsplit("1", 1)[1][:-6]
    acc, bits, out = 0, 0, []
    for c in data:
        acc = (acc << 5) | CHARSET.index(c)
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def read_varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def varint(n):
    out = b""
    while True:
        x, n = n & 0x7F, n >> 7
        if n:
            out += bytes([x | 0x80])
        else:
            return out + bytes([x])


def fields(b):
    """Minimal protobuf decoder: list of (field number, value)."""
    i, out = 0, []
    while i < len(b):
        key, i = read_varint(b, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = read_varint(b, i)
        elif wt == 2:
            n, i = read_varint(b, i)
            v, i = b[i : i + n], i + n
        else:
            raise ValueError(f"unexpected wire type {wt}")
        out.append((num, v))
    return out


def sha256(x):
    return hashlib.sha256(x).digest()


def existence_root(proof):
    """ICS-23 ExistenceProof -> root. Checks the leaf op is the IAVL/Tendermint shape."""
    f = fields(proof)
    key = next(v for n, v in f if n == 1)
    value = next(v for n, v in f if n == 2)
    leaf = dict(fields(next(v for n, v in f if n == 3)))
    # LeafOp: hash=SHA256, prehash_key=NO_HASH, prehash_value=SHA256, length=VAR_PROTO
    assert leaf.get(1) == 1 and leaf.get(2, 0) == 0 and leaf.get(3) == 1 and leaf.get(4) == 1, leaf
    h = sha256(leaf.get(5, b"") + varint(len(key)) + key + varint(32) + sha256(value))
    for n, v in f:
        if n == 4:  # InnerOp: hash, prefix, suffix
            op = dict(fields(v))
            assert op.get(1) == 1
            h = sha256(op.get(2, b"") + h + op.get(3, b""))
    return key, value, h


def main():
    contract = sys.argv[1]
    height = int(sys.argv[2]) if len(sys.argv) > 2 else int(
        get(f"{RPC}/status")["result"]["sync_info"]["latest_block_height"]) - 10
    subkey = (sys.argv[3] if len(sys.argv) > 3 else "contract_info").encode()
    key = b"\x03" + bech32_payload(contract) + subkey
    url = f"{RPC}/abci_query?path=%22/store/wasm/key%22&data=0x{key.hex()}&height={height}&prove=true"
    resp = get(url)["result"]["response"]
    ops = resp["proofOps"]["ops"]
    print("height", height, "proof ops", [o["type"] for o in ops])
    iavl = dict(fields(base64.b64decode(ops[0]["data"])))
    assert 1 in iavl, "expected an existence proof"
    k, _, store_root = existence_root(iavl[1])
    assert k == key
    simple = dict(fields(base64.b64decode(ops[1]["data"])))
    name, value, app_hash = existence_root(simple[1])
    assert name == b"wasm" and value == store_root
    header = get(f"{RPC}/commit?height={height + 1}")["result"]["signed_header"]["header"]
    print("computed app_hash ", app_hash.hex().upper())
    print("header H+1 app_hash", header["app_hash"])
    ok = app_hash.hex().upper() == header["app_hash"]
    print("MATCH" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
