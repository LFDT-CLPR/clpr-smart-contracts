# Vite → Hiero

Status: blocked. Vite has no BFT finality (each snapshot block carries one producer signature),
no state root (only account-chain heads and log hashes), no proof RPC, and no public RPC answered
on 2026-10-01.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Vite mainnet (no EVM chain id; no CAIP-2 namespace registered) |
| Chain type | L1, DAG of per-account chains plus a snapshot chain produced by Snapshot Block Producers (SBP) |
| Finality source | Confirmation count only (`ConfirmedTimes = latest height − height + 1`); no quorum certificate |
| Signature scheme | Ed25519 with BLAKE2b-512 in place of SHA-512 (`crypto/ed25519`), over the 32-byte BLAKE2b-256 snapshot hash |
| Producer set | 25 per round (23 top-voted + 2 random from ranks ≤ 100), 3 blocks each, 1 s interval: 75-block rounds. Votes weighted by VITE balances |
| State commitment | Snapshot block commits only to each account chain's head `(address, hash, height)`. Account blocks (v2) have no state hash; they commit `LogHash` |
| Verifier | none |
| Trust tier | — |
| Typical bundle / rotation | — |

## Classification

**(c) Blocked.**

1. **No live data source.** `buidl.vite.net` (the endpoint in `vitelabs/vite-docs` `a1ab1f7`) and
   `node-tokyo.vite.net` do not resolve; `node.vite.net` points to a load balancer with no
   addresses. `ledger_getLatestSnapshotBlock` could not be called, so liveness is unverified.
2. **No BFT finality.** One SBP signs each snapshot block. Confidence comes only from later blocks.
3. **Producer set not provable.** The round's SBP list follows from vote balances that no signed
   root covers, so a verifier must be given the list by a trusted party.
4. **No state proofs.** There is no state trie per account block in v2.9.0 and no proof RPC
   (`rpcapi/api/ledger*.go` offers `getVmLogs`, `getAccountBlocksByHeightRange`). The docs' "Merkle
   root of contract state" does not match the code.

What would unblock it: a confirmed live archive node, plus an accepted trusted updater for the
per-round SBP list (which in practice makes this the attestor family). A native verifier would need
Vite to add a quorum certificate and a state commitment.

## Possible design if unblocked (not built)

- Queue as a Solidity++ contract on Vite's asynchronous VM that emits one log per state change.
- Proof: snapshot block (BLAKE2b-256 hash, Ed25519-BLAKE2b signature) → SnapshotContent entry for the
  contract's account chain → hash chain of account blocks down to the block with the log →
  `LogHash = BLAKE2b(topics ‖ data ‖ addr ‖ prevHash)` preimage.
- "Finality" heuristic: require blocks from more than 2/3 of the round's distinct SBPs built on top:
  17 signatures over ~49 linked blocks.
- Gas estimate (not measured): Ed25519 with a BLAKE2b challenge ~600k per signature (BLAKE2F
  precompile for the hash; extrapolated from the measured 640k SHA-512 Ed25519): 17 × 600k ≈ 10.2M,
  plus ~49 BLAKE2b header hashes (~0.3M) and the account-chain and log path. About 11M gas,
  10–20 KB. Fits, but tight, and still trusts the SBP list.

## Evidence

Source: `vitelabs/go-vite` v2.9.0 (`b0ae1dbd`): `interfaces/core/snapshot_block.go` (hash fields:
PrevHash, height, timestamp, seed, seedHash, SnapshotContent items, fork name and version),
`interfaces/core/account_block.go`, `interfaces/core/vm_log_list.go`, `crypto/hash.go`,
`crypto/ed25519/README.md`, `common/config/genesis_json.go` (consensus group 1: NodeCount 25,
Interval 1, PerCount 3, RandCount 2, RandRank 100), `ledger/consensus/core/vote_algo.go`.
Docs: docs.vite.org (RPC/IPC, snapshot chain pages).

## Deployment profile

Not defined.

## Relayer requirements

A Vite full node with `ledger_*` RPC. None public was reachable.

## Chain-specific trust and caveats

Even with a verifier, Vite → Hiero would trust the source of the SBP list and a confirmation-depth
heuristic, not a BFT quorum.

## Live verification

None possible (no reachable RPC on 2026-10-01).

## Hiero → Vite

Not built. Vite's VM has no BLS12-381 or BN254 precompiles documented; not checked further.
