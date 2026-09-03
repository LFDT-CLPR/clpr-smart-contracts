# Ethereum Mainnet Verifier — Gas Report

Reproduce:

```shell
FOUNDRY_PROFILE=test forge test --match-path test/verifiers/evm/ethereum/EthGasReport.t.sol -vv
```

## Assumptions
To be conservative, the report assumes:
- 512/512 sync-committee participation (full)
- Account proof depth of 8 nodes (7 branches + leaf) :  Mainnet holds ~2.7 × 10⁸ accounts (levels = log₁₆(2.7e8) ≈ 7.05) - so we need ~7 branch nodes to get to the account + 1 leaf node holding account's RLP
- Storage proof depth of 4 nodes (3 branches + leaf) : Low estimation of 1000 slots (i.e. distinct channels) (log₁₆ ≈ 3) for a deployed CLPR service 
- Branch node width of 16 children (~529 B) : Mainnet's upper trie levels are dense
- No rotation or manifest

## 1. Full on-chain transaction cost

EIP-2028 charges intrinsic calldata gas (4/zero byte, 16/non-zero) **before** execution begins.
For a full on-chain transaction cost, add 21,000 (tx base) + the calldata gas. **Execution** below is the
full `submitBundle(N)` call (service dispatch + verification) — its own breakdown follows immediately after.

| Scenario | Execution | Calldata | Tx base | **Total** |
|---|---|---|---|---|
| N=1, 512/512 | 1,698,707 | 265,552 | 21,000 | **1,985,259** |
| N=10, 512/512 | 2,425,544 | 276,104 | 21,000 | **2,722,648** |
| N=1, 507/512 (~99%, typical mainnet ‡) † | ~1,800,404 | 297,052 | 21,000 | **~2,118,456** |
| N=1, 502/512 (~98%, typical mainnet ‡) † | ~1,865,225 | 328,532 | 21,000 | **~2,214,757** |
| N=1, 497/512 (~97%, typical mainnet ‡) † | ~1,927,297 | 360,012 | 21,000 | **~2,308,309** |
| N=1, 492/512 (~96%, typical mainnet ‡) † | ~1,988,949 | 391,456 | 21,000 | **~2,401,405** |
| N=1, 342/512 (2/3 floor) † | ~3,673,868 | 1,335,672 | 21,000 | **~5,030,540** |
| N=1, with rotation † | ~6,256,782 | 1,132,708 | 21,000 | **~7,410,490** |

† : approximate : The N=1 `submitBundle` execution total (1,698,707) is re-added to the
measured **execution** delta for that variant — the BLS step's own delta at that participation
versus full participation (§3, BLS total at 512/512 = 228,767):
- **+101,697** — 507/512 (§3: 330,464 − 228,767).
- **+166,518** — 502/512 (§3: 395,285 − 228,767).
- **+228,590** — 497/512 (§3: 457,357 − 228,767).
- **+290,242** — 492/512 (§3: 519,009 − 228,767).
- **+1,975,161** — the BLS step's own delta at the floor (§3: 2,203,928 at 342/512 − 228,767 at 512/512).
- **+4,558,075** — `verifyBundle`'s delta with rotation (§4 "Optional payload items": 5,984,073 − 1,425,998).

‡ : mainnet sync-committee participation has stayed above ~96% consistently.

Every † row assumes the ~272,751 gas of service overhead barely moves as participation or the payload
changes — reasonable, but unverified, hence the `~`.

The **calldata** column is a separate axis (raw bytes, priced by EIP-2028 before execution starts — no
relation to the execution deltas above): at the participation floor the 170 non-signer entries alone
are 170 × 419 bytes (pubkey + Merkle-authentication path each) ≈ 71,230 B on top of the 16,711 B
baseline proof, which is why calldata reaches 1.34M gas — comparable to the entire BLS computation it
authenticates. Rotation's 1.13M gas is the same story with a different cause: 512 **uncompressed**
128-byte G1 keys (65,536 B) plus the baseline proof and the SSZ Merkle proof for the new committee
root, 83,608 B total (§4) — the whole next committee has to be delivered, not just proofs of exclusion
for a few non-signers.

The worst realistic case (~5.0M) is a sixth of a 30M block; a rotation bundle at the floor would be worse still.

### Execution breakdown (N=1, 512/512)

`submitBundle`'s execution splits into service overhead and `verifyBundle`:

| Component | Gas | Share of execution |
|---|---|---|
| `verifyBundle` | 1,425,956 | 83.9% |
| Service overhead (`submitBundle` − verify) | 272,751 | 16.1% |
| **`submitBundle` execution total** | **1,698,707** | |

### Breakdown of a `verifyBundle` (N=1, 512/512)

| Step                                  | Gas | Share |
|---------------------------------------|---|---|
| 1 — trust-anchor reads                | 777 | 0.1% |
| — top-level RLP decode                | 20,528 | 1.5% |
| 2 — beacon header decode              | 12,563 | 0.9% |
| — beacon header SSZ root              | 8,124 | 0.6% |
| 3 — BLS sync-aggregate read           | 8,358 | 0.6% |
| — **BLS verify**                      | **228,767** | **16.5%** |
| 4 — execution SSZ branch (depth of 9) | 30,984 | 2.2% |
| 5 — channel context decode            | 1,320 | 0.1% |
| — **MPT account proof**               | **238,341** | **17.2%** |
| 6 — **MPT storage proof**             | **827,729** | **59.8%** |
| — bundle content protobuf             | 4,916 | 0.4% |
| — endpoint manifest (absent)          | 760 | 0.1% |
| 7 — rotation (absent)                 | 870 | 0.1% |
| — trust-anchor id                     | 135 | 0.0% |
| **Sum of steps**                      | **1,384,172** | |
| Real `verifyBundle` call              | 1,397,269 | |

The 13,097 gas gap is instrumentation plus external-call dispatch (~0.9%).

See §3 below for how the **BLS verify** line moves with non-signer count.

## 2. Total cost: `submitBundle(N)`
What does it cost to submit a bundle carrying N messages in one transaction

| N messages | `submitBundle` TOTAL | `verifyBundle` | Service overhead (TOTAL − verify) | Proof calldata | Calldata gas |
|---|---|---|---|---|---|
| 0 (ACK-only) | 1,399,031 | 1,291,446 | 107,585 | 14,549 B | 231,008 |
| 1 | 1,698,707 | 1,425,956 | 272,751 | 16,711 B | 265,552 |
| 2 | 1,779,293 | 1,429,879 | 349,414 | 16,785 B | 266,748 |
| 5 | 2,021,036 | 1,441,793 | 579,243 | 17,008 B | 270,292 |
| 10 | 2,425,544 | 1,461,773 | 963,771 | 17,378 B | 276,104 |

### The service overhead is verifier-independent
```
overhead(N) ≈ 195,970 + 76,780 · N        (gas)
```

> _How to obtain those values_ : 
> 
> N=1:  overhead = 272,751
> 
> N=10: overhead = 963,771
>
> Taking the linear model overhead(N) = a + b·N, we have the following system of equations:
> 
> a + b·1  = 272,751
> 
> a + b·10 = 963,771
>
> Subtract the first from the second to eliminate a:
> 
> 9b = 963,771 − 272,751 = 691,020
> 
> b  = 691,020 / 9 = **76,780**
>
> Plug back in to get a:
>
> a = 272,751 − 76,780 = 195,971  ≈ 195,970

### Correction to the underlying premise

| N | `verifyBundle` | Δ per message |
|---|---|---|
| 1 → 10 | 1,425,956 → 1,461,773 | ~3,980 |

The only N-dependence is the protobuf decode (~4k/message). 
The N=0 → N=1 step is larger (1,291,446 → 1,425,956, +134,510) because a message-bearing bundle carries a **6-entry**
storage proof instead of 5 — one extra MPT walk plus the `sentRunningHash` slot.

- `verifyBundle` varies with **participation** and **trie depth** — not with N.
- The **service overhead** is what varies with N.


Scenario #1:
```
TOTAL_execution(N) ≈ 1,618,000 + (76,780 + ~4,000 decode/msg) · N        (gas, N >= 1, 512/512, mainnet-shaped tries)
```

## 3. Inside the BLS step, by participation

| Signers | Non-signers | BLS total | `aggregateVerifyComplement` | Non-signer Merkle auth | Domain + signing root | Residual |
|---|---|---|---|---|---|---|
| 512/512 | 0 | **228,767** | 224,633 | 0 | 1,264 | 2,870 |
| 507/512 | 5 | **330,464** | 281,667 | 11,823 | 1,264 | 35,710 |
| 502/512 | 10 | **395,285** | 322,707 | 23,548 | 1,264 | 47,766 |
| 492/512 (~96%, typical mainnet ‡) | 20 | **519,009** | 399,446 | 46,971 | 1,264 | 71,328 |
| 342/512 (2/3 floor) | 170 | **2,203,928** | 1,362,358 | 403,403 | 1,264 | 436,903 |

‡ : mainnet sync-committee participation has stayed above ~96% consistently since the Altair fork;
342/512 (2/3) is the protocol's minimum-participation floor for a valid update, not a scenario seen in
practice — it exists to bound the worst case, not to describe typical operation.

Each non-signer costs one G1MSM term plus a  9-level keccak Merkle fold authenticating the key against the anchor's committee root. 
The two scale differently:

- **Merkle authentication is linear**: 2,365 gas/entry at 5 non-signers, 2,373 at 170.
- **G1MSM is sublinear**, because EIP-2537 prices multi-scalar multiplication with a per-term discount
  that grows with the term count: 11,407 gas/term over the first 5, 8,208 over the next 5, 6,498
  averaged over the remaining 160.

Averaged to the 2/3 floor the BLS step costs ~11,600 gas per non-signer, but that average hides the
curve — the first few non-signers are roughly twice as expensive as the last hundred. At the floor the
BLS step alone is 2.20M gas: a ~1.98M swing versus full participation, and the single largest source
of variance in the whole path.

## 4. Sensitivity

### MPT trie depth (N=1, 512/512, both tries at the stated depth)

| Proof nodes per trie | MPT account | MPT storage | `verifyBundle` total |
|---|---|---|---|
| 2 | 78,442 | 658,773 | 1,064,309 |
| 4 | 131,726 | 826,811 | 1,285,203 |
| 6 | 185,187 | 1,153,601 | 1,670,695 |
| 8 | 238,817 | 1,481,946 | 2,058,709 |

~26.7k gas per account-proof node and ~137k per storage-proof depth level (six walks share each
level). Depth is a property of how populated the peer's tries are, so it drifts upward over the
peer chain's lifetime — this is the term to watch.

### Branch node width (N=1, 512/512, headline depths)

| Branch width | MPT account | MPT storage | `verifyBundle` | Proof calldata |
|---|---|---|---|---|
| 2 children (~81 B) | 236,411 | 764,371 | 1,326,431 | 4,765 B |
| 16 children (~529 B) | 238,341 | 827,729 | 1,393,613 | 16,711 B |

Dense branches cost ~5% more execution but **3.5× the calldata**. We choose dense trie levels to reflect mainnet.

### Optional payload items (N=1, 512/512)

| Bundle | `verifyBundle` | Delta | Proof calldata | Calldata gas |
|---|---|---|---|---|
| Baseline | 1,425,998 | — | 16,711 B | 265,552 |
| + committee rotation | 5,984,073 | **+4,558,075** | 83,608 B | 1,132,708 |
| + endpoint manifest | 1,700,185 | +274,187 | — | — |

A rotation bundle costs ~4.6M gas of execution plus ~1.1M of calldata: it carries 512 uncompressed
128-byte keys, runs `requireOnCurveG1` over all of them, and reconstructs the SSZ committee root by
compressing each on the fly.

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/evm/ethereum/EthGasReport.t.sol` | The measurement suite (16 tests) — real service, real verifier, real bundles. |
| `test/verifiers/evm/ethereum/EthBundleProofFactory.sol` | Builds complete, self-consistent bundle proofs at a chosen depth/density/participation. |
| `test/helpers/EvmMptBuilder.sol` | Real hexary Merkle-Patricia trie builder: inclusion and exclusion proofs, with depth and branch-density padding. |
| `test/libraries/EvmMptBuilder.t.sol` | Validates the builder against the **production** walker (`MerklePatriciaProof`), not a test-side mirror. |
