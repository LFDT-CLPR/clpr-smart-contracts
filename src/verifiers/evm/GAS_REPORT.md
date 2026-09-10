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
- No rotation or manifest, except where a row says otherwise

## 1. Full on-chain transaction cost

EIP-2028 charges intrinsic calldata gas (4/zero byte, 16/non-zero) **before** execution begins.
For a full on-chain transaction cost, add 21,000 (tx base) + the calldata gas. **Execution** below is the
full `submitBundle(N)` call (service dispatch + verification) — its own breakdown follows immediately after.

| Scenario | Execution | Calldata | Tx base | **Total** |
|---|---|---|---|---|
| N=1, 512/512 | 1,712,799 | 265,600 | 21,000 | **1,999,399** |
| N=10, 512/512 | 2,439,578 | 276,152 | 21,000 | **2,736,730** |
| N=1, 507/512 (~99%, typical mainnet ‡) † | ~1,814,498 | 297,100 | 21,000 | **~2,132,598** |
| N=1, 502/512 (~98%, typical mainnet ‡) † | ~1,879,319 | 328,580 | 21,000 | **~2,228,899** |
| N=1, 497/512 (~97%, typical mainnet ‡) † | ~1,941,393 | 360,060 | 21,000 | **~2,322,453** |
| N=1, 492/512 (~96%, typical mainnet ‡) † | ~2,003,046 | 391,504 | 21,000 | **~2,415,550** |
| N=1, 342/512 (2/3 floor) † | ~3,688,000 | 1,335,720 | 21,000 | **~5,044,720** |
| N=1, rotation: **widen** (window unchanged) | 6,070,906 | 1,138,936 | 21,000 | **7,230,842** |
| N=1, rotation: **shift** (window advances) | 6,100,951 | 1,138,936 | 21,000 | **7,260,887** |

† : approximate : The N=1 `submitBundle` execution total (1,712,799) is re-added to the
measured **execution** delta for that variant — the BLS step's own delta at that participation
versus full participation (§3, BLS total at 512/512 = 229,275):
- **+101,699** — 507/512 (§3: 330,974 − 229,275).
- **+166,520** — 502/512 (§3: 395,795 − 229,275).
- **+228,594** — 497/512 (§3: 457,869 − 229,275).
- **+290,247** — 492/512 (§3: 519,522 − 229,275).
- **+1,975,201** — the BLS step's own delta at the floor (§3: 2,204,476 at 342/512 − 229,275 at 512/512).

‡ : mainnet sync-committee participation has stayed above ~96% consistently.

Every † row assumes the ~284,416 gas of service overhead barely moves as participation or the payload
changes — reasonable, but unverified, hence the `~`.

The **calldata** column is a separate axis (raw bytes, priced by EIP-2028 before execution starts — no
relation to the execution deltas above): at the participation floor the 170 non-signer entries alone
are 170 × 419 bytes (pubkey + Merkle-authentication path each) ≈ 71,230 B on top of the 16,714 B
baseline proof, which is why calldata reaches 1.34M gas — comparable to the entire BLS computation it
authenticates. Rotation's 1.14M gas is the same story with a different cause: 512 **uncompressed**
128-byte G1 keys (65,536 B) plus the baseline proof and the SSZ Merkle proof for the new committee
root, 83,611 B total (§4) — the whole next committee has to be delivered, not just proofs of exclusion
for a few non-signers.

The worst realistic case without rotation (~5.0M) is a sixth of a 30M block; a rotation bundle at the
participation floor would be worse still.

### Execution breakdown (N=1, 512/512)

`submitBundle`'s execution splits into service overhead and `verifyBundle`:

| Component | Gas | Share of execution |
|---|---|---|
| `verifyBundle` | 1,428,383 | 83.4% |
| Service overhead (`submitBundle` − verify) | 284,416 | 16.6% |
| **`submitBundle` execution total** | **1,712,799** | |

### Breakdown of a `verifyBundle` (N=1, 512/512)

| Step                                  | Gas | Share |
|---------------------------------------|---|---|
| 1 — trust-anchor reads                | 1,034 | 0.1% |
| — top-level RLP decode                | 21,711 | 1.6% |
| 2 — beacon header decode              | 12,561 | 0.9% |
| — beacon header SSZ root              | 8,151 | 0.6% |
| 3 — signature slot → window member, sync-aggregate read | 9,766 | 0.7% |
| — **BLS verify**                      | **229,275** | **16.5%** |
| 4 — execution SSZ branch (depth of 9) | 30,943 | 2.2% |
| 5 — channel context decode            | 1,389 | 0.1% |
| — **MPT account proof**               | **238,347** | **17.2%** |
| 6 — **MPT storage proof**             | **827,762** | **59.6%** |
| — bundle content protobuf             | 4,916 | 0.4% |
| — endpoint manifest (absent)          | 757 | 0.1% |
| 7 — rotation (absent)                 | 983 | 0.1% |
| — trust-anchor id                     | 136 | 0.0% |
| **Sum of steps**                      | **1,387,731** | |
| Real `verifyBundle` call              | 1,400,318 | |

The 12,587 gas gap is instrumentation plus external-call dispatch (~0.9%).

See §3 below for how the **BLS verify** line moves with non-signer count.

## 2. Total cost: `submitBundle(N)`
What does it cost to submit a bundle carrying N messages in one transaction

| N messages | `submitBundle` TOTAL | `verifyBundle` | Service overhead (TOTAL − verify) | Proof calldata | Calldata gas |
|---|---|---|---|---|---|
| 0 (ACK-only) | 1,413,239 | 1,293,980 | 119,259 | 14,552 B | 231,056 |
| 1 | 1,712,799 | 1,428,383 | 284,416 | 16,714 B | 265,600 |
| 2 | 1,793,326 | 1,432,251 | 361,075 | 16,788 B | 266,796 |
| 5 | 2,035,055 | 1,444,157 | 590,898 | 17,011 B | 270,340 |
| 10 | 2,439,578 | 1,464,185 | 975,393 | 17,381 B | 276,152 |

### The service overhead is verifier-independent
```
overhead(N) ≈ 207,640 + 76,775 · N        (gas)
```

> _How to obtain those values_ : 
> 
> N=1:  overhead = 284,416
> 
> N=10: overhead = 975,393
>
> Taking the linear model overhead(N) = a + b·N, we have the following system of equations:
> 
> a + b·1  = 284,416
> 
> a + b·10 = 975,393
>
> Subtract the first from the second to eliminate a:
> 
> 9b = 975,393 − 284,416 = 690,977
> 
> b  = 690,977 / 9 ≈ **76,775**
>
> Plug back in to get a:
>
> a = 284,416 − 76,775 = 207,641  ≈ 207,640

### Correction to the underlying premise

| N | `verifyBundle` | Δ per message |
|---|---|---|
| 1 → 10 | 1,428,383 → 1,464,185 | ~3,980 |

The only N-dependence is the protobuf decode (~4k/message). 
The N=0 → N=1 step is larger (1,293,980 → 1,428,383, +134,403) because a message-bearing bundle carries a **6-entry**
storage proof instead of 5 — one extra MPT walk plus the `sentRunningHash` slot.

- `verifyBundle` varies with **participation** and **trie depth** — not with N.
- The **service overhead** is what varies with N.


Scenario #1:
```
TOTAL_execution(N) ≈ 1,632,000 + (76,775 + ~4,000 decode/msg) · N        (gas, N >= 1, 512/512, mainnet-shaped tries)
```

## 3. Inside the BLS step, by participation

| Signers | Non-signers | BLS total | `aggregateVerifyComplement` | Non-signer Merkle auth | Domain + signing root | Residual |
|---|---|---|---|---|---|---|
| 512/512 | 0 | **229,275** | 224,633 | 0 | 1,264 | 3,378 |
| 507/512 | 5 | **330,974** | 281,667 | 11,823 | 1,264 | 36,220 |
| 502/512 | 10 | **395,795** | 322,707 | 23,548 | 1,264 | 48,276 |
| 492/512 (~96%, typical mainnet ‡) | 20 | **519,522** | 399,446 | 46,971 | 1,264 | 71,841 |
| 342/512 (2/3 floor) | 170 | **2,204,476** | 1,362,358 | 403,403 | 1,264 | 437,451 |

‡ : mainnet sync-committee participation has stayed above ~96% consistently since the Altair fork;
342/512 (2/3) is the protocol's minimum-participation floor for a valid update, not a scenario seen in
practice — it exists to bound the worst case, not to describe typical operation.

Each non-signer costs one G1MSM term plus a  9-level keccak Merkle fold authenticating the key against the selected window member's committee root. 
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
| 2 | 78,444 | 658,799 | 1,067,356 |
| 4 | 131,729 | 826,843 | 1,288,191 |
| 6 | 185,192 | 1,153,642 | 1,673,626 |
| 8 | 238,823 | 1,481,996 | 2,061,582 |

~26.7k gas per account-proof node and ~137k per storage-proof depth level (six walks share each
level). Depth is a property of how populated the peer's tries are, so it drifts upward over the
peer chain's lifetime — this is the term to watch.

### Branch node width (N=1, 512/512, headline depths)

| Branch width | MPT account | MPT storage | `verifyBundle` | Proof calldata |
|---|---|---|---|---|
| 2 children (~81 B) | 236,415 | 764,397 | 1,329,477 | 4,768 B |
| 16 children (~529 B) | 238,347 | 827,762 | 1,396,602 | 16,714 B |

Dense branches cost ~5% more execution but **3.5× the calldata**. We choose dense trie levels to reflect mainnet.

### Optional payload items (N=1, 512/512)

| Bundle | `verifyBundle` | Delta vs baseline | Item's step | Proof calldata | Calldata gas |
|---|---|---|---|---|---|
| Baseline | 1,428,383 | — | — | 16,714 B | 265,600 |
| + rotation: **widen** (window unchanged) | 5,807,238 | **+4,378,855** | 3,996,816 | 83,611 B | 1,138,936 |
| + rotation: **shift** (window advances) | 5,808,475 | **+4,380,092** | 3,996,583 | 83,611 B | 1,138,936 |
| + endpoint manifest | 1,587,413 | +159,030 | 150,483 | 18,478 B | 293,332 |

The window anchor has two rotation outcomes (README §"Rotation"). A **widen** is a bundle signed in the
window's own period that carries the `next_sync_committee` proof: the verifier does the full rotation
work — 512 uncompressed keys through `requireOnCurveG1`, the SSZ committee root rebuilt by compressing
each key on the fly, the state-root branch, the keccak committee root — and then only checks that the
proven committee equals the stored `next`, returning an empty anchor. A **shift** is the same bundle
signed one period ahead: the same work, then the window rotates and the 428-byte successor anchor is
returned. Inside `verifyBundle` the two are indistinguishable (~1.2k apart, within noise); the shift's
real extra cost is the storage write the service performs, measured next.

### Rotation through the service (N=1, 512/512)

`submitBundle` with the rotation bundle above. The widen runs against the channel's own window; the
shift needs the channel opened one period behind, which `EthGasReportShiftTest` does.

| `submitBundle` | Execution | Delta vs N=1 | Stored anchor afterwards |
|---|---|---|---|
| N=1 baseline | 1,712,799 | — | unchanged |
| N=1 + rotation: widen | 6,070,906 | +4,358,107 | unchanged |
| N=1 + rotation: shift | 6,100,951 | +4,388,152 | **replaced** (428 B + 8-byte id) |

The shift costs 30,045 gas more than the widen end to end: that is `BundleLib` overwriting the 428-byte
`Channel.trustAnchor` and its `trustAnchorId`. Everything else in the ~4.4M rotation premium is
verification and is paid whether or not the window moves — which is the point of the window design:
an endpoint can carry the advance in any ordinary bundle during the ~27-hour period, instead of
timing a dedicated transition transaction at the boundary.

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/evm/ethereum/EthGasReport.t.sol` | The measurement suite (20 tests) — real service, real verifier, real bundles. `EthGasReportTest` measures against a channel on the attested-period window; `EthGasReportShiftTest` opens the channel a period behind for the `submitBundle` shift. |
| `test/verifiers/evm/ethereum/EthBundleProofFactory.sol` | Builds complete, self-consistent bundle proofs at a chosen depth/density/participation, with `Rotation.None`, `.Widen` or `.Shift`. |
| `test/helpers/EvmMptBuilder.sol` | Real hexary Merkle-Patricia trie builder: inclusion and exclusion proofs, with depth and branch-density padding. |
| `test/libraries/EvmMptBuilder.t.sol` | Validates the builder against the **production** walker (`MerklePatriciaProof`, through the `test/helpers/MptWalk.sol` copy-out wrapper), not a test-side mirror. |
