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
| N=1, 512/512 | 773,673 | 258,684 | 21,000 | **1,053,357** |
| N=10, 512/512 | 1,500,972 | 269,176 | 21,000 | **1,791,148** |
| N=1, 507/512 (~99%, typical mainnet ‡) † | ~875,447 | 290,196 | 21,000 | **~1,186,643** |
| N=1, 502/512 (~98%, typical mainnet ‡) † | ~940,281 | 321,652 | 21,000 | **~1,282,933** |
| N=1, 497/512 (~97%, typical mainnet ‡) † | ~1,002,371 | 353,144 | 21,000 | **~1,376,515** |
| N=1, 492/512 (~96%, typical mainnet ‡) † | ~1,064,036 | 384,612 | 21,000 | **~1,469,648** |
| N=1, 342/512 (2/3 floor) † | ~2,749,412 | 1,328,816 | 21,000 | **~4,099,228** |
| N=1, rotation: **widen** (window unchanged) | 5,065,326 | 1,131,996 | 21,000 | **6,218,322** |
| N=1, rotation: **shift** (window advances) | 5,095,354 | 1,131,972 | 21,000 | **6,248,326** |

† : approximate : The N=1 `submitBundle` execution total (773,673) is re-added to the
measured **execution** delta for that variant — the BLS step's own delta at that participation
versus full participation (§3, BLS total at 512/512 = 230,150):
- **+101,774** — 507/512 (§3: 331,924 − 230,150).
- **+166,608** — 502/512 (§3: 396,758 − 230,150).
- **+228,698** — 497/512 (§3: 458,848 − 230,150).
- **+290,363** — 492/512 (§3: 520,513 − 230,150).
- **+1,975,739** — the BLS step's own delta at the floor (§3: 2,205,889 at 342/512 − 230,150 at 512/512).

‡ : mainnet sync-committee participation has stayed above ~96% consistently.

Every † row assumes the ~285,223 gas of service overhead barely moves as participation or the payload
changes — reasonable, but unverified, hence the `~`.

The **calldata** column is a separate axis (raw bytes, priced by EIP-2028 before execution starts — no
relation to the execution deltas above): at the participation floor the 170 non-signer entries alone
are 170 × 419 bytes (pubkey + Merkle-authentication path each) ≈ 71,230 B on top of the 16,281 B
baseline proof, which is why calldata reaches 1.33M gas — comparable to the entire BLS computation it
authenticates. Rotation's 1.13M gas is the same story with a different cause: 512 **uncompressed**
128-byte G1 keys (65,536 B) plus the baseline proof and the SSZ Merkle proof for the new committee
root, 83,178 B total (§4) — the whole next committee has to be delivered, not just proofs of exclusion
for a few non-signers.

The worst realistic case without rotation (~4.1M) is about a seventh of a 30M block; a rotation bundle at the
participation floor would be worse still.

### Execution breakdown (N=1, 512/512)

`submitBundle`'s execution splits into service overhead and `verifyBundle`:

| Component | Gas | Share of execution |
|---|---|---|
| `verifyBundle` | 488,450 | 63.1% |
| Service overhead (`submitBundle` − verify) | 285,223 | 36.9% |
| **`submitBundle` execution total** | **773,673** | |

### Breakdown of a `verifyBundle` (N=1, 512/512)

| Step                                  | Gas | Share |
|---------------------------------------|---|---|
| 1 — trust-anchor reads                | 1,895 | 0.4% |
| — top-level RLP decode                | 21,677 | 4.8% |
| 2 — beacon header decode              | 12,675 | 2.8% |
| — beacon header SSZ root              | 8,486 | 1.9% |
| 3 — signature slot → window member, sync-aggregate read | 9,863 | 2.2% |
| — **BLS verify**                      | **230,150** | **51.0%** |
| 4 — execution SSZ branch (depth of 9) | 31,146 | 6.9% |
| 5 — channel context decode            | 1,463 | 0.3% |
| — **MPT account proof**               | **27,756** | **6.2%** |
| 6 — **MPT storage proof**             | **99,060** | **22.0%** |
| — bundle content protobuf             | 5,074 | 1.1% |
| — endpoint manifest (absent)          | 771 | 0.2% |
| 7 — rotation (absent)                 | 1,014 | 0.2% |
| — trust-anchor id                     | 136 | 0.0% |
| **Sum of steps**                      | **451,166** | |
| Real `verifyBundle` call              | 461,370 | |

The 10,204 gas gap is instrumentation plus external-call dispatch (~2.2%).

See §3 below for how the **BLS verify** line moves with non-signer count.

## 2. Total cost: `submitBundle(N)`
What does it cost to submit a bundle carrying N messages in one transaction

| N messages | `submitBundle` TOTAL | `verifyBundle` | Service overhead (TOTAL − verify) | Proof calldata | Calldata gas |
|---|---|---|---|---|---|
| 0 (ACK-only) | 588,788 | 464,003 | 124,785 | 14,552 B | 231,056 |
| 1 | 773,673 | 488,450 | 285,223 | 16,281 B | 258,684 |
| 2 | 855,951 | 494,227 | 361,724 | 16,355 B | 259,724 |
| 5 | 1,096,362 | 505,004 | 591,358 | 16,578 B | 263,376 |
| 10 | 1,500,972 | 525,279 | 975,693 | 16,948 B | 269,176 |

### The service overhead is verifier-independent
```
overhead(N) ≈ 208,500 + 76,719 · N        (gas)
```

> _How to obtain those values_ : 
> 
> N=1:  overhead = 285,223
> 
> N=10: overhead = 975,693
>
> Taking the linear model overhead(N) = a + b·N, we have the following system of equations:
> 
> a + b·1  = 285,223
> 
> a + b·10 = 975,693
>
> Subtract the first from the second to eliminate a:
> 
> 9b = 975,693 − 285,223 = 690,470
> 
> b  = 690,470 / 9 ≈ **76,719**
>
> Plug back in to get a:
>
> a = 285,223 − 76,719 = 208,504  ≈ 208,500

### Correction to the underlying premise

| N | `verifyBundle` | Δ per message |
|---|---|---|
| 1 → 10 | 488,450 → 525,279 | ~4,090 |

The only N-dependence is the protobuf decode (~4k/message). 
The N=0 → N=1 step is larger (464,003 → 488,450, +24,447) because a message-bearing bundle carries a **6-entry**
storage proof instead of 5 — one extra MPT walk plus the `sentRunningHash` slot.

- `verifyBundle` varies with **participation** and **trie depth** — not with N.
- The **service overhead** is what varies with N.


Scenario #1:
```
TOTAL_execution(N) ≈ 693,000 + (76,719 + ~4,090 decode/msg) · N        (gas, N >= 1, 512/512, mainnet-shaped tries)
```

## 3. Inside the BLS step, by participation

| Signers | Non-signers | BLS total | `aggregateVerifyComplement` | Non-signer Merkle auth | Domain + signing root | Residual |
|---|---|---|---|---|---|---|
| 512/512 | 0 | **230,150** | 225,413 | 0 | 1,300 | 3,437 |
| 507/512 | 5 | **331,924** | 282,507 | 11,823 | 1,300 | 36,294 |
| 502/512 | 10 | **396,758** | 323,547 | 23,548 | 1,300 | 48,363 |
| 492/512 (~96%, typical mainnet ‡) | 20 | **520,513** | 400,286 | 46,971 | 1,300 | 71,956 |
| 342/512 (2/3 floor) | 170 | **2,205,889** | 1,363,198 | 403,403 | 1,300 | 437,988 |

‡ : mainnet sync-committee participation has stayed above ~96% consistently since the Altair fork;
342/512 (2/3) is the protocol's minimum-participation floor for a valid update, not a scenario seen in
practice — it exists to bound the worst case, not to describe typical operation.

Each non-signer costs one G1MSM term plus a  9-level keccak Merkle fold authenticating the key against the selected window member's committee root. 
The two scale differently:

- **Merkle authentication is linear**: 2,365 gas/entry at 5 non-signers, 2,373 at 170.
- **G1MSM is sublinear**, because EIP-2537 prices multi-scalar multiplication with a per-term discount
  that grows with the term count: 11,419 gas/term over the first 5, 8,208 over the next 5, 6,498
  averaged over the remaining 160.

Averaged to the 2/3 floor the BLS step costs ~11,600 gas per non-signer, but that average hides the
curve — the first few non-signers are roughly twice as expensive as the last hundred. At the floor the
BLS step alone is 2.21M gas: a ~1.98M swing versus full participation, and the single largest source
of variance in the whole path.

## 4. Sensitivity

### MPT trie depth (N=1, 512/512, both tries at the stated depth)

| Proof nodes per trie | MPT account | MPT storage | `verifyBundle` total |
|---|---|---|---|
| 2 | 8,725 | 84,489 | 423,921 |
| 4 | 16,768 | 99,044 | 445,782 |
| 6 | 22,978 | 140,552 | 498,613 |
| 8 | 27,756 | 178,619 | 547,342 |

~3.2k gas per account-proof node and ~15.7k per storage-proof depth level (six walks share each
level). Depth is a property of how populated the peer's tries are, so it drifts upward over the
peer chain's lifetime — this is the term to watch.

### Branch node width (N=1, 512/512, headline depths)

| Branch width | MPT account | MPT storage | `verifyBundle` | Proof calldata |
|---|---|---|---|---|
| 2 children (~81 B) | 25,834 | 93,483 | 448,634 | 4,993 B |
| 16 children (~529 B) | 27,756 | 99,060 | 457,663 | 16,281 B |

Dense branches cost ~2% more execution but **3.3× the calldata**. We choose dense trie levels to reflect mainnet.

### Optional payload items (N=1, 512/512)

| Bundle | `verifyBundle` | Delta vs baseline | Item's step | Proof calldata | Calldata gas |
|---|---|---|---|---|---|
| Baseline | 488,450 | — | — | 16,281 B | 258,684 |
| + rotation: **widen** (window unchanged) | 4,801,372 | **+4,312,922** | 3,961,640 | 83,178 B | 1,131,996 |
| + rotation: **shift** (window advances) | 4,802,444 | **+4,313,994** | 3,961,354 | 83,178 B | 1,131,972 |
| + endpoint manifest | 531,819 | +43,369 | 36,348 | 18,045 B | 286,092 |

The window anchor has two rotation outcomes (README §"Rotation"). A **widen** is a bundle signed in the
window's own period that carries the `next_sync_committee` proof: the verifier does the full rotation
work — 512 uncompressed keys through `requireOnCurveG1`, the SSZ committee root rebuilt by compressing
each key on the fly, the state-root branch, the keccak committee root — and then only checks that the
proven committee equals the stored `next`, returning an empty anchor. A **shift** is the same bundle
signed one period ahead: the same work, then the window rotates and the 428-byte successor anchor is
returned. Inside `verifyBundle` the two are indistinguishable (~1.1k apart, within noise); the shift's
real extra cost is the storage write the service performs, measured next.

### Rotation through the service (N=1, 512/512)

`submitBundle` with the rotation bundle above. The widen runs against the channel's own window; the
shift needs the channel opened one period behind, which `EthGasReportShiftTest` does.

| `submitBundle` | Execution | Delta vs N=1 | Stored anchor afterwards |
|---|---|---|---|
| N=1 baseline | 773,673 | — | unchanged |
| N=1 + rotation: widen | 5,065,326 | +4,291,653 | unchanged |
| N=1 + rotation: shift | 5,095,354 | +4,321,681 | **replaced** (428 B + 8-byte id) |

The shift costs 30,028 gas more than the widen end to end: that is `BundleLib` overwriting the 428-byte
`Channel.trustAnchor` and its `trustAnchorId`. Everything else in the ~4.3M rotation premium is
verification and is paid whether or not the window moves — which is the point of the window design:
an endpoint can carry the advance in any ordinary bundle during the ~27-hour period, instead of
timing a dedicated transition transaction at the boundary.

## Test infrastructure

| File | Role |
|---|---|
| `../../../../test/verifiers/evm/ethereum/EthGasReport.t.sol` | The measurement suite (20 tests) — real service, real verifier, real bundles. `EthGasReportTest` measures against a channel on the attested-period window; `EthGasReportShiftTest` opens the channel a period behind for the `submitBundle` shift. |
| `../../../../test/verifiers/evm/ethereum/EthBundleProofFactory.sol` | Builds complete, self-consistent bundle proofs at a chosen depth/density/participation, with `Rotation.None`, `.Widen` or `.Shift`. |
| `../../../../test/helpers/EvmMptBuilder.sol` | Real hexary Merkle-Patricia trie builder: inclusion and exclusion proofs, with depth and branch-density padding. |
| `../../../../test/libraries/EvmMptBuilder.t.sol` | Validates the builder against the **production** walker (`MerklePatriciaProof`, through the `../../../../test/helpers/MptWalk.sol` copy-out wrapper), not a test-side mirror. |
