# QBFT Verifiers — Gas Report

Reproduce:

```shell
FOUNDRY_PROFILE=test forge test --match-path test/verifiers/evm/qbft/QbftGasReport.t.sol -vv
```

## Assumptions

To be conservative where it matters and realistic where it doesn't:

- **Synthetic, shallow tries** (built by `EvmMptBuilder`): the service-account proof is 2–3 nodes and the
  channel storage proofs a few nodes each. A dedicated Besu app chain holds orders of magnitude fewer
  accounts and slots than mainnet, so shallow tries reflect the deployment target; for mainnet-shaped
  depth sensitivity see `../ethereum/GAS_REPORT.md` §4 — depth adds cost per node on every walk.
- **Validator-array trie**: one length slot + one slot per validator; two-level branch structure above
  15 validators (3-node proofs per slot).
- **Seals at exactly the quorum**: ⌈2N/3⌉ committed seals per header (34/35 at N=51/52), matching real
  Besu headers; the 1-validator header-mode row is a single-node chain, so one seal.
- **ACK-only bundles**: empty bundle content, 5-entry channel storage proof, no endpoint manifest.
- **Calldata** is priced per EIP-2028 (4 gas per zero byte, 16 per non-zero) over the three
  `verifyBundle` arguments (proof, trust anchor, channel context).
- **Service overhead** is not re-measured here: it is verifier-independent (see
  `../ethereum/GAS_REPORT.md` §2), `overhead(N) ≈ 208,500 + 76,719·N` gas for N messages,
  measured there as 124,785 for an ACK-only bundle. That figure is `submitBundle − verifyBundle`,
  i.e. service-side dispatch and storage. The totals below use it.

All figures are post the MPT/RLP hot-path rewrite (`RlpCursor` + in-place `MerklePatriciaProof` walk,
in-place validator-set sort, cursor-parsed trusted-set and storage-entry lists); before it, the
51→52 rotation alone executed at ~29.9M gas.

## 1. Full on-chain transaction cost

**Execution** is the verifier call frame (`vm.lastCallGas().gasTotalUsed`). **Total** adds the
ACK-only service overhead (124,785), the EIP-2028 calldata gas, and the 21,000 tx base.

| Scenario | Execution (verify) | Service overhead | Calldata | Tx base | **Total** |
|---|---|---|---|---|---|
| Header mode, steady state (1 validator) | 122,348 | 124,785 | 13,528 | 21,000 | **281,661** |
| Contract mode, steady, 3 validators | 194,111 | 124,785 | 34,788 | 21,000 | **374,684** |
| Contract mode, steady, 10 validators | 318,956 | 124,785 | 109,992 | 21,000 | **574,733** |
| Contract mode, steady, 25 validators | 671,421 | 124,785 | 346,976 | 21,000 | **1,164,182** |
| Contract mode, steady, 52 validators | 1,295,071 | 124,785 | 731,060 | 21,000 | **2,171,916** |
| Contract mode, rotation 10 → 11 (1 hop) | 596,889 | 124,785 | 232,596 | 21,000 | **975,270** |
| Contract mode, rotation 51 → 52 (1 hop) | 2,428,340 | 124,785 | 1,433,044 | 21,000 | **4,007,169** |

Header mode lets a relay omit the trusted-set list when no rotation is crossed
(`qbft-header-mode.md` §5): the verifier then sorts and hashes the current header's own list against
the anchor instead of parsing, sorting and hashing a second copy from the payload. Measured on the
same synthetic steady state as the rows above:

| Validators | Execution (omitted) | Δ execution | Δ proof bytes | Δ calldata gas | **Total (omitted)** |
|---|---|---|---|---|---|
| 3 | 132,808 | −6,572 | −65 B | −1,016 | **293,497** |
| 10 | 188,050 | −16,092 | −212 B | −3,356 | **356,391** |
| 25 | 309,152 | −44,586 | −529 B | −8,404 | **493,221** |
| 52 | 570,922 | −129,571 | −1,096 B | −17,428 | **783,179** |

The saving grows faster than linearly (the omitted work includes an O(N²) insertion sort of the
submitted list) and is ~16% of the total at 52 validators. Relays should send `0xc0` whenever the
hop list is empty.

The worst case above (a 51 → 52 rotation, ~4.0M) is roughly an eighth of a 30M block. Each additional
hop crossed in one bundle adds approximately one hop-quorum + one hop-resolveSet (§3) plus its share
of calldata.

There is no hard set-size limit below `ClprQbftQuorum.MAX_VALIDATORS = 256` (see
`qbft-contract-mode.md` §8) — gas is the constraint. Extrapolating the §3 per-validator terms (~22k
per slot proof, ~10k per seal, an O(N²) sort, ~1.4M calldata per 52 validators), a contract-mode
one-hop rotation is ~10M total at 100 validators, ~20M at 200, and approaches a 30M block near the
cap; steady state is roughly half of that. Header mode has no slot proofs, so its steady state is
seals plus list handling (§2a): extrapolating ~13k execution and ~1.4k calldata per validator gives
roughly 1.7M total at 100 validators and ~4M at the 256 cap. The synthetic builders in
`QbftContractModeProofBuilders` do not reach those sizes (they exhaust test memory above ~60
validators), so treat these as estimates and measure on the target chain's block gas limit.

`verifyConfig` (contract mode, 3 validators, channel setup — runs once per channel, via
`completeChannel` rather than `submitBundle`): **165,919** execution + 23,156 calldata gas over a
1,955-byte config proof. Header mode (3 validators): **107,457** execution.

## 2. Why contract mode scales with the validator-set size

Every contract-mode bundle — steady state included — carries and verifies the **full validator
array** out of the peer contract's storage (`resolveSet`: one MPT slot proof per validator plus the
length slot), and opens the anchor's set commitment against the full submitted list. Rotation
detection is exactly this harvest; there is no cheaper "nothing changed" path.

| Validators | Execution | Δ vs previous row | Proof bytes | Calldata gas |
|---|---|---|---|---|
| 3 | 194,111 | — | 2,802 B | 34,788 |
| 10 | 318,956 | +17.8k/validator | 7,503 B | 109,992 |
| 25 | 671,421 | +23.5k/validator | 22,367 B | 346,976 |
| 52 | 1,295,071 | +23.1k/validator | 46,493 B | 731,060 |

The per-validator marginal cost grows with the set because each validator adds (a) one storage-slot
MPT walk in `resolveSet`, (b) its share of quorum `ecrecover`s (⌈2N/3⌉ seals per verified header),
and (c) ~900 B of proof calldata; the two-level array trie above 15 validators also makes each slot
proof one node deeper. Calldata grows linearly and at 52 validators is already over 50% of the
execution cost.

## 2a. How header mode scales with the validator-set size

A header-mode steady-state bundle carries no validator storage proof at all: the set is the current
header's own `extraData.validators`, and the payload repeats it as the trusted list (or omits it, see
§1). What grows with `N` is the quorum check — ⌈2N/3⌉ `ecrecover` seals — and the list handling:
parse, sort (in-place insertion sort, O(N²)) and hash of the header list and of the trusted list,
plus the `equals` comparison between them.

| Validators | Seals | Execution | Δ vs previous row | Proof bytes | Calldata gas |
|---|---|---|---|---|---|
| 1 | 1 | 122,348 | — | 1,318 B | 13,528 |
| 3 | 2 | 139,380 | +8.5k/validator | 1,472 B | 15,920 |
| 10 | 7 | 204,142 | +9.3k/validator | 2,104 B | 25,912 |
| 25 | 17 | 353,738 | +10.0k/validator | 3,407 B | 46,688 |
| 52 | 35 | 700,493 | +12.8k/validator | 5,747 B | 83,900 |

Roughly ⅔ of a seal (~10k each, so ~6.7k) per added validator is the floor; the rest of the marginal
cost is the two list sorts, which is why the per-validator term drifts upward with the set. Each
validator adds ~87 B of proof (20 B in the header list, 20 B in the trusted list, and ⅔ of a 65-byte
seal), about 1.4k calldata gas. At 52 validators header mode runs at ~43% of contract mode's total
(930,178 vs 2,171,916): the ~0.76M `resolveSet` harvest and its ~650k of slot-proof calldata are what
header mode does not pay.

The 1-validator row is the single-node shape in `GasUsage.t.sol` (a 1-seal header built by
`_buildSealedCurrentHeader`); the 3–52 rows come from `QbftHeaderModeProofBuilders._steadyScenario`
and share one measurement run with the contract-mode rows of §1. All header-mode figures are post the
single `extraData` decode per header: one `ClprQbftSeal.decodeHeader` now serves both the validator
list and the seal check, where each header used to be copied and RLP-split twice. That took roughly
9–10k gas off every header-mode verification, per header and per hop, independent of the set size.
They also include the member-list parser's two checks, canonical 21-byte items only and no zero
address, at about 18 gas per listed member on every path that parses a list.

## 3. Rotation 51 → 52 breakdown

Component replays of the same inputs, each as its own call frame through a small harness contract
(`vm.lastCallGas()`, like the full call), over the trusted set exactly as the bundle submits it
(unsorted). The header decode sits inside each quorum row; the trusted-set list parse and the
channel/service-account proofs sit in the remainder.

| Step | Gas | Share |
|---|---|---|
| Open set commitment (sort + hash 51 members) | 83,330 | 3.4% |
| Hop quorum (34 `ecrecover` seals) | 333,254 | 13.7% |
| **Hop `resolveSet` (52 slot proofs)** | **762,759** | **31.4%** |
| Current-header quorum (35 `ecrecover` seals) | 344,208 | 14.2% |
| **Final `resolveSet` (52 slot proofs)** | **766,053** | **31.5%** |
| Measured steps sum | 2,289,604 | 94.3% |
| Remainder (payload decode, trusted-set parse, service account proof, channel slots) | 138,736 | 5.7% |
| **Full `verifyBundle`** | **2,428,340** |  |

The two `resolveSet` harvests — one under the hop's state root, one under the current block's — are
~63% of the rotation. A quorum check costs ~10k gas per seal (`ecrecover` + the sealing-digest keccak
and header decode amortized), so seals are a minor term next to the array proofs. A steady-state
bundle at the same set size drops the hop pair and keeps one harvest, which is why it runs at ~1.3M
(§2).

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/evm/qbft/QbftGasReport.t.sol` | The measurement suite behind this report (6 tests: `QbftGasReportTest` for the 1-validator header row and contract mode, `QbftHeaderModeGasReportTest` for header mode by set size, listed and omitted trusted set). |
| `test/verifiers/evm/qbft/ContractModeGasUsage.t.sol` | The regression-tracked contract-mode baselines (`script/gas/baselines.yml` / `npm run gas:check`). |
| `test/verifiers/evm/qbft/GasUsage.t.sol` | The regression-tracked header-mode baselines. |
| `test/verifiers/evm/qbft/QbftHeaderModeProofBuilders.sol` | Assembles complete header-mode bundles (listed sets, hops, anchors, config proofs). |
| `test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol` | Assembles complete contract-mode bundles (sets, hops, anchors) from the helpers below. |
| `test/helpers/QbftContractProofs.sol` | Validator-array storage proofs, sealed headers with listed sets, contract-proof wrapping. |
| `test/helpers/QbftSyntheticProofs.sol` | Header-mode synthetic proofs: sealed headers, service-account and channel storage proofs. |
| `test/helpers/EvmMptBuilder.sol` | Real hexary Merkle-Patricia trie builder validated against the production walker. |
