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
  depth sensitivity see `src/verifiers/evm/GAS_REPORT.md` §4 — depth adds cost per node on every walk.
- **Validator-array trie**: one length slot + one slot per validator; two-level branch structure above
  15 validators (3-node proofs per slot).
- **Seals at exactly the quorum**: ⌈2N/3⌉ committed seals per header in contract mode (34/35 at N=51/52),
  matching real Besu headers; header mode runs at its `MIN_COMMITTED_SEALS = 1`.
- **ACK-only bundles**: empty bundle content, 5-entry channel storage proof, no endpoint manifest.
- **Calldata** is priced per EIP-2028 (4 gas per zero byte, 16 per non-zero) over the three
  `verifyBundle` arguments (proof, trust anchor, channel context).
- **Service overhead** is not re-measured here: it is verifier-independent (see
  `src/verifiers/evm/GAS_REPORT.md` §2), `overhead(N) ≈ 195,970 + 76,780·N` gas for N messages,
  measured there as 107,585 for an ACK-only bundle. That figure is `submitBundle − verifyBundle`,
  i.e. service-side dispatch and storage, which the MPT/RLP rewrite did not touch — so it stays
  valid even though the ETH report's own MPT figures predate the rewrite. The totals below use it.

All figures are post the MPT/RLP hot-path rewrite (`RlpCursor` + in-place `MerklePatriciaProof` walk,
in-place validator-set sort, cursor-parsed trusted-set and storage-entry lists); before it, the
51→52 rotation alone executed at ~29.9M gas.

## 1. Full on-chain transaction cost

**Execution** is the verifier call frame (`vm.lastCallGas().gasTotalUsed`). **Total** adds the
ACK-only service overhead (107,585), the EIP-2028 calldata gas, and the 21,000 tx base.

| Scenario | Execution (verify) | Service overhead | Calldata | Tx base | **Total** |
|---|---|---|---|---|---|
| Header mode, steady state (1 validator) | 111,841 | 107,585 | 12,704 | 21,000 | **253,130** |
| Contract mode, steady, 3 validators | 217,610 | 107,585 | 34,788 | 21,000 | **380,983** |
| Contract mode, steady, 10 validators | 365,767 | 107,585 | 109,992 | 21,000 | **604,344** |
| Contract mode, steady, 25 validators | 864,092 | 107,585 | 346,976 | 21,000 | **1,339,653** |
| Contract mode, steady, 52 validators | 1,685,593 | 107,585 | 731,060 | 21,000 | **2,545,238** |
| Contract mode, rotation 10 → 11 (1 hop) | 689,857 | 107,585 | 232,596 | 21,000 | **1,051,038** |
| Contract mode, rotation 51 → 52 (1 hop) | 3,203,931 | 107,585 | 1,433,044 | 21,000 | **4,765,560** |

The worst case above (a 51 → 52 rotation, ~4.8M) is roughly a sixth of a 30M block. Each additional
hop crossed in one bundle adds approximately one hop-quorum + one hop-resolveSet (§3) plus its share
of calldata.

There is no hard set-size limit below `ClprQbftQuorum.MAX_VALIDATORS = 256` (see
`qbft-contract-mode.md` §8) — gas is the constraint. Extrapolating the §3 per-validator terms (~22k
per slot proof, ~10k per seal, an O(N²) sort, ~1.4M calldata per 52 validators), a one-hop rotation
is ~10M total at 100 validators, ~20M at 200, and approaches a 30M block near the cap; steady state
is roughly half of that. The synthetic builders in `QbftContractModeProofBuilders` do not reach
those sizes (they exhaust test memory above ~60 validators), so treat these as estimates and measure
on the target chain's block gas limit.

`verifyConfig` (contract mode, 3 validators, channel setup — runs once per channel, via
`completeChannel` rather than `submitBundle`): **184,245** execution + 23,204 calldata gas over a
1,958-byte config proof.

## 2. Why contract mode scales with the validator-set size

Every contract-mode bundle — steady state included — carries and verifies the **full validator
array** out of the peer contract's storage (`resolveSet`: one MPT slot proof per validator plus the
length slot), and opens the anchor's set commitment against the full submitted list. Rotation
detection is exactly this harvest; there is no cheaper "nothing changed" path.

| Validators | Execution | Δ vs previous row | Proof bytes | Calldata gas |
|---|---|---|---|---|
| 3 | 217,610 | — | 2,802 B | 34,788 |
| 10 | 365,767 | +21.2k/validator | 7,503 B | 109,992 |
| 25 | 864,092 | +33.2k/validator | 22,367 B | 346,976 |
| 52 | 1,685,593 | +30.4k/validator | 46,493 B | 731,060 |

The per-validator marginal cost grows with the set because each validator adds (a) one storage-slot
MPT walk in `resolveSet`, (b) its share of quorum `ecrecover`s (⌈2N/3⌉ seals per verified header),
and (c) ~900 B of proof calldata; the two-level array trie above 15 validators also makes each slot
proof one node deeper. Calldata grows linearly and at 52 validators is already over 40% of the
execution cost.

## 3. Rotation 51 → 52 breakdown

Component replays of the same inputs, each as its own call frame through a small harness contract
(`vm.lastCallGas()`, like the full call), over the trusted set exactly as the bundle submits it
(unsorted). The header decode sits inside each quorum row; the trusted-set list parse and the
channel/service-account proofs sit in the remainder.

| Step | Gas | Share |
|---|---|---|
| Open set commitment (sort + hash 51 members) | 83,330 | 2.6% |
| Hop quorum (34 `ecrecover` seals) | 335,771 | 10.5% |
| **Hop `resolveSet` (52 slot proofs)** | **1,146,007** | **35.8%** |
| Current-header quorum (35 `ecrecover` seals) | 346,799 | 10.8% |
| **Final `resolveSet` (52 slot proofs)** | **1,152,338** | **36.0%** |
| Measured steps sum | 3,064,245 | 95.6% |
| Remainder (payload decode, trusted-set parse, service account proof, channel slots) | 139,686 | 4.4% |
| **Full `verifyBundle`** | **3,203,931** |  |

The two `resolveSet` harvests — one under the hop's state root, one under the current block's — are
~72% of the rotation. A quorum check costs ~10k gas per seal (`ecrecover` + the sealing-digest keccak
and header decode amortized), so seals are a minor term next to the array proofs. A steady-state
bundle at the same set size drops the hop pair and keeps one harvest, which is why it runs at ~1.7M
(§2).

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/evm/qbft/QbftGasReport.t.sol` | The measurement suite behind this report (5 tests). |
| `test/verifiers/evm/qbft/ContractModeGasUsage.t.sol` | The regression-tracked baselines (`script/gas/baselines.yml` / `npm run gas:check`). |
| `test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol` | Assembles complete contract-mode bundles (sets, hops, anchors) from the helpers below. |
| `test/helpers/QbftContractProofs.sol` | Validator-array storage proofs, sealed headers with listed sets, contract-proof wrapping. |
| `test/helpers/QbftSyntheticProofs.sol` | Header-mode synthetic proofs: sealed headers, service-account and channel storage proofs. |
| `test/helpers/EvmMptBuilder.sol` | Real hexary Merkle-Patricia trie builder validated against the production walker. |
