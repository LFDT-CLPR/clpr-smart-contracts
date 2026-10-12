# Hiero Verifier — Gas Report

Reproduce:

```shell
FOUNDRY_PROFILE=test forge test --match-path test/verifiers/hiero/HieroGasReport.t.sol -vv
```

## Assumptions

- **Real proof**: every figure is measured on `test/verifiers/hiero/fixtures/stateProof.bin`, a
  5,422-byte `StateProof` from a Hiero network. It has 2 Merkle paths (the `ClprChannel` leaf and one
  `ClprMessageValue` leaf) and a 3,432-byte block signature, laid out as
  hintVk (1,096) ‖ hintSig (1,632) ‖ abProof (704). The bundle therefore carries **one message**.
- **Cold execution**: every `submitBundle` is its own transaction, so accounts and storage start
  cold. The `verifyBundle` rows are the first call of a test (cold). Component rows come from later
  frames and measure only work inside the callee, which is the same either way.
- **Two trust-anchor states**:
  - *First bundle*: the `trustAnchor` argument is not `keccak256(hintsVk)` (the fixture passes the
    32-byte ledger id, as `GasUsage.t.sol` does), so WRAPS recomputes the Poseidon hash of the hinTS
    VK.
  - *Steady state*: the relay passes back the `keccak256(hintsVk)` returned by the previous
    `verifyBundle`, so WRAPS skips Poseidon (`WRAPSVerifierContract.verify(..., skipPoseidon)`).
- **Calldata** is priced per EIP-2028 (4 gas per zero byte, 16 per non-zero byte) over the three
  `verifyBundle` arguments: proof 83,644, trust anchor 512, empty channel context 0. It is not priced
  over the ABI-encoded `submitBundle` payload.
- **Service overhead** is not re-measured here. It does not depend on the verifier; the figure used is
  the N = 1 value from `../evm/ethereum/GAS_REPORT.md` §2, **284,416**
  (`overhead(N) ≈ 207,640 + 76,775·N`). `src/verifiers/evm/qbft/GAS_REPORT.md` quotes a different fit
  (`195,970 + 76,780·N`, 107,585 ACK-only); the two need reconciling.
- **EVM target**: `osaka` (EIP-2537 BLS12-381 precompiles, EIP-7883 MODEXP pricing), per `foundry.toml`.

## 1. Full on-chain transaction cost

**Execution** is the `HieroVerifier.verifyBundle` call frame (`vm.lastCallGas().gasTotalUsed`).
**Total** adds the N = 1 service overhead, the EIP-2028 calldata gas and the 21,000 tx base.

| Scenario | Execution (verify) | Service overhead | Calldata | Tx base | **Total** |
|---|---|---|---|---|---|
| First bundle under a hinTS VK (Poseidon runs) | 6,108,407 | 284,416 | 84,156 | 21,000 | **6,497,979** |
| Steady state (cached `keccak256(hintsVk)`, Poseidon skipped) | 4,468,057 | 284,416 | 84,156 | 21,000 | **4,857,629** |

The first-bundle execution figure equals the `HieroVerifier.verifyBundle` minimum in
`script/gas/baselines.yml` (6,108,407), which is regression-tracked by `GasUsage.t.sol`.

Caching the anchor saves **1,640,350** gas (25% of the first-bundle total). Relays should always
pass back the anchor the previous bundle returned. The saving is lost only on the first bundle
after the hinTS VK rotates.

## 2. Breakdown by step

Component replays of the same proof, each in its own call frame
(`HieroParts` / `TSSVerifierHarness` / `WRAPSVerifierContract` in `HieroGasReport.t.sol`). Steps 2
and 5 run inside a frame that also decodes, so decode is subtracted out; the remainder is
`verifyBundle` minus the measured steps.

| Step | First bundle | Share | Steady state | Share |
|---|---|---|---|---|
| 1. `ClprStateProof.decode` | 181,387 | 3.0% | 181,387 | 4.1% |
| 2. Block root: `findFirstPath` + `computeChainedRoot` (path 1) | 1,367,299 | 22.4% | 1,367,299 | 30.6% |
| 3a. hinTS aggregate (`_verifyHintsAggregate`) | 894,977 | 14.7% | 894,977 | 20.0% |
| **3b. WRAPS: Poseidon hash of hinTS VK** | **1,632,850** | **26.7%** | — | — |
| 3c. WRAPS: remaining verification | 808,672 | 13.2% | 808,672 | 18.1% |
| 3d. `verifyTss` glue (slicing, call) | 1,215 | 0.0% | 1,215 | 0.0% |
| 4. `extractDecodedQueueData` (path 2 re-hash, leaf decode) | 1,202,325 | 19.7% | 1,202,325 | 26.9% |
| Remainder (cold accesses, `ledgerId` SLOADs, metadata, ABI) | 19,682 | 0.3% | 12,182 | 0.3% |
| **Full `verifyBundle`** | **6,108,407** |  | **4,468,057** |  |

Figures for steps 3a–3d come from calling `TSSVerifier.verifyTss` directly: 3,337,714 with Poseidon
and 1,704,864 without, each matching 3a + 3b + 3c + 3d. The Poseidon term (3b) is the difference
between the two WRAPS frames, 2,441,522 − 808,672.

What this shows:

- **Once Poseidon is skipped, SHA-384 dominates.** Steps 2 and 4 hash with `Sha384`
  (`src/libraries/crypto/Sha384.sol`), which is written in Solidity because the EVM has no SHA-384
  precompile. `GasUsage.t.sol` annotates each path as 15 SHA-384 hashes, which works out to about
  91k gas per hash. Together the two Merkle walks cost ≈ 2.57M, 57% of steady-state execution.
  Each extra message leaf in a bundle adds another path of this size, so the per-message verifier
  cost is ≈ 1.2M. This is unlike the EVM verifiers, where N adds about 4k per message
  (`../evm/ethereum/GAS_REPORT.md` §2). This fixture has a single message, so that per-message
  figure is an extrapolation.
- **hinTS is ≈ 0.9M and does not depend on bundle size.** Its per-step cost is in §3.
- **Decode, glue and remainder together are under 5%.**

## 3. Inside the hinTS step

Measured on the synthetic n = 8 hinTS fixture (`HINTS_VK_N8` / `HINTS_SIG_N8` / `BLOCK_ROOT_N8` from
`GasUsage.t.sol`), warm, by `HintsGasProfile.t.sol`.

### 3.1 Per step

| Step | Function | Gas | Share | Precompile work inside (measured) | Non-precompile remainder |
|---|---|---:|---:|---|---:|
| 0 | `_checkThreshold` + `_readU64Le` | 1,081 | 0.1% | — | 1,081 |
| 3 | `_computeFiatShamirChallenge` | 12,601 | 1.4% | 2× SHA-256, 1× modexp (48-byte base) | — |
| 3 | `_nthRootOfUnity` | 1,586 | 0.2% | 1× modexp (small exponent) | — |
| — | g0 / h0 / h1 → EIP-2537 | 974 | 0.1% | — | 974 |
| 4 | `_verifyBls12381SignaturePairing` | 170,084 | 18.9% | hash-to-G2 65,068 + 2-pair pairing 103,997 | 1,019 |
| 5 | `_verifyMergedKzgOpening` | 236,294 | 26.3% | 9-term G1MSM 78,165 + 2-term G2MSM 45,546 + 2-pair pairing 103,997 | 8,586 |
| 6 | `_verifyShiftedKzgOpening` | 180,103 | 20.1% | 2-term G1MSM 23,292 + 2-term G2MSM 45,546 + 2-pair pairing 103,997 + `_frInv` 4,889 | 2,379 |
| 7 | `_verifyBskIdentity` | 172,396 | 19.2% | 4-pair pairing 168,655 | 3,741 |
| 8 | `_verifyFieldIdentities` | 18,106 | 2.0% | 2× `_frInv` (of `n` and `r − ω^{n−1}`) 9,778 + 2× small `_frPow` ≈ 2,650 | ≈ 5,678 |
| 9 | `_verifyDegreeBound` | 104,949 | 11.7% | 2-pair pairing 103,997 | 952 |
| | **Sum of steps** | **898,174** | 100% | | |
| | External call (length checks, calldata, dispatch) | +19,586 | | | |
| | **`_verifyHintsAggregate` via external call** | **917,760** | | | |

### 3.2 By operation

| Operation | Calls | Gas | Share of 898,174 |
|---|---:|---:|---:|
| Pairing (12 pairs total) | 5 | 584,643 | 65.1% |
| G1MSM (9-term, 2-term) | 2 | 101,457 | 11.3% |
| G2MSM (2-term) | 2 | 91,092 | 10.1% |
| Hash-to-G2 (2× map-to-G2, G2ADD, 4× modexp, SHA-256 expansion) | 1 | 65,068 | 7.2% |
| Fr modexp (`_frInv` ×3, small `_frPow` ×3) | 6 | ≈ 18,900 | 2.1% |
| Fiat-Shamir transcript + hash-to-Fr | 1 | 12,601 | 1.4% |
| Solidity glue (conversions, `bytes.concat`, memory) | — | ≈ 24,400 | 2.7% |

Unit costs (each includes its wrapper's memory work):

| Operation | Gas | Derived |
|---|---:|---|
| Pairing, 2 / 4 / 6 pairs | 103,997 / 168,655 / 233,858 | ≈ 32.5k per pair + ≈ 39k fixed per call |
| G1MSM, 1 / 2 / 9 / 10 terms | 12,516 / 23,292 / 78,165 / 85,952 | ≈ 7.8k marginal per term at 9–10 terms |
| G2MSM, 2 terms | 45,546 | |
| `_frInv` (255-bit exponent) | 4,889 | |
| `_frPow` (exponent 7) | 1,325 | |

## 4. Relationship to `GasUsage.t.sol`

`HieroGasBenchmarkTest.test_hiero_verifier_gas_breakdown` reports a component TOTAL of 6,138,491
(`script/gas/baselines.yml`). That is **higher** than the full `verifyBundle` it breaks down, for
two reasons:

- It measures with `gasleft()` deltas inside a single test frame, so the memory-expansion cost
  grows as the test accumulates buffers. Its Merkle path 1 reads 1,407,156, against 1,367,299 in a
  clean frame.
- Its hinTS row (902,642) uses the synthetic n = 8 fixture (`HINTS_VK_N8` / `HINTS_SIG_N8`), not
  the hinTS VK and signature inside `stateProof.bin`. The real proof's aggregate costs 894,977.

Treat its rows as regression tripwires, and this report as the cost model.

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/hiero/HieroGasReport.t.sol` | The measurement suite behind this report (`test_report`: first-bundle and component frames; `test_steadyCold`: cold steady-state `verifyBundle`). |
| `test/verifiers/hiero/GasUsage.t.sol` | Regression-tracked baselines (`script/gas/baselines.yml` / `npm run gas:check`). |
| `test/verifiers/hiero/HintsGasProfile.t.sol` | Per-step hinTS profile behind §3. |
| `test/helpers/TSSVerifierHarness.sol` | Exposes `_verifyHintsAggregate` for a standalone hinTS frame. |
| `test/helpers/CalldataGas.sol` | EIP-2028 calldata pricing (`CalldataGas.eip2028`). |
| `test/verifiers/hiero/fixtures/stateProof.bin`, `trustAnchor.bin` | The real Hiero `StateProof` and 32-byte ledger id used throughout. |
