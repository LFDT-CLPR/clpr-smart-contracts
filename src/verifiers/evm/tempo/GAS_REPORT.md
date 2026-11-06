# Tempo Verifier — Gas Report

Reproduce:

```shell
FOUNDRY_PROFILE=test forge test --match-path test/verifiers/tempo/TempoGasReport.t.sol -vv
```

## Assumptions

- **Synthetic, shallow tries** (built by `MptWire`): a one-node service-account proof and a
  one-node channel storage proof shared by the 5 channel slots. A dedicated Tempo deployment holds
  few accounts and slots, so this matches the target. Deeper tries add cost per node on every walk.
- **ACK-only bundles**: empty bundle content, 5 channel slots, no endpoint manifest.
- **Epoch length 100** in the synthetic scenarios. The epoch length changes no cost.
- **Keys and signatures** come from a test key built with the EIP-2537 MSM precompiles. The BLS
  primitive rows use the real mainnet (Presto) certificate and the key that signed it, from
  `test/verifiers/tempo/fixtures/`.
- **Calldata** is priced per EIP-2028 over the three `verifyBundle` arguments.
- **Service overhead** is verifier-independent: 107,585 gas for an ACK-only bundle
  (`src/verifiers/evm/GAS_REPORT.md` §2). The totals below use it, plus the 21,000 tx base.

## 1. Full on-chain transaction cost

**Execution** is the verifier call frame (`vm.lastCallGas().gasTotalUsed`).

| Scenario | Execution (verify) | Service overhead | Calldata | Tx base | **Total** |
|---|---|---|---|---|---|
| Steady state (no rotation) | 229,289 | 107,585 | 18,284 | 21,000 | **376,158** |
| 1 rotation | 417,228 | 107,585 | 29,444 | 21,000 | **575,257** |
| 2 rotations | 603,624 | 107,585 | 40,432 | 21,000 | **772,641** |

Proof sizes: 1,733 bytes steady, 2,909 bytes with one rotation, 4,081 bytes with two rotations.

`verifyConfig` (channel setup, runs once): **219,523** execution + 11,780 calldata gas over a
1,214-byte config proof.

In the steady state, the cost does not depend on the validator-set size.

## 2. Where the gas goes

Each row is one call frame through a small harness contract, on the real mainnet tip certificate.

| Step | Gas |
|---|---|
| `parseProposal` (three varints + 32-byte hash) | 4,310 |
| `compressG1` (bind the uncompressed signature) | 1,614 |
| `compressG2` (bind an uncompressed key) | 2,260 |
| `hashToG1` (expand_message_xmd, 2 × MAP_FP_TO_G1, G1ADD) | 26,559 |
| **`verifyMinSig`** (`hashToG1` + one 2-pair PAIRING_CHECK) | **131,765** |
| Certified header, mainnet tip (decode, hash, bind, `verifyMinSig`) | 191,961 |
| `dkgOutcomeKey` (read the key from a 2,477-byte boundary `extraData`) | 2,961 |

The pairing is about 105k of the 131k BLS check. The rest of a certified header (about 60k) is
the RLP decode of a 672-byte Tempo header and of the certificate items, the keccak of the header,
and copying the byte arrays. A steady-state bundle adds the Merkle-Patricia tail and the return
encoding on top of one certified header.

## 3. Cost per rotation

Each rotation is one more certified header plus the `extraData` read and a G2 compression:

| Rotations | Execution | Δ per rotation | Calldata |
|---|---|---|---|
| 0 | 229,289 | — | 18,284 |
| 1 | 417,228 | +187,939 | 29,444 |
| 2 | 603,624 | +186,396 | 40,432 |

The rotation rows use a synthetic boundary header. A mainnet boundary header is about 3.1 kB,
because its `extraData` holds the DKG outcome, so a real rotation needs more calldata.

A rotation is needed only when the group key changed (a full DKG). Reshares keep the key and need
no rotation, so a bundle that crosses many epochs without a key change still pays the steady-state cost.

## Test infrastructure

| File | Role |
|---|---|
| `test/verifiers/tempo/TempoGasReport.t.sol` | The measurement suite behind this report. |
| `test/verifiers/tempo/TempoGasUsage.t.sol` | The regression-tracked baselines (`script/gas/baselines.yml`, `npm run gas:check`) and the shared scenarios. |
| `test/helpers/TempoSyntheticProofs.sol` | BLS test signer, Tempo header and proof encoders, fixture loader. |
| `test/verifiers/tempo/fixtures/` | Real mainnet certificates and keys used by the primitive rows. |
