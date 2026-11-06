# Sei Verifier on Tempo — Gas Report

This report measures `SeiCometBftVerifier` and `Ed25519Verifier` on a real Tempo network and compares
every number with the same bytecode and calldata on anvil (Ethereum Osaka schedule).

**Summary**

| What | Ethereum (anvil, Osaka) | Tempo localnet | Why |
|---|---|---|---|
| One Ed25519 signature check, inside the verifier | 604,279 | **604,279** | Pure computation. Same schedule today. |
| Signed-header path, 1 signature | 793,734 | **793,734** | |
| One ICS-23 IAVL storage proof | 298,303 | **298,303** | |
| `verifyBundle`, n signing validators (extrapolated) | 1,979,273 + 604,279·n | **1,979,273 + 604,279·n** | 6 ICS-23 proofs plus one Ed25519 check per signature. |
| Deploy the 2-contract Sei verifier stack | 7,767,998 | **37,172,798** (×4.8) | TIP-1000: 500,000 + 1,000 gas per code byte. |
| One Ed25519 check under TIP-1102 (draft) | — | **≈ 876,600** (×1.45) | `MULMOD` goes from 8 to 65. |

Verification costs exactly the same on both chains. Deployment costs about 4.8× more. Tempo's
30,000,000 per-transaction cap bounds a bundle at about 45 signing validators today, and at about 31
under TIP-1102, a future Tempo upgrade (still a draft).

## Setup

- **Tempo**: the 3-validator localnet from `tools/tempo-localnet` (the image pinned in its
  `docker-compose.yml`, `tempo/v1.14.0-6957b77`), chain id 1337.
- **Ethereum baseline**: `anvil 1.7.1 --hardfork osaka`, the fork `foundry.toml` targets.
- **Inputs**: the real relay data in `SeiRealBundleFixtures` (a signed header and commit captured from
  `clpr-relay-sei1`, one validator, and a real IAVL non-existence proof), printed by
  `test/gas/TempoVerifierInputs.t.sol`. There is no full Sei bundle with real signatures in the
  repository, so the steps are measured as `test/verifiers/evm/sei/GasUsage.t.sol` measures them:
  `SeiGasHarness` returns the `gasleft()` delta of each step, and `verifyBundle` is extrapolated from
  them. Same bytecode on both chains: solc 0.8.30, via-ir, 2000 runs.
- **Method**: nothing is deployed or sent. `tools/tempo-localnet/measure-verifier-gas.ts` runs each
  constructor through `eth_call`, injects the returned runtime code with a state override, and reads
  `gasUsed` from `debug_traceCall`, which equals a receipt's `gasUsed`: the method reproduces the
  receipt values in `src/verifiers/hiero/GAS_REPORT_TEMPO.md` exactly, for example `PoseidonPermuteA`'s
  14,025,479-gas deployment on Tempo. The sender's
  nonce is overridden to 1, because a nonce-0 sender pays Tempo's 250,000-gas account-creation charge.
  `SeiGasHarness` is 25,382 bytes, over EIP-170, so its runtime is built on anvil (started with a raised
  code-size limit) and injected on Tempo; it is a test harness and is never deployed.

## 1. Verification: identical

Steps, from the `gasleft()` deltas `SeiGasHarness` returns:

| Step | Ethereum | Tempo |
|---|---|---|
| Ed25519 verification, per signature | 604,279 | 604,279 |
| Signed-header path, 1 signature (parse, validator-set hash, header hash, sign bytes, Ed25519) | 793,734 | 793,734 |
| ICS-23 IAVL storage proof, per slot | 298,303 | 298,303 |

Whole transactions:

| Transaction | Ethereum | Tempo | Calldata |
|---|---|---|---|
| `Ed25519Verifier.verify`, one real signature | 625,811 | 625,811 | 356 B |
| `SeiGasHarness.measureSignedHeader` | 834,407 | 834,407 | 804 B |
| `SeiGasHarness.measureIavlProof` | 345,690 | 345,690 | 1,348 B |

The only precompile is SHA-256 (`0x02`): 28 calls and 2,460 gas on the signed-header path, 35 calls and
3,288 gas per IAVL proof, under 1% of either. Ed25519 is implemented in Solidity, so almost all of the
cost is plain EVM arithmetic; one signature check runs 3,624 `MULMOD`, 6,546 `SHL` and 2,139 `SHR`. Tempo
prices those opcodes as Ethereum does today.

**`verifyBundle`, extrapolated.** A message-bearing bundle proves one multistore proof and 5 storage
slots, and `_verifyCommit` checks one Ed25519 signature per signing validator. As in `GasUsage.t.sol`,
the multistore proof is priced as one more IAVL proof:

`fixed = (793,734 − 604,279) + 6 × 298,303 = 1,979,273`, and `verifyBundle ≈ 1,979,273 + 604,279 · n`.

| Signing validators n | `verifyBundle` execution | At the mainnet base fee |
|---|---|---|
| 1 | 2,583,552 | $0.052 |
| 4 | 4,396,389 | $0.088 |
| 10 | 8,022,063 | $0.16 |
| 21 | 14,669,132 | $0.29 |
| 40 | 26,150,433 | $0.52 |

Tempo mainnet's base fee is 2 × 10^10 attodollars per gas (TIP-1010).

**The per-transaction cap.** A whole `submitBundle` also pays the 21,000 base, the proof calldata (about
130,000 for the header, the commit and the 6 proofs, plus about 1,700 per signature), about 145,000 for
the service's ack-only work (measured in `src/verifiers/hiero/GAS_REPORT_TEMPO.md`), and 2,100 per word
of the stored trust anchor, which holds 64 bytes per validator. That is about `2,290,000 + 610,000 · n`,
so Tempo's 30,000,000 cap (TIP-1010) allows about **45** signing validators per bundle. Osaka's
EIP-7825 cap of 16,777,216 allows about 23 on Ethereum.

## 2. Deployment: about 4.8× more

TIP-1000 changes contract creation from `32,000 + 200 × bytes` to `500,000 + 1,000 × bytes`. For both
contracts, the difference is exactly `468,000 + 800 × code bytes`.

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `Ed25519Verifier` | 12,206 B | 2,680,406 | 12,913,206 |
| `SeiCometBftVerifier` | 23,380 B | 5,087,592 | 24,259,592 |
| **Total** | | **7,767,998** | **37,172,798** |

`SeiCometBftVerifier` is at 95% of the EIP-170 limit, and its Tempo deployment uses 81% of the
30,000,000 per-transaction cap. There is no headroom problem today, but code added to this contract
raises the deployment by 1,000 gas per byte. The stack costs about **$0.74** to deploy at the mainnet
base fee.

## 3. What TIP-1102 would change

TIP-1102 (draft, no protocol version yet) raises `MULMOD` from 8 to 65, `ADDMOD` from 8 to 36,
`SHL`/`SHR` from 3 to 9 and `ISZERO` from 3 to 5, and SHA-256 to `104 + 13 per word`. The projection
below re-prices each precompile call of the measured trace and applies the opcode deltas to the opcode
counts of the same execution:

| Transaction | Today | TIP-1102 | Opcode delta | Precompile delta |
|---|---|---|---|---|
| `Ed25519Verifier.verify`, one signature | 625,811 | ≈ 898,200 (×1.44) | +272,400 | 0 |
| `measureSignedHeader`, 1 signature | 834,407 | ≈ 1,114,500 (×1.34) | +278,800 | +1,300 |
| `measureIavlProof` | 345,690 | ≈ 370,400 (×1.07) | +23,100 | +1,600 |

`MULMOD` alone is 206,568 of the Ed25519 increase. Per step, one signature goes from 604,279 to
≈ 876,600 and one IAVL proof from 298,303 to ≈ 323,000, so `verifyBundle ≈ 2,135,000 + 876,600 · n`,
and the 30,000,000 cap drops to about **31** signing validators per bundle. Re-measure with this
report's tooling as soon as a Tempo release ships TIP-1102.

## Reproduce

```shell
# Tempo localnet: tools/tempo-localnet/README.md, steps 1-2. Ethereum baseline (the raised code-size
# limit only lets SeiGasHarness be built):
anvil --hardfork osaka --port 8555 --silent --code-size-limit 100000 &

FOUNDRY_PROFILE=test forge build
CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv > /tmp/verifier-inputs.log
npx tsx tools/tempo-localnet/measure-verifier-gas.ts anvil http://127.0.0.1:8555 /tmp/verifier-inputs.log /tmp/anvil.json --opcodes
RUNTIME_RPC=http://127.0.0.1:8555 npx tsx tools/tempo-localnet/measure-verifier-gas.ts tempo http://127.0.0.1:18545 /tmp/verifier-inputs.log /tmp/tempo.json --opcodes
```

The Sei rows are the `SeiGasHarness` and `Ed25519Verifier` keys of the output JSON; `returns` holds the
step deltas.

| File | Role |
|---|---|
| `test/gas/TempoVerifierInputs.t.sol` | Prints the calldata of the steps above. Does nothing unless `CLPR_DUMP_VERIFIER_INPUTS=1`. |
| `tools/tempo-localnet/measure-verifier-gas.ts` | Deployment and call gas, precompile breakdown, opcode counts and the TIP-1102 projection, from read-only RPC calls. |
| `test/verifiers/evm/sei/GasUsage.t.sol` | `SeiGasHarness` and the Foundry version of the same extrapolation. |

References: TIP-1000 (state creation costs), TIP-1010 (mainnet gas parameters), TIP-1102 (draft
repricing), all at tips.sh.
