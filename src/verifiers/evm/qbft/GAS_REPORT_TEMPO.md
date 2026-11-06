# QBFT Verifiers on Tempo — Gas Report

This report measures `QbftHeaderModeVerifier` and `QbftContractModeVerifier` on a real Tempo network
and compares every number with the same bytecode and calldata on anvil (Ethereum Osaka schedule). The
scenarios are the ones behind `script/gas/baselines.yml`.

**Summary**

| What | Ethereum (anvil, Osaka) | Tempo localnet | Why |
|---|---|---|---|
| Header mode `verifyBundle`, steady state (1 validator), full tx | 158,792 | **158,792** | Pure computation. Same schedule today. |
| Header mode, rotation 51 → 52 validators | 1,396,296 | **1,396,296** | |
| Contract mode `verifyBundle`, steady state (3 validators) | 275,043 | **275,043** | |
| Contract mode, rotation 51 → 52 validators | 4,657,183 | **4,657,183** | |
| Deploy `QbftHeaderModeVerifier` | 3,797,205 | **18,190,805** (×4.8) | TIP-1000: 500,000 + 1,000 gas per code byte. |
| Deploy `QbftContractModeVerifier` | 3,799,063 | **18,209,463** (×4.8) | Same rule. |
| Header mode rotation 51 → 52 under TIP-1102 (draft) | — | **≈ 3,008,000** (×2.15) | ECRECOVER goes from 3,000 to 25,000 per seal. |

Verification costs exactly the same on both chains. Deployment costs about 4.8× more. A future Tempo
upgrade, TIP-1102 (still a draft), would roughly double the cost of a header-mode rotation (×1.4 in
contract mode), because every seal check is one ECRECOVER.

## Setup

- **Tempo**: the 3-validator localnet from `tools/tempo-localnet` (the image pinned in its
  `docker-compose.yml`, `tempo/v1.14.0-6957b77`), chain id 1337.
- **Ethereum baseline**: `anvil 1.7.1 --hardfork osaka`, the fork `foundry.toml` targets.
- **Inputs**: the exact calldata of the gas-baseline scenarios, built by
  `QbftHeaderModeProofBuilders` and `QbftContractModeProofBuilders` and printed by
  `test/gas/TempoVerifierInputs.t.sol`. Same bytecode on both chains: solc 0.8.30, via-ir, 2000 runs.
- **Method**: nothing is deployed or sent. `tools/tempo-localnet/measure-verifier-gas.ts` runs each
  constructor through `eth_call`, injects the returned runtime code with a state override, and reads
  `gasUsed` from `debug_traceCall`, which equals a receipt's `gasUsed`: the method reproduces the
  receipt values in `src/verifiers/hiero/GAS_REPORT_TEMPO.md` exactly, for example `PoseidonPermuteA`'s
  14,025,479-gas deployment on Tempo. The sender's
  nonce is overridden to 1, because a nonce-0 sender pays Tempo's 250,000-gas account-creation charge.

## 1. Verification: identical

Full transaction, `verifier.verify*(proof, anchor, context)` called directly:

| Scenario | Ethereum | Tempo | Calldata | Execution | ECRECOVER |
|---|---|---|---|---|---|
| Header mode, steady state, 1 validator | 158,792 | 158,792 | 1,540 B | 123,232 | 1 |
| Header mode, rotation 10 → 11 | 429,411 | 429,411 | 3,716 B | 365,095 | 16 |
| Header mode, rotation 51 → 52 | 1,396,296 | 1,396,296 | 9,924 B | 1,233,252 | 70 |
| Header mode, `verifyConfig` | 135,873 | 135,873 | 996 B | 107,457 | 2 |
| Contract mode, steady state, 3 validators | 275,043 | 275,043 | 3,012 B | 218,259 | 2 |
| Contract mode, rotation 10 → 11 | 944,686 | 944,686 | 15,876 B | 690,010 | 15 |
| Contract mode, rotation 51 → 52 | 4,657,183 | 4,657,183 | 91,108 B | 3,202,023 | 69 |
| Contract mode, `verifyConfig` | 228,002 | 228,002 | 2,148 B | 182,930 | 2 |

Execution is the full transaction minus the 21,000 base and the calldata gas. It equals the Foundry
figure in `script/gas/baselines.yml` for every row.

The only precompile either mode calls is ECRECOVER (`0x01`), at 3,000 gas per seal: 15% of the header
mode 51 → 52 rotation and under 5% of every contract-mode row. The rest is plain EVM execution: RLP
decoding, `keccak256` over headers and trie nodes, and the Merkle-Patricia walks. Tempo prices those
opcodes as Ethereum does today.

**Cost in dollars.** At Tempo mainnet's base fee of 2 × 10^10 attodollars per gas (TIP-1010), a
steady-state header-mode verification costs about **$0.003**, and a 51 → 52 rotation about **$0.028**
in header mode or **$0.093** in contract mode.

## 2. Deployment: about 4.8× more

TIP-1000 changes contract creation from `32,000 + 200 × bytes` to `500,000 + 1,000 × bytes`. For
every contract below, the difference is exactly `468,000 + 800 × code bytes`.

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `QbftHeaderModeVerifier` | 17,407 B | 3,797,205 | 18,190,805 |
| `QbftContractModeVerifier` | 17,428 B | 3,799,063 | 18,209,463 |
| `QBFTVerifier` (the router `bin/deploy.sh qbft-verifier` deploys today; removal tracked in issue #443) | 14,955 B | 3,271,050 | 15,703,050 |

Each fits well under Tempo's 30,000,000 per-transaction cap. One verifier costs about **$0.36** to
deploy at the mainnet base fee.

## 3. A QBFT bundle on Tempo, end to end

The service's side of a bundle does not depend on the verifier. Its costs on Tempo, including the
storage-creation charge per queued message, are measured in `src/verifiers/hiero/GAS_REPORT_TEMPO.md`.
For an ack-only `submitBundle` it adds about 145,000 gas, plus 2,100 per 32-byte word of the stored
trust anchor the service reads (128 bytes in header mode, 224 in contract mode). A rotation also
rewrites the anchor words that change, at 2,900 each, in the same slots.

| Component | Header mode, steady | Header mode, 51 → 52 | Contract mode, steady | Contract mode, 51 → 52 |
|---|---|---|---|---|
| Verifier execution | 123,232 | 1,233,252 | 218,259 | 3,202,023 |
| Proof calldata | 12,124 | 139,632 | 32,916 | 1,431,172 |
| Service, ack-only, and anchor read | ≈ 155,500 | ≈ 155,500 | ≈ 161,800 | ≈ 161,800 |
| Tx base | 21,000 | 21,000 | 21,000 | 21,000 |
| **Total** | **≈ 312,000** | **≈ 1,549,000** | **≈ 434,000** | **≈ 4,816,000** |

Each inbound message adds its payload's calldata, a small decode cost in the verifier, and the
service's per-message cost from the Hiero report. The signature and storage checks do not grow with
the message count, because one proven running hash covers every message.

## 4. What TIP-1102 would change

TIP-1102 (draft, no protocol version yet) reprices ECRECOVER from 3,000 to 25,000, and raises the
arithmetic, shift and `KECCAK256` opcodes (for example `KECCAK256` from 30 + 6 per word to 205 + 41 per
word, `SHL`/`SHR` from 3 to 9). The projection below re-prices each precompile call of the measured
trace and applies the opcode deltas to the opcode counts of the same execution:

| Scenario | Today | TIP-1102 | Precompile delta | Opcode delta |
|---|---|---|---|---|
| Header mode, steady state | 158,792 | ≈ 192,000 (×1.21) | +22,000 | +10,700 |
| Header mode, rotation 10 → 11 | 429,411 | ≈ 807,000 (×1.88) | +352,000 | +25,500 |
| Header mode, rotation 51 → 52 | 1,396,296 | ≈ 3,008,000 (×2.15) | +1,540,000 | +72,000 |
| Header mode, `verifyConfig` | 135,873 | ≈ 187,000 (×1.38) | +44,000 | +7,300 |
| Contract mode, steady state | 275,043 | ≈ 338,000 (×1.23) | +44,000 | +19,200 |
| Contract mode, rotation 10 → 11 | 944,686 | ≈ 1,340,000 (×1.42) | +330,000 | +64,900 |
| Contract mode, rotation 51 → 52 | 4,657,183 | ≈ 6,473,000 (×1.39) | +1,518,000 | +297,700 |
| Contract mode, `verifyConfig` | 228,002 | ≈ 287,000 (×1.26) | +44,000 | +14,700 |

The `KECCAK256` word count is read from the struct logger's per-step cost, so memory expansion
during a hash counts as extra words, a slight overestimate. Every scenario stays far below the
30,000,000 cap. Each additional seal in a rotation would cost 22,000 more than today. Re-measure with
this report's tooling as soon as a Tempo release ships TIP-1102.

## Reproduce

```shell
# Tempo localnet: tools/tempo-localnet/README.md, steps 1-2. Ethereum baseline:
anvil --hardfork osaka --port 8555 --silent --code-size-limit 100000 &

FOUNDRY_PROFILE=test forge build
CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv > /tmp/verifier-inputs.log
npx tsx tools/tempo-localnet/measure-verifier-gas.ts anvil http://127.0.0.1:8555 /tmp/verifier-inputs.log /tmp/anvil.json --opcodes
RUNTIME_RPC=http://127.0.0.1:8555 npx tsx tools/tempo-localnet/measure-verifier-gas.ts tempo http://127.0.0.1:18545 /tmp/verifier-inputs.log /tmp/tempo.json --opcodes
```

The QBFT rows are the `QbftHeaderModeVerifier` and `QbftContractModeVerifier` keys of the output JSON.

| File | Role |
|---|---|
| `test/gas/TempoVerifierInputs.t.sol` | Prints the calldata of the baseline scenarios. Does nothing unless `CLPR_DUMP_VERIFIER_INPUTS=1`. |
| `tools/tempo-localnet/measure-verifier-gas.ts` | Deployment and call gas, precompile breakdown, opcode counts and the TIP-1102 projection, from read-only RPC calls. |
| `test/verifiers/evm/qbft/GasUsage.t.sol`, `ContractModeGasUsage.t.sol` | The Foundry baselines for the same scenarios. |

References: TIP-1000 (state creation costs), TIP-1010 (mainnet gas parameters), TIP-1102 (draft
repricing), all at tips.sh.
