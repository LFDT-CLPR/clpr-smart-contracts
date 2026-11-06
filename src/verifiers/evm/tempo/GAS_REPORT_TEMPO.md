# Tempo Verifier on Tempo — Gas Report

`GAS_REPORT.md` measures `TempoVerifier` under the Ethereum schedule. This report runs it on a real
Tempo network, the destination side of a Tempo-to-Tempo channel, and compares every number with the
same bytecode and calldata on anvil (Ethereum Osaka schedule).

**Summary**

| What | Ethereum (anvil, Osaka) | Tempo localnet | Why |
|---|---|---|---|
| `verifyBundle`, steady state, full tx | 269,633 | **269,633** | Pure computation. Same schedule today. |
| `verifyBundle`, one rotation | 468,764 | **468,764** | One more certificate. |
| Real mainnet certificate check (Presto tip) | 228,393 | **228,393** | |
| Deploy `TempoVerifier` | 3,912,026 | **18,729,626** (×4.8) | TIP-1000: 500,000 + 1,000 gas per code byte. |
| Steady state under TIP-1102 (draft) | — | **≈ 784,000** (×2.9) | BLS12-381 pairing 102,900 → 564,000. |

Verification costs exactly the same on both chains. Deployment costs about 4.8× more. A future Tempo
upgrade, TIP-1102 (still a draft), would roughly triple every bundle, because each certificate is one
BLS pairing check.

## Setup

- **Tempo**: the 3-validator localnet from `tools/tempo-localnet` (the image pinned in its
  `docker-compose.yml`, `tempo/v1.14.0-6957b77`), chain id 1337.
- **Ethereum baseline**: `anvil 1.7.1 --hardfork osaka`, the fork `foundry.toml` targets.
- **Inputs**: the gas-baseline scenarios of `TempoGasUsage.t.sol` (synthetic certificates signed with
  test BLS keys) and the real Presto mainnet certificate in `test/verifiers/tempo/fixtures/presto-tip.json`,
  checked through `TempoGasHarness.certify` from `TempoGasReport.t.sol`, all printed by
  `test/gas/TempoVerifierInputs.t.sol`. Same bytecode on both chains: solc 0.8.30, via-ir, 2000 runs.
- **Method**: nothing is deployed or sent. `tools/tempo-localnet/measure-verifier-gas.ts` runs the
  constructor through `eth_call`, injects the returned runtime code with a state override, and reads
  `gasUsed` from `debug_traceCall`, which equals a receipt's `gasUsed`: the method reproduces the
  receipt values in `src/verifiers/hiero/GAS_REPORT_TEMPO.md` exactly, for example `PoseidonPermuteA`'s
  14,025,479-gas deployment on Tempo. The sender's
  nonce is overridden to 1, because a nonce-0 sender pays Tempo's 250,000-gas account-creation charge.

## 1. Verification: identical

Full transaction, called directly:

| Scenario | Ethereum | Tempo | Calldata | Execution | Precompiles |
|---|---|---|---|---|---|
| `verifyBundle`, steady state | 269,633 | 269,633 | 1,956 B | 229,289 | 115,791 (42.9%) |
| `verifyBundle`, one rotation | 468,764 | 468,764 | 3,140 B | 417,228 | 231,582 (49.4%) |
| `verifyBundle`, two rotations | 666,068 | 666,068 | 4,292 B | 603,624 | 347,373 (52.2%) |
| `verifyConfig` | 253,111 | 253,111 | 1,380 B | 219,523 | 115,791 (45.7%) |
| Presto mainnet certificate, header decode to BLS check | 228,393 | 228,393 | 1,572 B | 191,961 | 115,791 (50.7%) |

Execution is the full transaction minus the 21,000 base and the calldata gas. It equals the Foundry
figures in `script/gas/baselines.yml` and `GAS_REPORT.md`. Every certificate costs the same set of
precompile calls:

| Precompile | Calls | Gas |
|---|---|---|
| `0x0f` BLS12-381 pairing (2 pairs) | 1 | 102,900 |
| `0x10` BLS12-381 map to G1 | 2 | 11,000 |
| `0x05` MODEXP (field reduction) | 2 | 1,000 |
| `0x02` SHA-256 (message expansion) | 5 | 516 |
| `0x0b` BLS12-381 G1 add | 1 | 375 |

The rest is plain EVM execution: RLP decoding, point compression for the key and signature binding,
and the Merkle-Patricia walks. Tempo prices those opcodes as Ethereum does today.

**Cost in dollars.** At Tempo mainnet's base fee of 2 × 10^10 attodollars per gas (TIP-1010), a
steady-state verification costs about **$0.005**, and each rotation it carries adds about $0.004.

## 2. Deployment: about 4.8× more

TIP-1000 changes contract creation from `32,000 + 200 × bytes` to `500,000 + 1,000 × bytes`. The
difference below is exactly `468,000 + 800 × code bytes`.

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `TempoVerifier` | 17,937 B | 3,912,026 | 18,729,626 |

It fits under Tempo's 30,000,000 per-transaction cap with 11.3M to spare, and costs about **$0.37** to
deploy at the mainnet base fee.

## 3. A Tempo bundle on Tempo, end to end

The service's side of a bundle does not depend on the verifier. Its costs on Tempo, including the
storage-creation charge per queued message, are measured in `src/verifiers/hiero/GAS_REPORT_TEMPO.md`.
For an ack-only `submitBundle` it adds about 145,000 gas, plus 2,100 per 32-byte word of the 416-byte
stored trust anchor the service reads. A bundle with rotations also stores the new anchor in the
same slots: the block-number word and the 8 key words change, at 2,900 each, and the rest are 100-gas
no-ops. No new slot is created.

| Component | Steady state | One rotation |
|---|---|---|
| Verifier execution | 229,289 | 417,228 |
| Proof calldata | 13,772 | 24,920 |
| Service, ack-only, and anchor read | ≈ 174,400 | ≈ 174,400 |
| New anchor written | — | ≈ 26,600 |
| Tx base | 21,000 | 21,000 |
| **Total** | **≈ 438,000** | **≈ 664,000** |

Each inbound message adds its payload's calldata, a small decode cost in the verifier, and the
service's per-message cost from the Hiero report. The certificate check does not grow with the
message count, because one proven running hash covers every message.

## 4. What TIP-1102 would change

TIP-1102 (draft, no protocol version yet) reprices the BLS12-381 pairing to `230,000 + 167,000 per
pair`, map to G1 from 5,500 to 26,000, G1 add from 375 to 2,300 and SHA-256 to `104 + 13 per word`, and
raises the arithmetic, shift and `KECCAK256` opcodes. The projection below re-prices each precompile
call of the measured trace and applies the opcode deltas to the opcode counts of the same execution:

| Scenario | Today | TIP-1102 | Precompile delta | Opcode delta |
|---|---|---|---|---|
| `verifyBundle`, steady state | 269,633 | ≈ 784,100 (×2.91) | +504,300 | +10,200 |
| `verifyBundle`, one rotation | 468,764 | ≈ 1,494,300 (×3.19) | +1,008,500 | +17,000 |
| `verifyBundle`, two rotations | 666,068 | ≈ 2,201,800 (×3.31) | +1,512,800 | +23,000 |
| `verifyConfig` | 253,111 | ≈ 765,300 (×3.02) | +504,300 | +7,900 |
| Presto mainnet certificate | 228,393 | ≈ 738,700 (×3.23) | +504,300 | +6,100 |

Each certificate goes up by 504,263, almost all of it the pairing (+461,100) and the two map-to-G1
calls (+41,000). The `KECCAK256` word count is read from the struct logger's per-step cost, so memory
expansion during a hash counts as extra words, a slight overestimate. Every scenario stays far below
the 30,000,000 cap; a bundle would need about 40 rotations to reach it. Re-measure with this report's
tooling as soon as a Tempo release ships TIP-1102.

## Reproduce

```shell
# Tempo localnet: tools/tempo-localnet/README.md, steps 1-2. Ethereum baseline:
anvil --hardfork osaka --port 8555 --silent --code-size-limit 100000 &

FOUNDRY_PROFILE=test forge build
CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv > /tmp/verifier-inputs.log
npx tsx tools/tempo-localnet/measure-verifier-gas.ts anvil http://127.0.0.1:8555 /tmp/verifier-inputs.log /tmp/anvil.json --opcodes
RUNTIME_RPC=http://127.0.0.1:8555 npx tsx tools/tempo-localnet/measure-verifier-gas.ts tempo http://127.0.0.1:18545 /tmp/verifier-inputs.log /tmp/tempo.json --opcodes
```

The Tempo rows are the `TempoVerifier` and `TempoGasHarness` keys of the output JSON.

| File | Role |
|---|---|
| `test/gas/TempoVerifierInputs.t.sol` | Prints the calldata of the scenarios above. Does nothing unless `CLPR_DUMP_VERIFIER_INPUTS=1`. |
| `tools/tempo-localnet/measure-verifier-gas.ts` | Deployment and call gas, precompile breakdown, opcode counts and the TIP-1102 projection, from read-only RPC calls. |
| `test/verifiers/tempo/TempoGasUsage.t.sol`, `TempoGasReport.t.sol` | The Foundry baselines, and the harness for the real certificate. |

References: TIP-1000 (state creation costs), TIP-1010 (mainnet gas parameters), TIP-1102 (draft
repricing), all at tips.sh.
