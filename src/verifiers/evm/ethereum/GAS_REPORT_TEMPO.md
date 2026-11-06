# Ethereum Mainnet Verifier on Tempo — Gas Report

This report measures `EthMainnetVerifier` on a real Tempo network and compares every number with the
same bytecode and calldata on anvil (Ethereum Osaka schedule).

**Summary**

| What | Ethereum (anvil, Osaka) | Tempo localnet | Why |
|---|---|---|---|
| `verifyBundle`, 1 message, 512/512 signers, full tx | 832,733 | **832,733** | Pure computation. Same schedule today. |
| Same, 342/512 signers (the supermajority minimum) | 3,910,104 | **3,910,104** | One G1 MSM over the 170 non-signers. |
| Same, with the next sync committee (window widen or shift) | 5,679,176 | **5,679,176** | SSZ root of 512 keys, 1,058 SHA-256 calls. |
| `verifyConfig` | 6,844,735 | **6,844,735** | Both committees, 1,024 keys. |
| Deploy `EthMainnetVerifier` | 4,917,874 | **23,474,674** (×4.8) | TIP-1000: 500,000 + 1,000 gas per code byte. |
| 342/512 signers under TIP-1102 (draft) | — | **≈ 10,904,000** (×2.8) | BLS12-381 G1 MSM ×6.5. |

Verification costs exactly the same on both chains. Deployment costs about 4.8× more. A future Tempo
upgrade, TIP-1102 (still a draft), would raise the BLS precompiles several-fold, most of all at low
participation, where the non-signer MSM dominates.

## Setup

- **Tempo**: the 3-validator localnet from `tools/tempo-localnet` (the image pinned in its
  `docker-compose.yml`, `tempo/v1.14.0-6957b77`), chain id 1337.
- **Ethereum baseline**: `anvil 1.7.1 --hardfork osaka`, the fork `foundry.toml` targets.
- **Inputs**: bundles built by `EthBundleProofFactory` in the shape `EthGasReport.t.sol` measures
  (8-node account proof, 4-node storage proofs, dense branch nodes, real BLS signatures over the
  self-consistent committee of `EthCommitteeFixtures`), printed by `test/gas/TempoVerifierInputs.t.sol`.
  Same bytecode on both chains: solc 0.8.30, via-ir, 2000 runs.
- **Method**: nothing is deployed or sent. `tools/tempo-localnet/measure-verifier-gas.ts` runs the
  constructor through `eth_call`, injects the returned runtime code with a state override, and reads
  `gasUsed` from `debug_traceCall`, which equals a receipt's `gasUsed`: the method reproduces the
  receipt values in `src/verifiers/hiero/GAS_REPORT_TEMPO.md` exactly, for example `PoseidonPermuteA`'s
  14,025,479-gas deployment on Tempo. The sender's
  nonce is overridden to 1, because a nonce-0 sender pays Tempo's 250,000-gas account-creation charge.

## 1. Verification: identical

Full transaction, `verifier.verify*(proof, anchor, context)` called directly:

| Scenario | Ethereum | Tempo | Calldata | Execution | Precompiles |
|---|---|---|---|---|---|
| 1 message, 512/512 signers | 832,733 | 832,733 | 16,996 B | 547,105 | 155,500 (18.7%) |
| 1 message, 342/512 signers | 3,910,104 | 3,910,104 | 88,228 B | 2,554,280 | 1,220,488 (31.2%) |
| 10 messages, 512/512 signers | 865,702 | 865,702 | 17,668 B | 575,046 | 155,500 (18.0%) |
| 1 message, next committee, window widens | 5,679,176 | 5,679,176 | 83,908 B | 4,520,116 | 338,479 (6.0%) |
| 1 message, next committee, window shifts | 5,680,130 | 5,680,130 | 83,908 B | 4,521,058 | 338,479 (6.0%) |
| `verifyConfig` | 6,844,735 | 6,844,735 | 133,732 B | 5,087,103 | 192,750 (2.8%) |

Execution is the full transaction minus the 21,000 base and the calldata gas. The trace shows the
same precompile usage on both chains. At full participation:

| Precompile | Calls | Gas |
|---|---|---|
| `0x0f` BLS12-381 pairing (2 pairs) | 1 | 102,900 |
| `0x11` BLS12-381 map to G2 | 2 | 47,600 |
| `0x02` SHA-256 | 27 | 2,400 |
| `0x05` MODEXP | 4 | 2,000 |
| `0x0d` BLS12-381 G2 add | 1 | 600 |

At 342 signers, one `0x0c` G1 MSM over the 170 non-signer keys adds 1,064,988, and their Merkle
authentication adds 1,700 `KECCAK256` calls; the proof is 5× larger because it carries those keys.
With the next committee, 1,058 SHA-256 calls (89,004 gas) build its SSZ root from the 512 keys, and
257 G1 additions (96,375 gas) check that the 512 keys and the aggregate are on the curve, two points
per call. The rest is plain EVM execution: SSZ and
Merkle-Patricia walks, key compression, and copying. Tempo prices those opcodes as Ethereum does
today.

**Cost in dollars.** At Tempo mainnet's base fee of 2 × 10^10 attodollars per gas (TIP-1010), a
full-participation verification costs about **$0.017**, one at the supermajority minimum about
**$0.078**, and a committee hand-off about **$0.11**.

## 2. Deployment: about 4.8× more

TIP-1000 changes contract creation from `32,000 + 200 × bytes` to `500,000 + 1,000 × bytes`. The
difference below is exactly `468,000 + 800 × code bytes`.

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `EthMainnetVerifier` | 22,611 B | 4,917,874 | 23,474,674 |

At 22,611 bytes the contract is at 92% of the EIP-170 limit, and its Tempo deployment is under the
30,000,000 per-transaction cap with 6.5M to spare. It costs about **$0.47** to deploy at the mainnet
base fee.

## 3. An Ethereum bundle on Tempo, end to end

The service's side of a bundle does not depend on the verifier. Its costs on Tempo, including the
storage-creation charge per queued message, are measured in `src/verifiers/hiero/GAS_REPORT_TEMPO.md`.
For an ack-only `submitBundle` it adds about 145,000 gas, plus 2,100 per 32-byte word of the 428-byte
stored trust anchor the service reads.

| Component | 512/512 signers | 342/512 signers |
|---|---|---|
| Verifier execution | 547,105 | 2,554,280 |
| Proof calldata | 258,180 | 1,328,336 |
| Service, ack-only, and anchor read | ≈ 176,500 | ≈ 176,500 |
| Tx base | 21,000 | 21,000 |
| **Total** | **≈ 1,003,000** | **≈ 4,080,000** |

Calldata is a large share because the proof carries the non-signer keys and, on a hand-off, the next
committee. Each inbound message adds its payload's calldata, about 3,100 gas of verifier execution
(the 10-message row), and the service's per-message cost from the Hiero report.

## 4. What TIP-1102 would change

TIP-1102 (draft, no protocol version yet) reprices the BLS12-381 precompiles (pairing
`230,000 + 167,000 per pair`, G1 MSM base 12,000 → 78,000 with the same discount table, G1 add
375 → 2,300, G2 add 600 → 3,500, map to G2 23,800 → 95,000) and SHA-256 (`104 + 13 per word`), and raises
the arithmetic, shift and `KECCAK256` opcodes. The projection below re-prices each precompile call of
the measured trace and applies the opcode deltas to the opcode counts of the same execution:

| Scenario | Today | TIP-1102 | Precompile delta | Opcode delta |
|---|---|---|---|---|
| 1 message, 512/512 signers | 832,733 | ≈ 1,480,000 (×1.78) | +607,700 | +39,700 |
| 1 message, 342/512 signers | 3,910,104 | ≈ 10,904,000 (×2.79) | +6,465,100 | +529,000 |
| 10 messages, 512/512 signers | 865,702 | ≈ 1,514,000 (×1.75) | +607,700 | +40,700 |
| Next committee, window widens | 5,679,176 | ≈ 7,367,000 (×1.30) | +1,149,800 | +538,400 |
| Next committee, window shifts | 5,680,130 | ≈ 7,368,000 (×1.30) | +1,149,800 | +537,800 |
| `verifyConfig` | 6,844,735 | ≈ 8,733,000 (×1.28) | +989,500 | +899,000 |

The G1 MSM over the non-signers goes from 1,064,988 to 6,922,422 at 342 signers, so under TIP-1102 the
cost depends on participation even more steeply than today. The `KECCAK256` word count is read from
the struct logger's per-step cost, so memory expansion during a hash counts as extra words, a slight
overestimate. Every scenario stays under the 30,000,000 cap. Re-measure with this report's tooling as
soon as a Tempo release ships TIP-1102.

## Reproduce

```shell
# Tempo localnet: tools/tempo-localnet/README.md, steps 1-2. Ethereum baseline:
anvil --hardfork osaka --port 8555 --silent --code-size-limit 100000 &

FOUNDRY_PROFILE=test forge build
CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv > /tmp/verifier-inputs.log
npx tsx tools/tempo-localnet/measure-verifier-gas.ts anvil http://127.0.0.1:8555 /tmp/verifier-inputs.log /tmp/anvil.json --opcodes
RUNTIME_RPC=http://127.0.0.1:8555 npx tsx tools/tempo-localnet/measure-verifier-gas.ts tempo http://127.0.0.1:18545 /tmp/verifier-inputs.log /tmp/tempo.json --opcodes
```

The Ethereum rows are the `EthMainnetVerifier` keys of the output JSON.

| File | Role |
|---|---|
| `test/gas/TempoVerifierInputs.t.sol` | Prints the calldata of the scenarios above. Does nothing unless `CLPR_DUMP_VERIFIER_INPUTS=1`. |
| `tools/tempo-localnet/measure-verifier-gas.ts` | Deployment and call gas, precompile breakdown, opcode counts and the TIP-1102 projection, from read-only RPC calls. |
| `test/verifiers/evm/ethereum/EthGasReport.t.sol`, `EthBundleProofFactory.sol` | The Foundry report and the bundle builder the inputs come from. |

References: TIP-1000 (state creation costs), TIP-1010 (mainnet gas parameters), TIP-1102 (draft
repricing), all at tips.sh.
