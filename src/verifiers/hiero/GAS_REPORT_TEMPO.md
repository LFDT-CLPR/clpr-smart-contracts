# Hiero Verifier on Tempo — Gas Report

Tempo runs the standard EVM, but its gas schedule is not Ethereum's. This report measures the
Hiero verifier and the `ClprService` on a real Tempo network and compares every number with the
same bytecode on anvil (Ethereum Osaka schedule).

**Summary**

| What | Ethereum (anvil, Osaka) | Tempo localnet | Why |
|---|---|---|---|
| `HieroVerifier.verifyBundle`, real fixture, full tx | 6,214,551 | **6,214,551** | Pure computation. Same schedule today. |
| Deploy the 6-contract Hiero verifier stack | 16,743,166 | **80,690,378** (×4.8) | TIP-1000: contract creation costs 500,000 + 1,000 gas per byte. |
| Deploy the 7-contract `ClprService` stack | 15,645,584 | **76,411,784** (×4.9) | Same rule, plus 250,000 per storage slot the constructor writes. |
| One new storage slot (SSTORE 0 → non-zero) | 43,391 (tx) | **275,591** (tx) | TIP-1000 state-creation charge, +232,200 per slot. |
| Same, when the contract has a storage credit | 43,391 | **30,591** | TIP-1060: every cleared slot mints a credit for the next creation in that contract. |
| `sendMessage`, 512-byte payload, real tx | 1,052,980 | **10,725,380** (×10) | 42 new slots (22 in the service, 20 in the mock connector), no credits. |
| `sendMessage`, 16-byte payload, real tx | 355,596 | **3,386,396** without credits, **1,426,396** with credits from earlier deletes | |
| Ack-only `submitBundle`, real tx | 154,191 | **168,803** | No new slots; Tempo gives no refund for the cleared slots. |
| Inbound DATA 16 B through `submitBundle`, charged in the fee asset | 523,037 (native value) | **3,540,459** (pathUSD) | Delivered and charged. Mostly the receiving app's storage; the service adds 3 slots. |
| Same, free execution (`messageExecutionCost = 0`) | — | **3,498,038** | Delivered; no balance check, charge or slash. |

The verifier itself costs the same. Creating state costs far more, unless the contract has
storage credits from earlier deletes (§3). Inbound DATA is delivered on Tempo with the service on a
fee token such as pathUSD, or with free execution (§4). A future Tempo upgrade (TIP-1102, still a draft) would also reprice the precompiles the
verifier relies on (§6).

## Setup

- **Tempo**: the 3-validator localnet from `tools/tempo-localnet` (the image pinned in its
  `docker-compose.yml`, `tempo/v1.14.0-6957b77`), chain id 1337, block gas limit 500,000,000. Fees are paid in the
  localnet's pathUSD by the funded first mnemonic account.
- **Ethereum baseline**: `anvil 1.7.1 --hardfork osaka`, the same fork `foundry.toml` targets.
- **Same bytecode and calldata on both**: solc 0.8.30, via-ir, 2000 runs, the committed fixtures
  `test/verifiers/hiero/fixtures/stateProof.bin` (5,668 bytes) and `trustAnchor.bin`.
- **Method**: real transactions, `gasUsed` from the receipt, per-callee breakdown from
  `debug_traceTransaction` with the call tracer. Deployment gas per contract is read from the
  receipts of the deploy CLI's transactions.
- Foundry internal-frame numbers from `test/verifiers/hiero/GasUsage.t.sol` are quoted where a
  comparison to `script/gas/baselines.yml` is useful.

## 1. Verification: identical

| Call | Ethereum | Tempo | Calldata | Intrinsic |
|---|---|---|---|---|
| `verifyBundle(proof, anchor, "")`, full tx | 6,214,551 | 6,214,551 | 5,668 B | 106,144 |
| hinTS BLS12-381 (n=8), harness tx | 960,580 | 960,580 | 3,012 B | 65,544 |
| WRAPS Groth16 + KZG, harness tx | 2,498,548 | 2,498,548 | 2,084 B | 49,580 |

The full-tx `verifyBundle` figure minus intrinsic gas is 6,108,407, against the 6,154,972 Foundry
frame in `baselines.yml`; the difference is the Foundry call overhead.

**First bundle versus steady state.** The trust anchor the service stores is
`keccak256(hintsVk) ‖ WRAPS step`. When its VK-hash half matches the bundle's hinTS key, WRAPS skips
re-hashing the 1,096-byte key with Poseidon:

| `verifyBundle`, real fixture, whole tx | Ethereum | Tempo |
|---|---|---|
| anchor does not match: first bundle, or the first after a hinTS key rotation | 6,214,551 | **6,214,551** |
| anchor matches: every following bundle | 4,574,201 | **4,574,201** |

A Hiero key rotation therefore costs one Poseidon pass, 1,640,350 gas, on the next bundle and
nothing else; there is no extra hop. Each additional message in a bundle adds one Merkle path,
1.19M to 1.41M gas in the table above, plus about 20k calldata gas.

The per-step breakdown that `test/verifiers/hiero/GasUsage.t.sol` prints was read from both live
chains through `eth_call` on an on-chain twin of that test (`test/helpers/HieroGasStepsHarness.sol`,
`tools/tempo-localnet/measure-hiero-steps.ts`). Same fixtures, same `gasleft()` deltas:

| Step | Foundry (`baselines.yml` ceiling) | Ethereum (anvil, Osaka) | Tempo localnet |
|---|---|---|---|
| Protobuf decode | 177,231 | 172,585 | **172,585** |
| Merkle path 1 (15 × SHA-384) | 1,407,156 | 1,406,757 | **1,406,757** |
| Merkle path 2 (15 × SHA-384) | 1,194,688 | 1,194,455 | **1,194,455** |
| hinTS BLS12-381 (n=8) | 902,642 | 899,229 | **899,229** |
| WRAPS Groth16 + KZG | 2,456,774 | 2,453,214 | **2,453,214** |
| **TOTAL** | 6,138,491 | 6,126,240 | **6,126,240** |

The small gap to the Foundry column is the harness call overhead the ceilings include. The trace of
`verifyBundle` shows the same precompile usage on both chains, 1,484,116 gas in total:

| Precompile | Calls | Gas | Share of `verifyBundle` |
|---|---|---|---|
| `0x0f` BLS12-381 pairing | 5 | 579,700 | 9.3% |
| `0x08` BN254 pairing (8 pairs) | 1 | 317,000 | 5.1% |
| `0x07` BN254 scalar mul | 46 | 276,000 | 4.4% |
| `0x0c` BLS12-381 G1 MSM | 2 | 100,428 | 1.6% |
| `0x0e` BLS12-381 G2 MSM | 2 | 90,000 | 1.4% |
| `0x05` MODEXP | 23 | 64,448 | 1.0% |
| `0x11` BLS12-381 map to G2 | 2 | 47,600 | 0.8% |
| `0x06`, `0x02`, `0x0d` | 59 | 8,940 | 0.1% |

The other 76% is plain EVM execution: protobuf decode, the two SHA-384 Merkle paths (SHA-384 is
implemented in Solidity, not a precompile), Poseidon, and copying. Tempo prices those opcodes as
Ethereum does today.

**Cost in dollars.** Tempo mainnet's base fee is 2 × 10^10 attodollars per gas (TIP-1010), so one
Hiero bundle verification is about **$0.12** at the base fee. TIP-1067's dynamic base fee can go
lower when blocks are not full.

## 2. Deployment: about 4.8× more

TIP-1000 changes contract creation from `32,000 + 200 × bytes` to `500,000 + 1,000 × bytes`.
Measured deltas match the formula exactly for every contract without constructor storage writes.

### Hiero verifier stack

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `PoseidonPermuteA` | 13,288 B | 2,927,079 | 14,025,479 |
| `PoseidonPermuteB` | 13,288 B | 2,927,055 | 14,025,455 |
| `PoseidonBN254Contract` | 1,794 B | 440,691 | 2,343,891 |
| `WRAPSVerifierContract` | 16,847 B | 3,693,107 | 17,638,707 |
| `TSSVerifier` | 15,714 B | 3,431,559 | 16,470,759 |
| `HieroVerifier` | 14,915 B | 3,323,675 | 16,186,087 |
| **Total** | | **16,743,166** | **80,690,378** |

### `ClprService` stack (deploy CLI, `all` mode)

| Contract | Code | Ethereum | Tempo |
|---|---|---|---|
| `ChannelLogic` | 9,978 B | 2,203,007 | 10,653,407 |
| `MessagingLogic` | 9,180 B | 2,030,512 | 9,842,512 |
| `BundleLogic` | 22,873 B | 4,983,624 | 23,750,024 |
| `ConnectorLogic` | 3,280 B | 755,997 | 3,847,997 |
| `AdminLogic` | 16,949 B | 3,704,399 | 17,731,599 |
| `BundleDecodeHelper` | 3,184 B | 739,784 | 3,754,984 |
| `ClprService` | 4,402 B | 1,228,261 | 6,831,261 |
| **Total** | | **15,645,584** | **76,411,784** |

`ClprService` costs 1.6M more than the formula predicts because its constructor writes seven
storage slots, each a new slot at 250,000. `BundleLogic` at 23.75M is the largest single
transaction and sits under Tempo's 30,000,000 per-transaction cap (TIP-1010). The cap was raised
from 16M to 30M precisely so that a 24,576-byte contract can still be deployed. Contracts near
the EIP-170 limit cost about 25M to deploy on Tempo. There is no headroom problem today, but a
verifier that bundles more code into one contract needs to check this number.

Whole stack, service plus Hiero verifier, at the mainnet base fee: about **$3.15**.

## 3. Storage: creation is expensive, deletion earns it back

### SSTORE transitions, one transaction each (7-byte probe contract)

| Transition | Ethereum | Tempo | Note |
|---|---|---|---|
| 0 → 1, slot never used, no credit | 43,391 | **275,591** | +232,200: the TIP-1000 creation charge |
| 1 → 2 | 26,663 | 26,663 | same |
| 2 → 0 (clear) | 21,670 | 31,179 | no refund on Tempo; a storage credit is minted instead |
| 0 → 1, different slot, one credit available | 43,391 | **30,591** | the credit pays the 245,000 creditable part |
| 0 → 1 in another contract, after a clear elsewhere | 43,391 | 275,591 | credits do not cross contracts |
| 3 → 3 | 23,863 | 23,863 | same |

This is TIP-1060 "Storage Credits" as implemented in the `edge` image the localnet runs: each
non-zero → zero write in a contract mints one credit for that contract; each later creation in
the same contract consumes one, and pays only the 5,000 set cost plus access. Credits persist
across transactions and never expire. The TIP page still lists the proposal as a draft targeting
T7, so confirm the mainnet build has it before relying on the numbers below.

### What CLPR operations create and delete

Counted with Foundry state-diff recording (`test/gas/TempoStorageWrites.t.sol`), service storage
only, internal call gas:

| Operation | New slots | Updates | Clears | Ethereum |
|---|---|---|---|---|
| `sendMessage`, first on the channel, 16 B data | 11 | 1 | 0 | 353,408 |
| `sendMessage`, steady state, 16 B data | 9 | 3 | 0 | 289,018 |
| `sendMessage`, steady state, 512 B data | 22 | 5 | 0 | 875,211 |
| `submitBundle`, 1 inbound DATA 5 B (enqueues 1 REPLY) | 3 | 3 | 0 | 530,703 |
| `submitBundle`, 1 inbound DATA 512 B (enqueues 1 REPLY) | 2 | 4 | 0 | 926,144 |
| `submitBundle`, 1 inbound REPLY (acks our DATA) | 0 | 2 | 9 | 73,516 |
| `submitBundle`, ack-only | 0 | 1 | 4 | 42,358 |

A queued message occupies about `3 + ceil(payloadBytes / 32)` slots, where the payload is the
application data plus roughly 90 bytes of protobuf framing. Every message is deleted again when it
is acked (REPLY and CONTROL) or answered (DATA), and each deleted slot is a credit for the next
message. So on Tempo the cost of a channel is driven by the **growth of its live queue**, not by
its throughput:

- A channel whose messages are acked promptly runs close to Ethereum cost. The measured 16-byte
  send after 13 deletes was 1,426,396 gas instead of 3,386,396.
- A backlog of unacked or unanswered messages pays the full 232,200 per slot, about $0.005 per
  32 bytes at the mainnet base fee.
- The receiving application's own storage follows the same rule. The e2e test double wrote 18 to
  40 slots per inbound message.

## 4. Full `ClprService` transactions, measured on chain

The whole flow on one chain, driven like the e2e harness (`tools/tempo-localnet/measure-submit-bundle.ts`):
`ClprService` stack, `E2EVerifier`, one channel, a bonded endpoint, a connector with the
`MockClprConnector` double, `E2EApplication` as sender and receiver. Three runs: native value on
anvil (0.1 ETH connector stake, 1 ETH operating balance), pathUSD as the `feeToken` on Tempo (100 USD
stake, 10 USD endpoint bond, 1 USD base penalty, 10 USD operating balance), and free execution on
Tempo (`messageExecutionCost` and every stake and bond zero). In every run each inbound DATA message
is delivered, `MessageDispatched` with `SUCCESS`, and in the charged runs paid, `ConnectorCharged`;
the script fails otherwise.

Two throttles were raised on both chains, `maxGasPerMessage` 1M → 8M and
`connectorInboundGasStipend` 500k → 3M, because the Ethereum defaults are too small on Tempo the
moment the application writes a few slots at 250,000 each.

| Transaction | Ethereum, native value | Tempo, pathUSD | Tempo, free execution | Tempo notes |
|---|---|---|---|---|
| `sendMessage`, first on channel, 16 B | 441,118 | **4,128,318** | **4,128,318** | 16 new slots: 11 service, 5 mock connector |
| `submitBundle`, 1 inbound DATA 16 B, delivered | 523,037 | **3,540,459** | **3,498,038** | app stores the message (test double), service adds 3 slots |
| `submitBundle`, 1 inbound REPLY, delivered | 266,505 | **1,008,017** | **1,008,017** | app stores the response |
| `submitBundle`, ack-only | 154,191 | **168,803** | **168,803** | 4 clears, no refund |
| `sendMessage`, steady, 16 B, after 13 deletes | 389,818 | **1,181,418** | **1,181,418** | storage credits cover most slots |
| `sendMessage`, steady, 512 B | 1,052,980 | **10,235,380** | **10,235,380** | 42 slots, last credits used |
| `submitBundle`, 1 inbound DATA 512 B, delivered | 1,197,880 | **8,582,110** | **8,537,724** | app stores 512 B; the connector callback runs out of its 3M stipend |
| `sendMessage`, steady, 16 B, no credits | 355,618 | **2,891,818** | **2,891,818** | 13 slots × 232,200 minus one credit |
| `sendMessage`, steady, 512 B, no credits | 1,052,980 | **10,725,380** | **10,725,380** | 42 slots × 232,200 |

In the pathUSD run the connector paid 3,846 micro-dollars (0.0038 USD) of execution charges for
the two inbound DATA messages, and the service passed all of it to the submitter: it held exactly
the 110 USD of stake and bond before and after. Charging costs 42,421 (16 B) and 44,386 (512 B) gas
more than free execution, for the TIP-20 balance reads and the two transfers. Every Tempo
transaction also emits a TIP-20 `Transfer` from the sender to the fee collector, the gas fee paid in
pathUSD.

What the rows say:

- **The service's own share of an inbound message is small.** It stores only the REPLY it
  generates, 2 to 3 slots. Almost all of the Tempo inbound cost above is the receiving
  application (the e2e double stores every message) and the connector callback. Real
  applications on Tempo pay 250,000 per slot they keep, so what an app persists per message
  decides its cost, not CLPR.
- **Outbound is where CLPR itself pays.** A queued message costs `3 + ceil(payload/32)` slots
  until it is acked, and the 512-byte send is 10× Ethereum.
- **Credits matter.** The same 16-byte send costs 1.18M right after 13 deletes and 2.89M with no
  credits left.
- **Throttles need Tempo values.** `maxGasPerMessage` and `connectorInboundGasStipend` sized for
  Ethereum fail on Tempo for any callee that writes storage. Both live in the ledger config and
  need no code change, but the peer's `maxGasPerMessage` is what a source chain enforces on
  sends, so it has to be set on the Tempo side and propagated.

## 5. A Hiero bundle on Tempo, end to end

| Component | Gas |
|---|---|
| `verifyBundle`, execution | 6,108,407 |
| Service overhead, ack-only bundle (measured, §4, minus intrinsic) | about 145,000 |
| Calldata, 5,668-byte proof | 85,144 |
| Tx base | 21,000 |
| **Total, ack-only** | **≈ 6,360,000**, within 1% of Ethereum |
| + one inbound DATA message | about +700,000 for the 3 slots of the service's REPLY, about +42,000 to charge it in pathUSD, plus whatever the application stores |

## 6. What TIP-1102 would change

TIP-1102 (draft, no protocol version yet) reprices opcodes and precompiles to about 1 GGas/s of
real work. Applied to the trace above, the precompile part of `verifyBundle` grows from 1.48M to
about 8.7M:

| Precompile | Today | TIP-1102 | Rule |
|---|---|---|---|
| `0x0f` BLS pairing (3 calls of 2 pairs, 2 of 3) | 579,700 | ≈ 3,154,000 | 230,000 + 167,000 per pair |
| `0x08` BN254 pairing, 8 pairs | 317,000 | 2,229,000 | 285,000 + 243,000 per pair |
| `0x07` BN254 scalar mul × 46 | 276,000 | 1,380,000 | 30,000 each |
| `0x0c` / `0x0e` MSM | 190,428 | ≈ 1,230,000 | ×6.5 base |
| `0x05` MODEXP × 23 | 64,448 | ≈ 450,000 | new complexity formula |
| `0x11` map to G2 × 2 | 47,600 | 190,000 | 95,000 each |

The pure-EVM part would rise as well: KECCAK256 ×6.8, MULMOD ×8, MOD ×8, SHL/SHR ×3, and the
SHA-384 Merkle paths and Poseidon rounds are built from exactly those opcodes. A single Hiero
bundle would then plausibly land between 15M and 25M gas, against the 30M per-transaction cap.
Re-measure with this report's tooling as soon as a Tempo release ships TIP-1102. The Tempo
verifier's own BLS check (one pairing of 2 pairs, 131k today) would go to about 560k.

T11, live on mainnet since 2026-09-10, changed none of this: TIP-1100 only raised the input
charge of Tempo's own system precompiles, which the verifier does not call.

## Reproduce

```shell
# Tempo localnet: tools/tempo-localnet/README.md, steps 1-2. Ethereum baseline:
anvil --hardfork osaka --port 8555 --silent &

# Hiero stack deploy, verifyBundle, harness txs, SSTORE probe, callTracer breakdown
FOUNDRY_PROFILE=test forge build
npx tsx tools/tempo-localnet/measure-hiero-gas.ts anvil http://127.0.0.1:8555 /tmp/anvil.json
npx tsx tools/tempo-localnet/measure-hiero-gas.ts tempo http://127.0.0.1:18545 /tmp/tempo.json

# Per-step breakdown (protobuf, Merkle paths, hinTS, WRAPS) via eth_call, same as GasUsage.t.sol
npx tsx tools/tempo-localnet/measure-hiero-steps.ts tempo http://127.0.0.1:18545

# SSTORE transition probe
npx tsx tools/tempo-localnet/probe-sstore.ts http://127.0.0.1:18545

# ClprService stack: deploy with the CLI, then read the receipts of the blocks it used
PRIVATE_KEY=0xac09…ff80 npx tsx script/deploy/cli.ts all --rpc-url http://127.0.0.1:18545 --output json
npx tsx tools/tempo-localnet/scan-deploy-gas.ts http://127.0.0.1:18545 <fromBlock> <toBlock> /tmp/deploy.json

# Storage slots per CLPR operation
FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoStorageWrites.t.sol -vv

# Storage credits probe, and the full ClprService flow: native value on anvil, pathUSD and free execution on Tempo
npx tsx tools/tempo-localnet/probe-storage-credits.ts http://127.0.0.1:18545
npx tsx tools/tempo-localnet/measure-submit-bundle.ts anvil http://127.0.0.1:8555 /tmp/submit-anvil.json
FEE_TOKEN=0x20C0000000000000000000000000000000000000 \
  npx tsx tools/tempo-localnet/measure-submit-bundle.ts tempo http://127.0.0.1:18545 /tmp/submit-tempo.json
FREE_EXECUTION=1 npx tsx tools/tempo-localnet/measure-submit-bundle.ts tempo-free http://127.0.0.1:18545 /tmp/submit-tempo-free.json
```

| File | Role |
|---|---|
| `tools/tempo-localnet/measure-hiero-gas.ts` | Deploys the Hiero stack and harnesses, sends the measured txs, records receipts and call traces. |
| `tools/tempo-localnet/measure-hiero-steps.ts`, `test/helpers/HieroGasStepsHarness.sol` | The per-step breakdown of `GasUsage.t.sol`, readable from a live chain. |
| `tools/tempo-localnet/measure-hiero-anchor.ts` | `verifyBundle` with a fresh versus a matching trust anchor. |
| `tools/tempo-localnet/probe-sstore.ts`, `probe-storage-credits.ts` | SSTORE transitions and the storage-credit behaviour on a 7-byte probe contract. |
| `tools/tempo-localnet/measure-submit-bundle.ts` | Deploys the service stack with real economics (native value, the `FEE_TOKEN` ERC-20, or free execution), wires a channel, connector and endpoint, measures `sendMessage` and `submitBundle` receipts, and fails unless every inbound DATA message is delivered and, when charged, paid. |
| `tools/tempo-localnet/scan-deploy-gas.ts` | Per-transaction gas and code size for a block range. |
| `test/gas/TempoStorageWrites.t.sol` | Storage-slot transitions per protocol operation. |
| `test/verifiers/hiero/GasUsage.t.sol` | The Foundry breakdown and the fixtures both chains were fed. |

References: TIP-1000 (state creation costs), TIP-1010 (mainnet gas parameters), TIP-1060
(storage credits), TIP-1100 and T11 (system precompile input pricing), TIP-1102 (draft
repricing), all at tips.sh.
