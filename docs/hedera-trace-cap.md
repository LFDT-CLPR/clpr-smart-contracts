# Hedera's contract trace-size cap and large-calldata verifiers

**Audience:** CLPR verifier authors and maintainers deploying `ClprService` and verifiers to a Hiero network
(Hedera mainnet, testnet, previewnet, or a Solo network).

Hiero consensus nodes limit the size of the contract trace they record for each transaction. A contract call
whose trace goes over the limit is executed, then failed with `INSUFFICIENT_GAS` and rolled back, although it had
enough gas. `eth_estimateGas` and anvil forks do not apply the limit, so they report success. Verifiers that take
a large input in one call (a full validator set or committee in `verifyConfig`, or a set change carried in a
bundle) are the CLPR code most likely to reach it.

This note explains the limit, how to measure a transaction against it, the budget it leaves a verifier, and design
patterns that stay inside it. All source links point at hiero-consensus-node tag
[`v0.77.2`](https://github.com/hiero-ledger/hiero-consensus-node/tree/v0.77.2), the latest release at the time
of writing.

## What the cap is

| Piece | Where |
| --- | --- |
| The setting `contracts.maxSerializedTraceDataBytes`, default **262,144** bytes (256 KiB), a network property set by the network's governance | [`ContractsConfig.java` L58-59](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-config/src/main/java/com/hedera/node/config/data/ContractsConfig.java#L58-L59) |
| A running estimate of the serialized trace size for one transaction; once over the limit it clears the trace and stays "exceeded" | [`TraceDataSizeLimiter.java`](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-app/src/main/java/com/hedera/node/app/workflows/handle/record/TraceDataSizeLimiter.java) |
| Record stream: each `ContractActions` and `ContractStateChanges` sidecar is measured with `PROTOBUF.measureRecord` and added to the estimate | [`RecordStreamBuilder.java` L1247, L1286, L1317](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-app/src/main/java/com/hedera/node/app/workflows/handle/record/RecordStreamBuilder.java#L1236-L1345) |
| Block stream: the same for `EvmTraceData.contract_actions` and `contract_slot_usages` | [`BlockStreamBuilder.java` L1367-L1401](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-app/src/main/java/com/hedera/node/app/blocks/impl/BlockStreamBuilder.java#L1367-L1401) |
| The failure: `if (hasExceededTraceDataSizeLimit(...)) throw new HandleException(INSUFFICIENT_GAS, rollbackHandler)`; the check also adds the estimated bytecode sidecar of any contract the call creates | [`ConversionUtils.throwIfUnsuccessfulCall` L801-L826](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-smart-contract-service-impl/src/main/java/com/hedera/node/app/service/contract/impl/utils/ConversionUtils.java#L801-L826) |

The trace is what the node publishes for every contract transaction: one `ContractAction` per call frame (call
type, caller, recipient, gas, **the full input**, **the full output** or revert reason, depth), one entry per storage
slot read or written, and the bytecode of contracts created. Precompile calls are frames like any other
(`ContractActionType.PRECOMPILE`), so their input and output count too. The mirror node serves the same data as
`/api/v1/contracts/results/{tx}/actions` and `.../state_changes`.

The cap first shipped in v0.74
([#26359](https://github.com/hiero-ledger/hiero-consensus-node/pull/26359)), turned into the clipping limiter
above in [#26434](https://github.com/hiero-ledger/hiero-consensus-node/pull/26434), and extended to contract calls
inside atomic batches and scheduled transactions in
[#27102](https://github.com/hiero-ledger/hiero-consensus-node/pull/27102).

## Why it shows up as `INSUFFICIENT_GAS`

The limiter runs while the stream records are built, after the EVM has finished. `throwIfUnsuccessfulCall` then
converts "trace too large" into `INSUFFICIENT_GAS` and rolls the transaction back. So:

- **Gas used is the full execution gas, whatever the gas limit.** Raising the limit does not help. The same
  transaction at a 5.6M and a 15M gas limit (Hedera's per-transaction maximum) fails with the same gas used.
- **The fee is charged** for the gas used, as for any failed execution.
- **No actions or state changes are recorded** for the transaction (the limiter clears them), so the mirror
  node's `actions` endpoint returns an empty list and there is no trace to debug from.

If a Hiero transaction fails with `INSUFFICIENT_GAS` and the gas used is well under the gas limit and identical
across retries, suspect the trace cap, not gas.

## Why `eth_estimateGas` and forks don't catch it

- **Mirror-node simulation** (`eth_estimateGas`, `eth_call` through the JSON-RPC relay) runs the consensus node's
  EVM with the sidecars switched off: the mirror node's web3 module sets `contracts.sidecars` to empty
  ([`EvmProperties.java` L178](https://github.com/hiero-ledger/hiero-mirror-node/blob/v0.164.0/web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java#L178)).
  With no actions recorded, the estimate never grows and the simulation succeeds.
- **anvil, Hardhat and other EVM forks** of a Hiero network have no trace cap at all. A fork replay reproduces
  the gas used exactly, which is useful, but it will report success.

The only checks that catch it are a trace-size estimate (below) or a real submission to a Hiero network.

## How to measure it

[`script/trace/trace-size.ts`](../script/trace/trace-size.ts) estimates the trace of one or more transactions from
any JSON-RPC endpoint that serves `debug_traceTransaction` with the `callTracer` and `prestateTracer`, such as an
anvil fork:

```sh
npm run trace:size -- <rpc url> <tx hash> [<tx hash> ...]
# <hash> actions 261, raw 301836 B, storage slots 37 -> ~331036 B (126.3 % of 262144)
```

It walks the call tree and adds up every frame's input and output, then adds about 96 B per frame and 112 B per
storage slot for the protobuf fields around them. The result is a conservative estimate, not the node's exact
`measureRecord` value. It exits with code 1 above 90 % of the cap (`HEDERA_TRACE_THRESHOLD`), so it can gate a
rehearsal or an e2e run; `HEDERA_TRACE_LIMIT` overrides the cap for networks configured differently.

To rehearse a transaction against a Hiero network's current state:

1. Start an anvil fork of the network's JSON-RPC relay at the latest block, or at the block before a transaction
   you are investigating (`anvil --fork-url <relay> --fork-block-number <n> --chain-id <id>`).
2. Impersonate the sender (`anvil_impersonateAccount`), fund it (`anvil_setBalance`), and send the same call data to
   the same contract (`cast send --unlocked`).
3. Run `trace-size.ts` on the fork transaction hash.

For a transaction that already failed on Hiero, the mirror node gives everything needed for step 2:
`/api/v1/contracts/results/{hash}` has `block_number`, `to`, `from` and `function_parameters`.

## Rough budgets

For a verifier input of `N` bytes that reaches the verifier through `ClprService`:

```
trace ≈ 3·N                          ClprService CALL, DELEGATECALL into the logic module, verifier STATICCALL
      + Σ (precompile input + output)
      + ~96 B per call frame + ~112 B per storage slot read or written
      ≤ 262,144 B
```

- **One input, three copies.** `ClprService` delegates to its logic modules, and the logic module calls the
  verifier, so the same bytes are recorded in at least three frames. With no precompile work, `N` tops out near
  87 KB, before framing and storage.
- **Per-item precompile calls count again.** A check that calls a precompile once per key records that key's bytes
  a fourth time, plus the precompile's output. For 128-byte BLS12-381 G1 keys checked with one `BLS12_G1ADD` call
  each, that is about 3 × 128 B + 384 B + 96 B ≈ 860 B per key, so roughly 300 keys fit in one transaction.
- **Bundles grow per message.** Message bytes appear in the proof, in the frames that carry it, and in the
  application call, so the trace of `submitBundle` grows with every message.
- **Contract creation** adds the created bytecode to the estimate.

## Design patterns that stay under the cap

- **Stage large trusted inputs in chunks, under the same trust anchor.** Instead of one `verifyConfig` (or one
  set-change bundle) carrying the whole validator set, submit the set in chunks in separate transactions. Each
  chunk is checked when it is staged and only a commitment (for example a Merkle subtree root) is stored; the final
  call references the commitments. The trust anchor and the final `verifyConfig` output must be byte-for-byte the
  same as the one-call path; test that parity directly. This is the shape of the staged-configuration proposal
  (separate PR).
- **Don't re-pass large calldata through extra frames.** Each extra `CALL`/`DELEGATECALL`/`STATICCALL` that
  forwards the same bytes records them again. Decode once, and pass hashes, offsets or the small decoded pieces to
  helpers. Prefer internal library functions over external calls for code that handles the full input.
- **Minimize precompile calls.** Batch work where a precompile allows it (one call over many points instead of one
  call per point), check whether a later call already validates the same inputs before adding a separate
  per-item check, and keep per-item precompile calls out of loops over large sets.
- **Keep return values small.** Outputs are recorded too; return a commitment or the fields the caller needs rather
  than echoing the input.
- **Budget traces like gas.** Record a per-transaction trace estimate next to the gas benchmarks for any verifier
  path meant to run on Hiero, and run `trace-size.ts` in e2e runs that target Hiero.

## Evidence from Hedera testnet

The measurements below come from deploying [CLPRouter](https://github.com/ColdAI-org/clprouter)
([live demo](https://clprouter-demo.doyoka-platform.workers.dev)) on Hedera testnet with `EthMainnetVerifier`.
Figures are from the Hedera testnet mirror node, re-checked on 2026-10-05.

The same `completeChannel` call to a `ClprService` (`0xa6db474e3047c3d43b10a4ff7abad547d89982b9`), carrying the
512-key `EthMainnetVerifier` configuration (67,364 B of call data), submitted five times:

| Transaction | Gas limit | Gas used | Result | Mirror-node actions |
| --- | ---: | ---: | --- | --- |
| [`0x6f0285ff…`](https://hashscan.io/testnet/transaction/0x6f0285ff22c877035165e025a01350fc7077fffe8bbb2a0f9d7fbebaed99781e) | 5,611,286 | 4,062,470 | `INSUFFICIENT_GAS` | none |
| [`0x4b95f023…`](https://hashscan.io/testnet/transaction/0x4b95f023fca443c71c9ed892be2dcd2aaf4ee247f819a7b91ff74c11b86d9643) | 12,949,122 | 4,062,470 | `INSUFFICIENT_GAS` | none |
| [`0xed92841b…`](https://hashscan.io/testnet/transaction/0xed92841b6bae53ef5da7c25d9f0412a1d397decbe6a2709f6d07292c46efec90) | 6,000,000 | 4,062,470 | `INSUFFICIENT_GAS` | none |
| [`0xa289c0b9…`](https://hashscan.io/testnet/transaction/0xa289c0b9ce2665fea2bceab8ad87c2a8ca21031b2d4a243a5f5c610e3379d0c7) | 6,000,000 | 4,062,470 | `INSUFFICIENT_GAS` | none |
| [`0x7dc546cd…`](https://hashscan.io/testnet/transaction/0x7dc546cdba0c66c0c0a5bb18014c60786071c69045489a4a2e8256826542cdf3) | 15,000,000 | 4,062,470 | `INSUFFICIENT_GAS` | none |

Replayed on an anvil fork of Hedera testnet at the block before the first attempt, the call succeeds with the same
4,062,470 gas. Its trace:

| Frame | Count | Input + output |
| --- | ---: | ---: |
| `CALL` `ClprService` | 1 | 67,364 B |
| `DELEGATECALL` into the logic module | 1 | 67,364 B |
| `STATICCALL` `EthMainnetVerifier.verifyConfig` | 1 | 68,260 B (67,012 in, 1,248 out) |
| `STATICCALL` ecrecover (`0x01`) | 1 | 160 B |
| `STATICCALL` `BLS12_G1ADD` (`0x0b`), one per key check | 257 | 98,688 B |
| **Total** | **261 frames, 37 storage slots** | **301,836 B raw, ~331,036 B estimated (126.3 % of the cap)** |

The raw frame data alone is 115 % of the cap. The same configuration staged in 16 chunks of 32 keys, then
opened with the 16 chunk roots, measured the same way:

| Transaction | Gas used | Frames | Raw | Estimate | Share of cap |
| --- | ---: | ---: | ---: | ---: | ---: |
| one chunk of 32 keys [`0xdf341d48…`](https://hashscan.io/testnet/transaction/0xdf341d4864af1506c95e52dde2aeb9659b9c06fc61e716b0d8be3cd0cb102ccd) | 171,716 | 18 | 10,724 B | ~12,564 B | 4.8 % |
| `completeChannel` with 16 roots [`0x28556511…`](https://hashscan.io/testnet/transaction/0x285565114acef4b37592e9ac115460bbfcabd547936e44fd515ed9919132a3d9) | 788,546 | 5 | 5,484 B | ~11,900 B | 4.5 % |
| `submitBundle`, one message, 14,829 B proof [`0x1249ca90…`](https://hashscan.io/testnet/transaction/0x1249ca9040fb4c1f02e99ee656823393b223bf9f2bcba9d2a6cdb36344e1989b) | 2,755,892 | 76 | 104,440 B | ~120,248 B | 45.9 % |

Each chunk transaction (about 4 KB of call data) also fits under Hedera's standard 6,144-byte transaction size.

To check a failure yourself:

```sh
M=https://testnet.mirrornode.hedera.com/api/v1
TX=0x6f0285ff22c877035165e025a01350fc7077fffe8bbb2a0f9d7fbebaed99781e
curl -s $M/contracts/results/$TX | jq '{result, gas_limit, gas_used, block_number}'
curl -s $M/contracts/results/$TX/actions   # empty list
```

## References

- hiero-consensus-node v0.77.2:
  [`ContractsConfig`](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-config/src/main/java/com/hedera/node/config/data/ContractsConfig.java),
  [`TraceDataSizeLimiter`](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-app/src/main/java/com/hedera/node/app/workflows/handle/record/TraceDataSizeLimiter.java),
  [`ConversionUtils`](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hedera-node/hedera-smart-contract-service-impl/src/main/java/com/hedera/node/app/service/contract/impl/utils/ConversionUtils.java),
  [`contract_action.proto`](https://github.com/hiero-ledger/hiero-consensus-node/blob/v0.77.2/hapi/hedera-protobuf-java-api/src/main/proto/streams/contract_action.proto)
- Pull requests: [#26359](https://github.com/hiero-ledger/hiero-consensus-node/pull/26359),
  [#26434](https://github.com/hiero-ledger/hiero-consensus-node/pull/26434),
  [#27102](https://github.com/hiero-ledger/hiero-consensus-node/pull/27102)
- [HIP-513: Smart Contract Traceability Extension](https://github.com/hiero-ledger/hiero-improvement-proposals/blob/main/HIP/hip-513.md) (the actions and state
  change sidecars)
- [`quirks.md`](quirks.md#hedera-trace-size-cap-fails-as-insufficient_gas)
