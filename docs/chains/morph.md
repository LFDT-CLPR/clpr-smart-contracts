# Morph

Morph → Hiero · status: live-verified on Ethereum mainnet (2026-10-01)

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:2818` |
| Chain type | L2, optimistic rollup with ZK proofs on challenge, settles on Ethereum; L2 state is an MPT |
| Finality source | `Rollup.finalizedStateRoots[batch]`, written by `finalizeBatch` after the 2-day challenge window, read through the Ethereum sync committee |
| Verifier | `L1RollupMptVerifier` + `EthL1StateVerifier`; family README: [L1-settled rollup verifiers](../../src/verifiers/evm/zkrollup/README.md) |
| Trust tier | **Trusts the Morph sequencer unless a whitelisted challenger challenges within 2 days**, plus the Ethereum sync committee and Morph's upgrade timelock (min delay 0 on 2026-10-01) |
| Typical bundle | live (stand-in, 5 absent slots): 1,922,495 gas, 16,804 B calldata |
| Rotation | in-bundle; derived rotation bundle 6,700,221 gas, 82,884 B |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `rollup` | `0x759894Ced0e6af42c26668076Ffa84d02E3CeF60` (Rollup proxy) | `test/e2e/relay/zkrollup.ts` (`MORPH_MAINNET`) |
| `stateRootsSlot` | 160 (`finalizedStateRoots`; `committedStateRoots` is 171 and is not used) | storage scan: for a committed but unfinalized batch slot 160 is zero and slot 171 is not |
| `implementation` | `0x213CE22b487B71Ac68a1B5b12d2b93D1AF30Ea1d` | EIP-1967 slot, 2026-10-01; verified source on Blockscout (`Rollup`, solc 0.8.24) |
| `minKey` | 0 | |
| Mapping key | batch index (`lastFinalizedBatchIndex()`) | `Rollup.finalizeBatch` |
| Parameters read 2026-10-01 | `finalizationPeriodSeconds` 172,800; `proofWindow` 259,200; `rollupDelayPeriod` 604,800 | `Rollup` getters |
| `EthL1StateVerifier` | `(802, 9, 87, 6, 8192)` | Electra/Fulu layout |
| Anchor GVR / fork | `0x4b36…fe95` / Fulu `0x06000000` | `capture.json` |
| ProxyAdmin / owner | `0x31110622D6CA24c9FF307d6ae1715F16E47F16A0` / timelock `0x542675E90E269F20ecbb9e0095d4751ac155B530` (`getMinDelay() = 0`) | mainnet reads, 2026-10-01 |

## Relayer requirements

- Ethereum beacon API and execution RPC as for the family; `eth_call lastFinalizedBatchIndex()` and
  `batchDataStore(batch)` (its third field is the batch's last L2 block) at the signed header's block.
- Morph RPC with `eth_getProof` about 2 days back. `rpc.morphl2.io` served it on 2026-10-01; Morph's QuickNode endpoint
  limits `eth_getProof` to the last 10,000 blocks. A Morph node with at least 3 days of state history is the production
  option.
- Cadence: one sync-committee rotation per Ethereum period.

## Chain-specific trust and caveats

- Morph's "finalized" means unchallenged: a batch committed by the submitter becomes final 2 days later unless a
  whitelisted challenger (`isChallenger`) challenges it; a challenged batch must be proven with a ZK proof within
  3 days. If all challengers stay silent, a false root is accepted. `commitBatchWithProof` (anyone, after 7 days of
  sequencer delay) finalizes with a ZK proof at once.
- Latency: at least 2 days; the finalized batch's last block was 173,559 s (48.2 h) older than the L1 block at capture.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/morph-live/capture.json`, captured 2026-10-01T08:36:22Z |
| Data | L1 block 26,096,312 (508/512 signers, Fulu); batch 61,081, root `0xef09…4595`, L2 block 27,538,430; stand-in predeploy `0x5300000000000000000000000000000000000001` |
| Refresh | `npm run zkrollup-live:refresh:morph` |
| Replay | `npm run test:e2e:zkrollup-live`; `forge test --match-contract MorphLiveTest -vv` |
| Verified | full bundle to 5 absent Channel slots; the family's rejection cases plus a tampered L2 storage proof |

## Hiero → Morph direction

Not covered by this branch. Morph runs the EVM; a Hiero verifier deployed on Morph and a relayer would serve it.
