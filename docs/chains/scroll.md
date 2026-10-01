# Scroll

Scroll → Hiero · status: live-verified on Ethereum mainnet (2026-10-01)

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:534352` |
| Chain type | L2, zk rollup, settles on Ethereum; L2 state is an Ethereum MPT since the Euclid upgrade |
| Finality source | `ScrollChain.finalizedStateRoots[batch]`, written after the ZK proof is verified, read through the Ethereum sync committee |
| Verifier | `L1RollupMptVerifier` + `EthL1StateVerifier`; family README: [L1-settled rollup verifiers](../../src/verifiers/evm/zkrollup/README.md) |
| Trust tier | Ethereum sync committee (2/3 of 512) + Scroll's validity proofs, its prover whitelist (enforced mode after 7 days) and its `ScrollOwner` upgrade keys |
| Typical bundle | live (stand-in, 5 absent slots): 2,098,879 gas, 18,948 B calldata |
| Rotation | in-bundle; derived rotation bundle 6,876,605 gas, 85,028 B |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `rollup` | `0xa13BAF47339d63B743e7Da8741db5456DAc1E556` (ScrollChain proxy) | `test/e2e/relay/zkrollup.ts` (`SCROLL_MAINNET`) |
| `stateRootsSlot` | 158 (`finalizedStateRoots`) | `storage[keccak(i ‖ 158)] == finalizedStateRoots(i)` checked on mainnet |
| `implementation` | `0x0a20703878E68E587c59204cc0EA86098B8c3bA7` | EIP-1967 slot, 2026-10-01; verified source on Blockscout (`ScrollChain`, solc 0.8.24) |
| `minKey` | 0 | Pre-Euclid zkTrie roots cannot be opened with MPT proofs, so they fail closed |
| Mapping key | batch index (`lastFinalizedBatchIndex()`) | `ScrollChain._afterFinalizeBatch` |
| `EthL1StateVerifier` | `(802, 9, 87, 6, 8192)` | Electra/Fulu layout |
| Anchor GVR / fork | `0x4b36…fe95` / Fulu `0x06000000` | `capture.json` |
| Anchor `codeHash` | keccak256 code hash of the ClprService on Scroll (`keccakCodeHash` in Scroll's `eth_getProof`) | L2 RPC |
| ProxyAdmin / owner | `0xEB803eb3F501998126bf37bB823646Ed3D59d072` / `ScrollOwner` `0x798576400F7D662961BA15C6b3F3d813447a26a6` | mainnet reads, 2026-10-01 |

## Relayer requirements

- Ethereum beacon API and execution RPC as for the family; `eth_call lastFinalizedBatchIndex()` and `eth_getProof` at
  the signed header's block.
- The batch's last L2 block: Scroll's batch API (`mainnet-api-re.scroll.io/api/batch?index=`, `end_block_number`),
  checked by state-root equality, or decoding of the commit transaction.
- Scroll RPC with `eth_getProof` at that block. `rpc.scroll.io` served it for a block 2.1 hours old; the publicnode
  endpoint returned proofs in the older zkTrie node format and must not be used.
- Cadence: one sync-committee rotation per Ethereum period.

## Chain-specific trust and caveats

- Finalization needs a whitelisted prover (`OnlyProver`); if none finalizes for 7 days (or L1 messages wait 7 days),
  enforced batch mode lets anyone commit and finalize with a proof (`SystemConfig.enforcedBatchParameters` =
  604,800 s, 604,800 s).
- Latency: the finalized batch's last block was 7,710 s (2.1 h) older than the L1 block at capture.
- Scroll's `eth_getProof` returns `keccakCodeHash` and `poseidonCodeHash`; the MPT account leaf is the standard
  4-field RLP with the keccak code hash.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/scroll-live/capture.json`, captured 2026-10-01T08:35:54Z |
| Data | L1 block 26,096,309 (508/512 signers, Fulu); batch 520,128, root `0xf288…47ad`, L2 block 35,234,875; stand-in L2MessageQueue `0x5300000000000000000000000000000000000000` |
| Refresh | `npm run zkrollup-live:refresh:scroll` |
| Replay | `npm run test:e2e:zkrollup-live`; `forge test --match-contract ScrollLiveTest -vv` |
| Verified | full bundle to 5 absent Channel slots; the family's rejection cases plus a tampered L2 storage proof |

## Hiero → Scroll direction

Not covered by this branch. Scroll runs the EVM; a Hiero verifier deployed on Scroll and a relayer would serve it.
