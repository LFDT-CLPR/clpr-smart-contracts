# PulseChain → Hiero · status: live-verified on PulseChain and testnet v4 data (anvil, 2026-10-01)

Bundles from a CLPR Service on PulseChain are verified on Hiero by `EthBeaconTwinVerifier`, the Ethereum
sync-committee light client with PulseChain's Capella parameters. Family README:
[src/verifiers/evm/ethtwins/README.md](../../src/verifiers/evm/ethtwins/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | PulseChain `eip155:369`; testnet v4 `eip155:943` |
| Chain type | L1, proof of stake, Ethereum consensus specs, Capella (no Deneb scheduled) |
| Finality source | Sync-committee BLS aggregate (≥ 342 of 512) over the attested header |
| Verifier | `EthBeaconTwinVerifier` ([source](../../src/verifiers/evm/ethtwins/EthBeaconTwinVerifier.sol)), preset `EthTwinPresets.pulsechain()` / `pulsechainTestnetV4()`, 20,182 B runtime |
| Trust tier | Light client: 2/3 of the current sync committee (smaller, PLS-staked validator set) and the bootstrap committee |
| Typical bundle | 1,320,015 gas, 12,452 B calldata (502/512); testnet v4 1,326,191 gas, 13,092 B (500/512) |
| Rotation | Rotation bundle 6,195,813 gas, 79,300 B calldata; testnet v4 6,202,941 gas, 79,972 B |

## Deployment profile

| Parameter | PulseChain | Testnet v4 | Read from |
|---|---|---|---|
| `genesisValidatorsRoot` | `0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90` | `0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64` | `/eth/v1/beacon/genesis`, 2026-10-01 |
| `forkVersion` | `0x0000036c` (Capella since epoch 3) | `0x00000946` (Capella since epoch 4200) | `/eth/v1/config/spec`, `/eth/v1/config/fork_schedule` |
| `slotsPerSyncCommitteePeriod` | 32 × 256 = 8,192 | 32 × 256 = 8,192 | `config/spec` |
| `executionStateRootGindex` | 402 (depth 8) | 402 | Re-merkleized 11-field `BeaconBlockBody` and 15-field payload |
| `nextSyncCommitteeGindex` | 55 (depth 5) | 55 | Re-merkleized 28-field Capella `BeaconState` |
| Bootstrap committee | `current_sync_committee` from the SSZ state | same | `/eth/v2/debug/beacon/states/{state root}` |
| Peer code hash (fixture) | beacon deposit contract `0x3693693693693693693693693693693693693693` | same address | `eth_getProof`; a real deployment pins the `ClprService` code hash |

## Relayer requirements

- **No light-client API.** Lighthouse-Pulse v2.5.1 answers 404 on every `/eth/v1/beacon/light_client/*`
  route. The relayer uses `/eth/v1/beacon/headers/head`, `/eth/v2/beacon/blocks/{root}` (JSON and SSZ)
  and `/eth/v2/debug/beacon/states/{state root}` (SSZ, about 18 MB, about 1.4 s to merkleize) for every
  bundle. The beacon API must serve the `debug` namespace.
- Execution RPC with `eth_getProof` and `eth_getBlockByNumber` at the attested block; no archive node is
  needed, because the state used is recent.
- Rotation every 8,192 slots of 10 s, about 22.8 h. Any bundle can carry the next committee from the
  same state.

## Chain-specific trust and caveats

- The sync committee is drawn from PulseChain's validator set, which is smaller and PLS-staked, so
  corrupting 2/3 of a committee costs less than on Ethereum.
- Capella layout (402/55). A PulseChain move to Deneb (802/55) or Electra (802/87) needs a new
  deployment today; the tests check that a PulseChain bundle fails under the Electra layout.
- About 98% participation in the captures (502/512, 500/512).

## Live verification

| | |
|---|---|
| Fixtures | `test/e2e/fixtures/ethtwins-live/pulsechain.json` (slot 10703719), `pulsechain-testnet.json` (slot 10946641), captured 2026-10-01 |
| Replay | `forge build && npm run test:e2e:ethtwins-live` |
| Foundry | `forge test --match-path 'test/verifiers/evm/ethtwins/*'` (uses `test/verifiers/evm/ethtwins/fixtures/pulsechain.json`) |
| Refresh | `npm run ethtwins-live:refresh` |

Verified: the real signature, the execution branch at gindex 402, the account proof, and full rotation
bundles at gindex 55 (periods 1307 and 1337) through the unmodified `verifyBundle`. The storage step proves
exclusion, because the deposit contract has no CLPR channel. Not yet run on Hedera.

## Hiero → PulseChain direction

Blocked by PulseChain's EVM (erigon 2.4.1, Shanghai level), checked with `eth_call` against
`rpc.pulsechain.com` and `rpc.v4.testnet.pulsechain.com`:

- No EIP-2537: `0x0b` returns empty output and `eth_getCode(0x0d)` is empty. `TSSVerifier` needs `0x0c`,
  `0x0d`, `0x0e`, `0x0f` and `0x11`.
- No Cancun opcodes (MCOPY, TSTORE, BLOBHASH) and no Osaka (CLZ, KZG precompile `0x0a`). The repo compiles
  for Osaka.
- PUSH0, the BN254 precompiles `0x06`–`0x08` and `eth_getProof` are present.

It would need BLS12-381 in plain EVM code (gas-prohibitive) or a SNARK wrapper over BN254, and the
contracts rebuilt for Shanghai.
