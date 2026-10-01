# Gnosis Chain → Hiero · status: live-verified on Gnosis and Chiado data (anvil, 2026-10-01)

Bundles from a CLPR Service on Gnosis Chain are verified on Hiero by `EthBeaconTwinVerifier`, the
Ethereum sync-committee light client with Gnosis parameters. Family README:
[src/verifiers/evm/ethtwins/README.md](../../src/verifiers/evm/ethtwins/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | Gnosis `eip155:100`; testnet Chiado `eip155:10200` |
| Chain type | L1, proof of stake, Ethereum consensus specs (Gnosis Beacon Chain), Fulu |
| Finality source | Sync-committee BLS aggregate (≥ 342 of 512) over the attested header |
| Verifier | `EthBeaconTwinVerifier` ([source](../../src/verifiers/evm/ethtwins/EthBeaconTwinVerifier.sol)), preset `EthTwinPresets.gnosis()` / `chiado()`, 20,182 B runtime |
| Trust tier | Light client: 2/3 of the current sync committee and the bootstrap committee |
| Typical bundle | Gnosis 1,934,671 gas, 23,108 B calldata (494/512); Chiado 2,926,126 gas, 44,196 B (452/512) |
| Rotation | `_verifyRotation` 4,836,051 gas, 66,902 B rotation items (Chiado 4,836,099); a rotation bundle adds the typical bundle, about 6.8M gas and 90,010 B in total (not measured as one call) |

## Deployment profile

| Parameter | Gnosis | Chiado | Read from |
|---|---|---|---|
| `genesisValidatorsRoot` | `0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47` | `0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e` | `/eth/v1/beacon/genesis`, 2026-10-01 |
| `forkVersion` | `0x06000064` (Fulu, epoch 1714688) | `0x0600006f` (Fulu, epoch 1353216) | `/eth/v1/config/spec`, `/eth/v1/config/fork_schedule` |
| `slotsPerSyncCommitteePeriod` | 16 × 512 = 8,192 | 16 × 512 = 8,192 | `SLOTS_PER_EPOCH`, `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` |
| `executionStateRootGindex` | 802 (depth 9) | 802 | Checked against the live `execution_branch` |
| `nextSyncCommitteeGindex` | 87 (depth 6) | 87 | Checked against the live `next_sync_committee_branch` |
| Bootstrap committee | `light_client/bootstrap/{finalized root}` | same | Beacon API |
| Peer code hash (fixture) | beacon deposit contract `0x0B98057eA310F4d31F2a452B414647007d1645d9` | `0xb97036A26259B7147018913bD58a774cf91acf25` | `eth_getProof`; a real deployment pins the `ClprService` code hash |

## Relayer requirements

- Beacon API with the light-client routes. Public nodes that serve them: `gnosis-beacon-api.publicnode.com`
  and `rpc-gbc.gnosischain.com` (Gnosis), `rpc-gbc.chiadochain.net` (Chiado; publicnode's Chiado node has
  none).
- Execution RPC with `eth_getProof` and `eth_getBlockByNumber` at the attested block.
- Rotation every 8,192 slots of 5 s, about 11.4 h. The light-client update for a period is usually older
  than the public `eth_getProof` window (about 128 blocks on publicnode, under 40 on others), so the
  relayer proves the rotation from a recent attested header or uses an archive RPC.

## Chain-specific trust and caveats

- Same light-client trust as Ethereum, with Gnosis's own validator set behind the sync committee.
- The GVR and fork version are pinned in the constructor: `verifyConfig` reverts with
  `ChainIdentityMismatch` for any other chain or fork version.
- The period is shorter than Ethereum's (about 11.4 h against 27.3 h), so rotations are more than twice as
  frequent.

## Live verification

| | |
|---|---|
| Fixtures | `test/e2e/fixtures/ethtwins-live/gnosis.json` (slot 30365892), `chiado.json` (slot 25085300), captured 2026-10-01 |
| Replay | `forge build && npm run test:e2e:ethtwins-live` |
| Foundry | `forge test --match-path 'test/verifiers/evm/ethtwins/*'` (uses `test/verifiers/evm/ethtwins/fixtures/gnosis.json`) |
| Refresh | `npm run ethtwins-live:refresh` |

Verified: the real sync-committee signature, execution branch at gindex 802 and account proof through the
unmodified `verifyBundle`, a real rotation at gindex 87 (periods 3707 and 3063), and rejection of tampered
branches and signatures. The storage step proves exclusion, because the deposit contract has no CLPR
channel. Not yet run on Hedera.

## Hiero → Gnosis direction

Not built. Gnosis's EVM is Osaka-level: EIP-2537 is present (G1ADD on two points at infinity returns 128
zero bytes) and MCOPY, TSTORE and CLZ work, so the Hiero verifier contracts could be deployed as they are.
It needs a deployment, a `ClprService` on Gnosis, and Hiero state proofs (see the Ethereum page's notes on
the Hiero side).
