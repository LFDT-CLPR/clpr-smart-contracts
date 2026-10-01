# ZKsync Era

ZKsync Era → Hiero · status: live-verified on ZKsync Sepolia over Ethereum Sepolia (2026-10-01, fixture capture timestamp)

ZKsync Era mainnet uses the same verifier and profile layout. Its storage layout, `StoredBatchInfo` hash and
`zks_getProof` output were checked by hand on 2026-10-01, but there is no committed mainnet fixture.

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | mainnet `eip155:324`; testnet ZKsync Sepolia `eip155:300` |
| Chain type | L2, ZK Stack rollup, EraVM, settles on Ethereum |
| Finality source | Batch executed on L1 (`n ≤ totalBatchesExecuted` in the diamond proxy), read through the Ethereum sync committee |
| Verifier | `ZkSyncEraVerifier` + `ZkSyncStateTreeVerifier` + `EthL1StateVerifier`; family README: [ZKsync Era verifier](../../src/verifiers/evm/zksync/README.md) |
| Trust tier | Ethereum sync committee (2/3 of 512) + ZK Stack validity proofs and ZKsync governance |
| Typical bundle | one tx: 14,529,485 gas, 27,492 B (live Sepolia, ACK-only, 6 tree entries). Split: `recordStorage` 12,632,320 gas / 5,892 B + `verifyBundle` 1,946,164 gas / 22,468 B |
| Rotation | in-bundle; synthetic 5.12M execution gas with 7 RECORDED entries, 69,675 proof bytes; live: not measured |

## Deployment profile

| Parameter | ZKsync Sepolia (`eip155:300`) | ZKsync Era mainnet (`eip155:324`) | Read from |
|---|---|---|---|
| L1 network | Ethereum Sepolia | Ethereum mainnet | `test/e2e/relay/buildZkSyncLiveProof.ts` (`ZKSYNC_SEPOLIA`) |
| `diamondProxy` | `0x9A6DE0f62Aa270A8bCB1e2610078650D539B1Ef9` | `0x32400084C286CF3E17e7B677ea9583e60a000324` | Sepolia: `buildZkSyncLiveProof.ts` and `capture.json` (`l1.diamondProxy`). Mainnet: `test/e2e/tests/verifiers/zksync-live-sepolia.spec.ts` (used there as "another chain's diamond"); confirm with `Bridgehub.getZKChain(324)` before deployment |
| Bridgehub | `0x35A54c8C757806eB6820629bc82d90E056394C92` | not in the repo; read from era-contracts deployment records | `buildZkSyncLiveProof.ts` |
| `totalBatchesExecutedSlot` | 11 | 11 | `test/e2e/relay/zksync.ts` (`ZKCHAIN_STORAGE_LAYOUT`) |
| `storedBatchHashesSlot` | 14 | 14 | `test/e2e/relay/zksync.ts` |
| `protocolVersionSlot` | 33 | 33 | `test/e2e/relay/zksync.ts` |
| `minProtocolVersion` | `29 << 32` (0.29.0) | same range is used in the repo | `buildZkSyncLiveProof.ts` (`ZKSYNC_SEPOLIA.minProtocolVersion`) |
| `maxProtocolVersion` | `30 << 32 ‖ 0xffffffff` (0.30.x) | same | `buildZkSyncLiveProof.ts` |
| Protocol version seen | 0.29.1 (`124554051585` = `0x1d00000001`) | 0.30.1 (by hand, 2026-10-01) | Sepolia: `capture.json` (`l1.protocolVersion`). Mainnet: family README |
| `EthL1StateVerifier` constructor | `(802, 9, 87, 6, 8192)` (Electra/Fulu) | same | `zksync-live-sepolia.spec.ts`, `EthL1StateVerifier.sol` NatSpec |
| Anchor GVR | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` | read `/eth/v1/beacon/genesis` on a mainnet beacon node | `capture.json` (`beacon.genesisValidatorsRoot`) |
| Anchor fork version | Fulu `0x90000075` | read `FULU_FORK_VERSION` (or the current fork) from mainnet `/eth/v1/config/spec` | `capture.json` (`beacon.spec`) |
| Anchor bootstrap committee | `light_client/bootstrap` of a finalized root | same | `test/e2e/relay/buildEthLiveProof.ts` |
| Anchor `codeHash` | the ClprService's versioned bytecode hash from `zks_getProof(0x8002, [service], n)`, or zero. The live fixture pins L2BaseToken's `0x010000ed…4db7` as a stand-in | same procedure | `buildZkSyncLiveProof.ts`, `capture.json` (`l2.proof.storageProof[0].value`) |

Re-check the slots and the protocol range against the chain's diamond at deployment.

## Relayer requirements

- **Ethereum beacon API:** `/eth/v1/beacon/light_client/finality_update`, `/eth/v1/beacon/light_client/bootstrap/{root}`,
  `/eth/v1/beacon/light_client/updates` (rotation), `/eth/v1/beacon/genesis`, `/eth/v1/config/spec`.
- **Ethereum execution RPC:** `eth_getStorageAt` and `eth_getProof` on the diamond at the attested block,
  `eth_getBlockByNumber`, `eth_getTransactionByHash` (the execute transaction, to decode `StoredBatchInfo`). A full
  node works if proofs are fetched while the attested block is recent; catch-up over old periods needs an archive
  node.
- **ZKsync RPC:** `zks_getL1BatchDetails` and `zks_getProof`. ZKsync's public RPCs serve both (the fixture used
  `https://sepolia.era.zksync.dev`).
- **Hedera:** `ZkSyncStateTreeVerifier.recordStorage` before any bundle with messages or a rotation (split path).
- **Cadence:** one sync-committee rotation per Ethereum period (8,192 slots, about 27 hours).

## Chain-specific trust and caveats

- Same as the family baseline: Ethereum sync committee, ZK Stack validity proofs and ZKsync governance.
- Latency: a block is deliverable once its batch executes on L1. On 2026-10-01 Era mainnet's
  `ValidatorTimelock.executionDelay()` was 10,800 s (3 hours), plus proving time; ZKsync Sepolia executed in about
  15 minutes. Neither is measured by a test.
- Era settles on Ethereum L1. If it moved settlement to ZKsync Gateway, the Channel would stall (see the family
  README, "Upgrades and forks").

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/zksync-sepolia-live/capture.json`, `capturedAt` 2026-10-01T04:34:25Z |
| Data | Sepolia attested slot 11257970, execution block 11819463, 487/512 participation, Fulu; ZKsync Sepolia batch 22329 (executed 2026-10-01T03:07:31Z), protocol 0.29.1 |
| Refresh | `npm run zksync-live:refresh` |
| Replay | `forge build && npm run test:e2e:zksync-live` |
| Verified | sync committee → L1 state root; diamond proof → executed batch → `StoredBatchInfo` → L2 root; one-tx `verifyBundle` with code hash and 5 Channel slots; split `recordStorage` + RECORDED bundle; rejections for a wrong code hash, tampered `StoredBatchInfo`, tampered sibling, another channel, out-of-range protocol version, another diamond, a dropped non-signer proof, and the previous fork version |

The live bundle proves the L2BaseToken system contract (`0x…800a`) as a stand-in for a ClprService, so its Channel
slots are genuine exclusion proofs and the metadata is zero.

## Hiero → ZKsync Era direction

Not covered by this branch. It needs a Hiero verifier deployed on ZKsync Era (EraVM, compiled with zksolc) and a
relayer that submits Hiero bundles there.
