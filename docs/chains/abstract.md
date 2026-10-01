# Abstract

Abstract → Hiero · status: family-covered

Abstract is an EraVM ZK Stack rollup that settles on Ethereum, so `ZkSyncEraVerifier` covers it with a chain-specific
profile. It has not been verified on live data. A relayer needs an Abstract node with the proof API: on 2026-10-01
Abstract's public RPC answered "Method not implemented" for `zks_getProof`.

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | mainnet `eip155:2741`; testnet Abstract Sepolia `eip155:11124` |
| Chain type | L2, ZK Stack rollup, EraVM, settles on Ethereum |
| Finality source | Batch executed on L1 (`n ≤ totalBatchesExecuted` in Abstract's diamond proxy), read through the Ethereum sync committee |
| Verifier | `ZkSyncEraVerifier` + `ZkSyncStateTreeVerifier` + `EthL1StateVerifier`; family README: [ZKsync Era verifier](../../src/verifiers/evm/zksync/README.md) |
| Trust tier | Ethereum sync committee (2/3 of 512) + ZK Stack validity proofs and the chain's upgrade governance |
| Typical bundle | not measured on Abstract. The cost does not depend on the chain: each tree entry hashes 256 levels. Expect the [ZKsync Era](./zksync-era.md) figures |
| Rotation | in-bundle, same as ZKsync Era; not measured on Abstract |

## Deployment profile

| Parameter | Value | Where to read it |
|---|---|---|
| `diamondProxy` (mainnet) | not in the repo | `Bridgehub.getZKChain(2741)` on Ethereum mainnet |
| `diamondProxy` (Abstract Sepolia) | not in the repo | `Bridgehub.getZKChain(11124)` on Ethereum Sepolia (the Sepolia Bridgehub `0x35A54c8C757806eB6820629bc82d90E056394C92` is in `test/e2e/relay/buildZkSyncLiveProof.ts`) |
| `totalBatchesExecutedSlot` | 11 | `test/e2e/relay/zksync.ts` (`ZKCHAIN_STORAGE_LAYOUT`); check that `storage[11] == getTotalBatchesExecuted()` on Abstract's diamond |
| `storedBatchHashesSlot` | 14 | `test/e2e/relay/zksync.ts` |
| `protocolVersionSlot` | 33 | `test/e2e/relay/zksync.ts` |
| `minProtocolVersion`, `maxProtocolVersion` | choose a range that contains the diamond's current version. The repo's range is 0.29.0–0.30.x (`ZKSYNC_SEPOLIA` in `buildZkSyncLiveProof.ts`); the family README records 0.30.1 for Abstract and 0.29.1 for Abstract Sepolia on 2026-10-01 | `getSemverProtocolVersion()` on the diamond, or storage slot 33 |
| `EthL1StateVerifier` constructor | `(802, 9, 87, 6, 8192)` (Electra/Fulu) | `EthL1StateVerifier.sol` NatSpec; shared with ZKsync Era |
| Anchor GVR, fork version, bootstrap committee | Ethereum mainnet (or Sepolia) values | `/eth/v1/beacon/genesis`, `/eth/v1/config/spec`, `/eth/v1/beacon/light_client/bootstrap/{root}` |
| Anchor `codeHash` | the ClprService's versioned bytecode hash on Abstract, or zero | `zks_getProof(0x8002, [service], n)` from an Abstract node with the proof API |

Check also that `getSettlementLayer()` on the diamond is Ethereum L1, not ZKsync Gateway. The verifier does not check
it.

## Relayer requirements

- **Ethereum beacon API and execution RPC:** the same calls as [ZKsync Era](./zksync-era.md).
- **Abstract node with the tree API enabled.** The relayer needs `zks_getProof` and `zks_getL1BatchDetails` at
  executed batches. Abstract's public RPC does not serve `zks_getProof`.
- **Hedera:** `ZkSyncStateTreeVerifier.recordStorage` before any bundle with messages or a rotation.
- **Cadence:** one sync-committee rotation per Ethereum period (8,192 slots, about 27 hours).

## Chain-specific trust and caveats

- Same baseline as the family. Abstract's own upgrade governance replaces ZKsync's in the trust list.
- Data availability: rollup; the node is still the only source of tree proofs.
- Latency depends on Abstract's batch execution delay on L1. Not measured.
- If Abstract migrates settlement to ZKsync Gateway, the Channel stalls (see the family README, "Upgrades and forks").

## Live verification

None. No fixture exists for Abstract. A live run needs an Abstract node with the proof API and a copy of
`buildZkSyncLiveProof.ts` with Abstract's diamond, chain id and RPC.

## Other ZK Stack chains

Sophon (`eip155:50104`), Lens (`eip155:232`) and Cronos zkEVM (`eip155:388`) are covered the same way. They are
validiums: the state root is committed on L1 in the same way, and only the node holds the data. Their public RPCs
also did not serve `zks_getProof` on 2026-10-01.

## Hiero → Abstract direction

Not covered by this branch. It needs a Hiero verifier deployed on Abstract (EraVM) and a relayer that submits Hiero
bundles there.
