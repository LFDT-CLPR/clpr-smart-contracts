# Arbitrum Nova → Hiero · status: family-covered (rollup layout checked on live L1 storage, 2026-10-01)

Arbitrum Nova is an Arbitrum Nitro chain that settles directly on Ethereum with BoLD rollup contracts. Its bundles
are verified on Hiero by `ArbitrumNitroVerifier` with a Arbitrum Nova profile. Family README: [src/verifiers/evm/arbitrum/README.md](../../src/verifiers/evm/arbitrum/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:42170` |
| Chain type | L2, Arbitrum Nitro (BoLD), settles on Ethereum mainnet; DA: blobs (formerly AnyTrust) |
| Finality source | Ethereum sync committee over L1, then `_assertions[h].status == Confirmed` in the rollup |
| Verifier | `ArbitrumNitroVerifier` ([source](../../src/verifiers/evm/arbitrum/ArbitrumNitroVerifier.sol)), 13,948 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | Sync committee + BoLD fault proofs + rollup owner |
| Typical bundle | Not measured for this chain. Same code on Plume: 2,459,563 gas, 24,996 B; on Arbitrum Sepolia: 2,928,765 gas, 34,564 B |
| Rotation | Not measured for this chain. Plume rotation bundle: 7,408,325 gas, 91,268 B |

## Deployment profile

`new ArbitrumNitroVerifier(EthL1StateVerifier(802, 9, 87, 6, 8192), profile)`.

| Value | Arbitrum Nova | Read from |
|---|---|---|
| `rollup` | `0xE7E8cCC7c381809BDC4b213CE44016300707B7Bd` | Rollup proxy on Ethereum; `chainId()` = 42170 |
| `rollupAdminLogic` / `rollupUserLogic` | same as Arbitrum One (`0x7fc126ff…df17` / `0x6490ba0a…a60d`; read at deployment) | EIP-1967 primary and secondary slots of the proxy |
| `layout` | `{assertionsSlot: 117, assertionStatusOffset: 25}` | nitro-contracts v3.x layout; slot 116 == `latestConfirmed()` and status byte 25 == 2 on live storage, 2026-10-01 |
| `confirmPeriodBlocks` (not a parameter) | 45,818 L1 blocks (about 6.4 days) | `confirmPeriodBlocks()`; sets latency |
| Trust anchor | Ethereum mainnet GVR, fork version and bootstrap committee; L2 `ClprService` code hash | Beacon API at deployment |

## Relayer requirements

- **Ethereum beacon API**: `light_client/finality_update`, `light_client/bootstrap/{root}`,
  `light_client/updates` (rotation), `beacon/genesis`, `config/spec`.
- **Ethereum execution RPC** (non-archive window of about 128 blocks): `eth_getBlockByNumber` of the
  attested block, `eth_getProof` of the rollup (both logic slots, `_latestConfirmed`, `_assertions[h]`),
  and `eth_getLogs` for `AssertionCreated` at the node's `createdAtBlock`.
- **L2 RPC**: `eth_getBlockByHash` of the confirmed block and `eth_getProof` of the `ClprService` there.
- **Archive depth**: The confirmed block is about 6.4 days old: the relayer needs an archive node or a full node keeping at least 7 days of state. Public Nova RPC retention was not measured.
- **Cadence**: one L1 sync-committee rotation per period (8,192 L1 slots, about 27 h). Latency is the
  assertion interval plus about 6.4 days.

## Chain-specific trust and caveats

- Same BoLD contracts and owner model as Arbitrum One.
- `anyTrustFastConfirmer` is `0x0`.
- `paused()` of the rollup is not checked; already-confirmed assertions stay valid.

## Live verification

None for Arbitrum Nova: no capture is recorded. The rollup layout was checked on live L1 storage on 2026-10-01.
To add one, add a network to `buildArbitrumLiveProof.ts` (as `--network plume` does) and add a spec that uses
`test/e2e/tests/verifiers/arbitrumLiveSuite.ts`. The same bytecode is live-verified on Plume and Arbitrum
Sepolia (`npm run test:e2e:plume-live`, `npm run test:e2e:arbitrum-live`).

## Hiero → Arbitrum Nova direction

Not built. It would deploy the Hiero verifier contracts on Arbitrum Nova; whether its ArbOS version provides the
EIP-2537 precompiles was not checked in this work.
