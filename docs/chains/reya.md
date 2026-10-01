# Reya → Hiero · status: family-covered (rollup layout checked on live L1 storage, 2026-10-01)

Reya is an Arbitrum Nitro chain that settles directly on Ethereum with BoLD rollup contracts. Its bundles
are verified on Hiero by `ArbitrumNitroVerifier` with a Reya profile. Family README: [src/verifiers/evm/arbitrum/README.md](../../src/verifiers/evm/arbitrum/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:1729` |
| Chain type | L2, Arbitrum Nitro (BoLD), settles on Ethereum mainnet; DA: AnyTrust (1-of-1 DAC) |
| Finality source | Ethereum sync committee over L1, then `_assertions[h].status == Confirmed` in the rollup |
| Verifier | `ArbitrumNitroVerifier` ([source](../../src/verifiers/evm/arbitrum/ArbitrumNitroVerifier.sol)), 13,948 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | Sync committee + BoLD fault proofs + rollup owner |
| Typical bundle | Not measured for this chain. Same code on Plume: 2,459,563 gas, 24,996 B; on Arbitrum Sepolia: 2,928,765 gas, 34,564 B |
| Rotation | Not measured for this chain. Plume rotation bundle: 7,408,325 gas, 91,268 B |

## Deployment profile

`new ArbitrumNitroVerifier(EthL1StateVerifier(802, 9, 87, 6, 8192), profile)`.

| Value | Reya | Read from |
|---|---|---|
| `rollup` | `0xB55002d2795217Fd3B91EcBb3385ba9A231E5327` | Rollup proxy on Ethereum; `chainId()` = 1729 |
| `rollupAdminLogic` / `rollupUserLogic` | `0x16ad566a…b724` / `0xa4892ffe…5451`, the same BoLD logic as Plume (full values on the Plume page) | EIP-1967 primary and secondary slots of the proxy |
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
- **Archive depth**: The confirmed block is about 6.4 days old: the relayer needs an archive node or a full node keeping at least 7 days of state. Public RPC retention was not measured.
- **Cadence**: one L1 sync-committee rotation per period (8,192 L1 slots, about 27 h). Latency is the
  assertion interval plus about 6.4 days.

## Chain-specific trust and caveats

- AnyTrust with a 1-of-1 data-availability committee: that one member can withhold data and stop honest challengers from rebuilding state.
- Validator whitelist and owner were not recorded in this work; read them before deployment.
- `anyTrustFastConfirmer` is `0x0`.
- `paused()` of the rollup is not checked; already-confirmed assertions stay valid.

## Live verification

None for Reya: no capture is recorded. The rollup layout was checked on live L1 storage on 2026-10-01.
To add one, add a network to `buildArbitrumLiveProof.ts` (as `--network plume` does) and add a spec that uses
`test/e2e/tests/verifiers/arbitrumLiveSuite.ts`. The same bytecode is live-verified on Plume and Arbitrum
Sepolia (`npm run test:e2e:plume-live`, `npm run test:e2e:arbitrum-live`).

## Hiero → Reya direction

Not built. It would deploy the Hiero verifier contracts on Reya; whether its ArbOS version provides the
EIP-2537 precompiles was not checked in this work.
