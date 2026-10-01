# Plume → Hiero · status: live-verified on mainnet data, typical and rotation bundles (anvil, 2026-10-01)

Plume is an Arbitrum Orbit chain (AnyTrust, custom gas token PLUME) that settles directly on Ethereum with
BoLD rollup contracts. Its bundles are verified on Hiero by `ArbitrumNitroVerifier` with the Plume profile.
Family README: [src/verifiers/evm/arbitrum/README.md](../../src/verifiers/evm/arbitrum/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:98866` |
| Chain type | L2, Arbitrum Orbit (Nitro, BoLD), AnyTrust DA, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee over L1, then `_assertions[h].status == Confirmed` in the rollup |
| Verifier | `ArbitrumNitroVerifier` ([source](../../src/verifiers/evm/arbitrum/ArbitrumNitroVerifier.sol)), 13,948 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | Weaker: sync committee + one whitelisted validator + rollup owner + AnyTrust DA committee |
| Typical bundle | 2,459,563 gas, 24,996 B calldata (508/512) |
| Rotation | Rotation bundle 7,408,325 gas, 91,268 B (next period 1872) |

## Deployment profile

`new ArbitrumNitroVerifier(EthL1StateVerifier(802, 9, 87, 6, 8192), profile)`; values checked on 2026-10-01.

| Value | Plume | Read from |
|---|---|---|
| `rollup` | `0x4eD3F488a5a4417839BbC39712EB76D8Aaee6eE8` | docs.plume.org contract list; `chainId()` 98866; `bridge()` = Bridge `0x3538…EF83`; sequencer inbox `0x85eC…0b59` |
| `rollupAdminLogic` | `0x16ad566aaa05fe6977a033de2472c05c84cab724` | EIP-1967 primary slot (same BoLD logic as Reya) |
| `rollupUserLogic` | `0xa4892ffe3deab25337d7d1a5b94b35daba255451` | EIP-1967 secondary slot |
| `layout` | `{assertionsSlot: 117, assertionStatusOffset: 25}` | Slot 116 == `latestConfirmed()`; `_assertions[h]` slot 0 status byte 25 == Confirmed, as `getAssertion(h).status` |
| `confirmPeriodBlocks` (not a parameter) | 40,320 L1 blocks (about 5.6 days) | `confirmPeriodBlocks()` |
| Trust anchor | Ethereum mainnet GVR, fork version and bootstrap committee; L2 `ClprService` code hash | Beacon API at deployment |

## Relayer requirements

- **Ethereum beacon API and execution RPC** (non-archive window): `finality_update` and committee data;
  `eth_getBlockByNumber`; `eth_getProof` of the rollup; `eth_getLogs` for `AssertionCreated` (decodes with
  the nitro-contracts v3 ABI; the preimage re-hashes to the assertion hash).
- **Plume RPC**: `rpc.plume.org` served `eth_getProof` at a confirmed block about 1.3M L2 blocks (about
  6 days) old, so full bundles work from a public RPC. L2 headers are standard Nitro (geth) RLP.
- **Cadence**: Plume asserts about every 12 h (3,579 L1 blocks between the live confirmed assertion and its
  child), so state reaches Hiero 5.6 to 6.1 days after it is produced. One L1 rotation per period
  (about 27 h).

## Chain-specific trust and caveats

- **Permissioned challenges.** `validatorWhitelistDisabled()` is false and `getValidators()` returns one EOA
  (`0x11f5…b1d5`). Only it can create or challenge assertions, so safety rests on that validator and the
  owner, not on an open fault-proof game.
- **AnyTrust DA.** A committee that certifies data it withholds could stop an honest challenger; with one
  whitelisted validator this adds no new party, but it stays in the trust set.
- **Owner.** `0xd688…8C04`, an upgradeable proxy (Orbit UpgradeExecutor pattern; its executors are not
  enumerable on-chain).
- `anyTrustFastConfirmer` is `0x0`. Nothing in the verifier changes from the Arbitrum One baseline: same
  bytecode, profile data only.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/plume-live/capture.json` (Ethereum slot 15333774, 508/512, Plume L2 block 95,299,114, assertion `0x7b8a…6984`, captured 2026-10-01); Foundry fixture `test/verifiers/evm/arbitrum/fixtures/plume-live.json` |
| Replay | `forge build && npm run test:e2e:plume-live` (12 of 12); `forge test --match-path 'test/verifiers/evm/arbitrum/ArbitrumNitroVerifierPlume.t.sol'` (32 of 32) |
| Refresh | `npm run plume-live:refresh` |

Verified on real mainnet data: full `verifyBundle` (typical and with a real sync-committee rotation whose
attested block proves an older confirmed assertion at L2 block 95,158,333), `verifyL2State`, and the full
negative matrix (pending and never-created assertions, unpinned logic, wrong header, wrong code hash,
another channel, BLS failures). The L2 account is WPLUME (`0xEa237441c92CAe6FC17Caaf9a7acB3f953be4bd1`) with
its real code hash; the channel slots are MPT exclusion proofs. Not yet run on Hedera.

## Hiero → Plume direction

Not built. Whether Plume's ArbOS version provides the EIP-2537 precompiles the Hiero verifier needs was not
checked.
