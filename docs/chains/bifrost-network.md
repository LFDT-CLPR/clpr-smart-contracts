# Bifrost Network

Bifrost Network → Hiero · status: live-verified on Bifrost Network mainnet (2026-10-01)

The date is the fixture capture timestamp (`recordedAt` 2026-10-01T08:07:32Z in
`test/e2e/fixtures/grandpa-live/bifrost.json`). "Live-verified" means real mainnet justifications and storage proofs
were replayed through the unmodified verifier on anvil. No ClprService is deployed on Bifrost Network yet.

This page covers Bifrost Network (the BFC chain, EVM chain id 3068, runtime `thebifrost-mainnet`). It is not Bifrost
Finance, the Polkadot parachain.

Family README: [Substrate verifiers: GRANDPA and BEEFY](../../src/verifiers/evm/grandpa/README.md). Bifrost Network
uses the same `GrandpaVerifier` as Bittensor, with its own profile; no new contract code.

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:3068` (the Frontier EVM chain id, `eth_chainId` = `0xbfc`; checked by `verifyConfig`) |
| Chain type | L1, Substrate solo chain (runtime `thebifrost-mainnet`, spec 2048: Aura + GRANDPA + Frontier). No `ParachainSystem` pallet, so there is no relay-chain hop |
| Finality source | Its own GRANDPA, ed25519, 19 authorities of weight 1, threshold 13 |
| Verifier contract | [`GrandpaVerifier`](../../src/verifiers/evm/grandpa/GrandpaVerifier.sol) (17,750 B), plus a deployed [`Ed25519Verifier`](../../src/verifiers/evm/sei/Ed25519Verifier.sol) (12,206 B) |
| Trust tier | > 2/3 of the GRANDPA set's weight is honest; weak-subjectivity bootstrap checkpoint |
| Typical bundle | 8,439,093 gas, 8,100 B (block #39,008,064, 13 ed25519 signatures) |
| Rotation bundle | 8,430,845 gas, 8,388 B (set 130,024 → 130,025 at block #39,007,800) |

Gas is `eth_estimateGas` of the full transaction on anvil (Prague rules), from
`test/e2e/tests/verifiers/grandpa-live.spec.ts`. Hedera's limits are 15M gas and 128 KB, so both bundles fit.

## Deployment profile

Constructor of `GrandpaVerifier`. The values below are the ones the live spec deploys with. A production deployment
takes its bootstrap checkpoint from the chain at deploy time.

| Parameter | Value | Read from |
|---|---|---|
| `ed25519Verifier` | Address of a deployed `Ed25519Verifier` | `test/e2e/tests/verifiers/grandpa-live.spec.ts` (deploys it first) |
| `evmPalletPrefix` | `0x1da53b775b270400e7e61ed5cbc5a146` (`twox128("EVM")`) | Live `state_getKeysPaged` under `EVM::AccountStorages` returns keys with this prefix; `test/e2e/relay/substrate.ts` (`EVM_PALLET_PREFIX`) |
| `chainId` | `eip155:3068` | `test/e2e/fixtures/grandpa-live/bifrost.json` (`evmChainId`, from `eth_chainId`) |
| `bootstrapSetId` | `130024` | `test/e2e/fixtures/grandpa-live/bifrost.json` (`rotation.setIdBefore`) |
| `bootstrapAuthoritiesHash` | `keccak256` of the packed set-130,024 authority list | `rotation.authoritiesBefore`, packed by `packGrandpaAuthorities` in `test/e2e/relay/substrate.ts` |
| `bootstrapMinHeight` | `39007800` (the set-change block) | `rotation.block.header.number` |

Bootstrap source: `Grandpa::CurrentSetId` and `Grandpa::Authorities` read with `state_getStorage` at a trusted block
(`test/e2e/relay/buildGrandpaLiveFixture.ts:recordBifrost`).

The Frontier storage layout is the standard one (`EVM::AccountStorages`,
`StorageDoubleMap<Blake2_128Concat H160, Blake2_128Concat H256>`). The live spec proves three real non-zero slots of
the contract `0xb461b71dc9c379c686fb839e3d351b537028bdee` with keys derived by the verifier's own
`accountStorageKey`, which confirms the layout.

## Relayer requirements

- RPC methods: `chain_getFinalizedHead`, `chain_getHeader`, `chain_getBlockHash`, `grandpa_proveFinality` (the
  newest justification), `chain_getBlock` (stored `FRNK` justifications at set-change blocks), `state_getStorage`
  (`Grandpa::CurrentSetId`, `Grandpa::Authorities`), `state_getReadProof` (the service's `EVM::AccountStorages`
  keys). The public endpoint `https://public-01.mainnet.bifrostnetwork.com/rpc` exposes all of them.
- Justifications: unlike Bittensor's public RPC, Bifrost's exposes `grandpa_proveFinality`, so a relayer can fetch a
  justification for a recent block without its own node. Every set-change block has a stored justification.
- State depth: the public endpoint answered `state_getStorage` 100,000 blocks back and reported "State already
  discarded" 1,000,000 blocks back (checked 2026-10-01). Bundles only need recent state.
- Signature aggregation: none. The relayer re-packs 13 of the precommits into 102-byte votes.
- Rotation cadence: the GRANDPA set id changes every session of 300 blocks (`setLengthBlocks` in the fixture; block
  time 3 s, so every 15 minutes), even though the authority keys stay the same. Precommits sign `set_id`, so the
  verifier must follow every change: one rotation bundle per session.

## Chain-specific trust and caveats

- **Rotation load.** A change every 300 blocks means about 96 rotation bundles per day at about 8.43M gas each
  (about 809M gas per day, computed from the measured rotation bundle). A rotation step plus a later final step is
  two signature checks (about 16.9M gas, estimated as twice the measured bundle), which does not fit in one transaction, so a relayer that falls behind by
  `k` sessions needs `k` transactions to catch up. This is the dominant cost of a Bifrost channel.
- **Same keys, new set id.** In the live window the authority list did not change across set ids
  130,021 to 130,025. The anchor still moves, because the set id is part of the signed message.
- **Delay 0 changes.** The set change at #39,007,800 is a `ScheduledChange` with delay 0, the same shape as
  Bittensor's. A `ForcedChange` reverts with `ForcedChangeUnsupported` and needs a new bootstrap.
- ed25519 costs about 585k gas per signature in pure Solidity. 13 signatures fit with room to spare.

## Live verification

- Fixture: `test/e2e/fixtures/grandpa-live/bifrost.json`. It holds raw public-RPC responses: the newest
  justification at #39,008,064 (set 130,025, 13 of 19 precommits) with its read proof, and the set-change block
  #39,007,800 (130,024 → 130,025, `ScheduledChange` with delay 0) justified by set 130,024, each checked off-chain by
  the recorder before writing.
- Refresh: `npm run grandpa-live:refresh -- bifrost` (override the RPC with `BIFROST_RPC`).
- Replay: `forge build && npm run test:e2e:grandpa-live` (the "Bifrost Network (GRANDPA, ed25519)" block, 11 cases).
- What is verified: on-chain `accountStorageKey` equals the chain's key derivation; a typical bundle with 13 of 19
  real ed25519 precommits and absent channel slots (zero metadata); the real 130,024 → 130,025 rotation returning
  the new anchor; three real non-zero EVM slots through the trie harness; rejection of a tampered signature, a
  commit below threshold, a wrong authority list, the previous set's anchor (same keys, so the signatures fail on
  `set_id`), a replayed set id, a stale block, and a proof with the root node missing.
- The "service" is the live contract `0xb461b71dc9c379c686fb839e3d351b537028bdee`, not a ClprService.

## Hiero → Bifrost Network direction

Not started on this branch. It needs a ClprService and a Hiero verifier deployed on Bifrost Network's Frontier EVM,
and a check of which precompiles the runtime exposes. Not measured.
