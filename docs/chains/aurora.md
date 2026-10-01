# Aurora → Hiero

Aurora → Hiero · status: family-covered (aurora-engine storage proof live-verified on the Aurora silo `0x4e45415c.c.aurora`, NEAR mainnet, 2026-10-01; Aurora mainnet `aurora` not readable on public RPCs)

Aurora is an EVM (aurora-engine) running as the NEAR contract `aurora`. An Aurora transaction is
final when the NEAR block that executed it is final. `AuroraVerifier` reuses the NEAR light client of
`NearVerifier` and proves each EVM storage slot of the Solidity ClprService as an entry of the engine
account's NEAR contract data. Full design: [family README](../../src/verifiers/evm/neartons/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Aurora mainnet 1313161554 / `eip155:1313161554`; testnet 1313161555 / `eip155:1313161555` (`eth_chainId` of mainnet.aurora.dev, testnet.aurora.dev) |
| Chain type | EVM inside a NEAR contract (aurora-engine) |
| Finality source | NEAR light-client block approved by > 2/3 of NEAR producer stake |
| Verifier contract | `src/verifiers/evm/neartons/AuroraVerifier.sol` · [family README](../../src/verifiers/evm/neartons/README.md) |
| Trust tier | NEAR's (> 2/3 producer stake, epoch-window checkpoint) plus the configured engine account |
| Typical bundle | Live silo, engine state + generation + 6 slots: 2.80M gas, 64.7 KB with 31 cached approvals, after 2 cache transactions (8.90M, 4.92M gas). Inline: 15.70M gas, over one transaction |
| Rotation | NEAR epoch change inside the bundle: +679 gas, no extra calldata |

## Deployment profile

| Parameter | Mainnet value | Read from |
|---|---|---|
| `chainId` | `eip155:1313161554` | `eth_chainId` of https://mainnet.aurora.dev |
| `engineAccount` | `aurora` | aurora-engine deployment (NEAR account) |
| `evmChainId` | 1313161554 (must equal `chain_id` in the engine state `07 00 "STATE"`) | `engine/src/state.rs` |
| Checkpoint | A NEAR mainnet epoch window, as for [NEAR](./near.md) | `test/e2e/fixtures/aurora-live/mainnet.json` (`derived.checkpointPrev`) |
| Live silo used by the tests | `chainId` `eip155:1313161564`, `engineAccount` `0x4e45415c.c.aurora` (global contract `global.c.aurora`), `evmChainId` 1313161564 | `test/e2e/relay/buildAuroraLiveFixture.ts` (`AURORA_TARGET`), proven engine state |
| Storage keys | slot: `07 04 ‖ address ‖ [u32le generation] ‖ slot`; generation: `07 07 ‖ address` → u32be; zero words are not stored | aurora-engine `engine-types/src/storage.rs`, `engine/src/engine.rs` |
| ClprService slots | `Channel` +1, +2, +4, +5, +16, last message running hash, manifest slot 18 | `ClprEvmBundleVerifier.sol` |

## Relayer requirements

- NEAR mainnet RPC with `view_state` on the engine account. Public NEAR RPCs (rpc.mainnet.near.org,
  FastNEAR, dRPC and others tried) answer `TOO_LARGE_CONTRACT_STATE` for `aurora` on mainnet and
  testnet, so a relayer needs its own NEAR RPC node with a raised `trie_viewer_state_size_limit`.
  Silos with small state work on the public RPC.
- Per bundle: one `view_state` with `include_proof` per key (engine state, generation, each slot),
  all at the light-client block's `prev_block_hash`; absent keys return exclusion paths.
- Record the NEAR approvals in the cache first (2 transactions at 31 signers).

## Chain-specific trust and caveats

- The engine owner can upgrade aurora-engine. A change of the storage-key layout or of the
  engine-state encoding stops proofs (safe stall) until a new deployment.
- The engine-state existence proof binds the chosen shard to the engine account, so an exclusion
  proof cannot be taken from another shard.
- The service address's storage generation is always proven; a contract that self-destructed and was
  re-created reads only its current generation.
- Configuration fields come from the registration's ControlMessage, as for other EVM peers.
- Calldata: 8 trie paths took 64.7 KB on the silo; the main `aurora` trie is larger, so paths may be
  longer there (not measured).

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/aurora-live/mainnet.json` |
| Captured | 2026-10-01T07:47:56Z (NEAR height 218,032,460) |
| Refresh | `npm run neartons-live:refresh` (or `npx tsx test/e2e/relay/buildAuroraLiveFixture.ts --refresh`) |
| Replay | `forge build && npm run test:e2e:neartons-live`; forge: `forge test --match-path test/verifiers/evm/neartons/AuroraLive.t.sol -vv` |
| What was verified | NEAR mainnet light-client block (31 of 100 producers, via the cache) and epoch rotation; engine state with chain id 1313161564; wNEAR `0xc42c…501d` at generation 1 (proven): totalSupply, name, symbol, decimals, and two never-written slots (exclusion proofs); an EOA with generation 0 and an absent slot under the 54-byte key form |

## Hiero → Aurora direction

Not started on this branch. A Hiero verifier deployed on Aurora's EVM would be an ordinary EVM
deployment.
