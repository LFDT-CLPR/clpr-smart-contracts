# Bittensor

Bittensor → Hiero · status: live-verified on Bittensor mainnet (finney) (2026-10-01)

The date is the fixture capture timestamp (`recordedAt` 2026-10-01T04:06:17Z in
`test/e2e/fixtures/grandpa-live/bittensor.json`). "Live-verified" means real mainnet justifications and storage proofs
were replayed through the unmodified verifier on anvil. No ClprService is deployed on Bittensor yet.

Family README: [Substrate verifiers: GRANDPA and BEEFY](../../src/verifiers/evm/grandpa/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:964` (the Frontier EVM chain id; checked by `verifyConfig`) |
| Chain type | L1, Substrate solo chain (subtensor runtime: Aura + GRANDPA + Frontier) |
| Finality source | Its own GRANDPA, ed25519, 20 authorities of weight 1, threshold 14 |
| Verifier contract | [`GrandpaVerifier`](../../src/verifiers/evm/grandpa/GrandpaVerifier.sol), plus a deployed [`Ed25519Verifier`](../../src/verifiers/evm/sei/Ed25519Verifier.sol) |
| Trust tier | > 2/3 of the GRANDPA set's weight is honest; weak-subjectivity bootstrap checkpoint |
| Typical bundle | 9.36M gas, 14.3 KB (block #9,183,744, 14 ed25519 signatures) |
| Rotation bundle | 9.34M gas, 14.1 KB (set 5 → 6 at block #8,867,448) |

Gas is `eth_estimateGas` of the full transaction on anvil (Prague rules), from
`test/e2e/tests/verifiers/grandpa-live.spec.ts`. Hedera's limits are 15M gas and 128 KB.

## Deployment profile

Constructor of `GrandpaVerifier`. The values below are the ones the live spec deploys with. A production deployment
takes its bootstrap checkpoint from the chain at deploy time.

| Parameter | Value | Read from |
|---|---|---|
| `ed25519Verifier` | Address of a deployed `Ed25519Verifier` | `test/e2e/tests/verifiers/grandpa-live.spec.ts` (deploys it first) |
| `evmPalletPrefix` | `0x1da53b775b270400e7e61ed5cbc5a146` (`twox128("EVM")`) | `test/e2e/relay/substrate.ts` (`EVM_PALLET_PREFIX`); hex in `test/helpers/SubstrateSyntheticProofs.sol` |
| `chainId` | `eip155:964` | `test/e2e/fixtures/grandpa-live/bittensor.json` (`evmChainId`) |
| `bootstrapSetId` | `5` | `test/e2e/fixtures/grandpa-live/bittensor.json` (`rotation.setIdBefore`) |
| `bootstrapAuthoritiesHash` | `keccak256` of the packed set-5 authority list (`authoritiesBefore` without its SCALE length prefix) | `test/e2e/fixtures/grandpa-live/bittensor.json` (`rotation.authoritiesBefore`), packed by `packGrandpaAuthorities` in `test/e2e/relay/substrate.ts` |
| `bootstrapMinHeight` | `8867448` (the set-change block) | `test/e2e/fixtures/grandpa-live/bittensor.json` (`rotation.block.header.number` = `0x874e78`) |

Bootstrap source: `Grandpa::CurrentSetId` and `Grandpa::Authorities` read with `state_getStorage` at a trusted block
(`test/e2e/relay/buildGrandpaLiveFixture.ts:recordBittensor`).

## Relayer requirements

- RPC methods: `chain_getFinalizedHead`, `chain_getHeader`, `chain_getBlockHash`, `chain_getBlock` (for
  `justifications`, engine `FRNK`), `state_getStorage` (`Grandpa::CurrentSetId`, `Grandpa::Authorities`),
  `state_getReadProof` (the `EVM::AccountStorages` keys of the service). The recorder also uses `state_getKeysPaged`
  to pick real slots for the test.
- Justifications: the public RPCs do not expose `grandpa_*` methods. The relayer reads stored justifications from
  `chain_getBlock`. Nodes store one for every set-change block and periodically for others (the recorder steps back
  in 512-block strides). Proving an arbitrary block needs an own node.
- Archive depth: `state_getReadProof` at a stored-justification block needs a node that still has that state. The
  default RPC is the public archive endpoint `https://archive.chain.opentensor.ai`.
- Signature aggregation: none. The relayer re-packs at least 14 of the precommits into 102-byte votes.
- Rotation cadence: on every GRANDPA set change. How often Bittensor changes its set is not measured. Each change
  needs one bundle at the change block, because a rotation step plus a later final step (about 18M gas) does not
  fit in one transaction.

## Chain-specific trust and caveats

- Set changes are scheduled through `AdminUtils` (subtensor `GrandpaInterfaceImpl`, which bumps `CurrentSetId`
  itself and can also issue forced or delayed changes). A `ForcedChange` reverts with `ForcedChangeUnsupported` and
  needs a new bootstrap.
- ed25519 costs about 585k gas per signature in pure Solidity. The largest equal-weight set that fits is about 34
  authorities (estimate). Bittensor has 20 today.
- Bittensor has no BEEFY, so the cheaper secp256k1 route used for Hydration is not available.
- Spec version 470 at recording time (from the family README).

## Live verification

- Fixture: `test/e2e/fixtures/grandpa-live/bittensor.json`. It holds raw public-RPC responses: the set-6
  justification at #9,183,744 with its read proof, and the set-change block #8,867,448 (5 → 6, `ScheduledChange`
  with delay 0) justified by set 5.
- Refresh: `npm run grandpa-live:refresh -- bittensor` (override the RPC with `BITTENSOR_RPC`).
- Replay: `forge build && npm run test:e2e:grandpa-live` (the "Bittensor (GRANDPA, ed25519)" block, 11 cases).
- What is verified: on-chain `accountStorageKey` equals the chain's key derivation; a typical bundle with 14 of 20
  real ed25519 precommits and absent channel slots (zero metadata); the real 5 → 6 rotation returning the new
  anchor; three real non-zero EVM slots through the trie harness; rejection of a tampered signature, a commit below
  threshold, a wrong authority list, the old set's anchor, a replayed set id, a stale block, and a proof with the root node missing.
- The "service" is the live contract `0x6647dcbeb030dc8e227d8b1a2cb6a49f3c887e3c`, not a ClprService.

## Hiero → Bittensor direction

Not started on this branch. It needs a ClprService and a Hiero verifier deployed on Bittensor's Frontier EVM, and a
check of which precompiles the subtensor runtime exposes. Not measured.
