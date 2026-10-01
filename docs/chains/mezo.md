# Mezo → Hiero

Status: live-verified on Mezo mainnet (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `mezo_31612-1` / `cosmos:mezo_31612-1` |
| Chain type | L1, Cosmos SDK + CometBFT 0.38.19, EVM from an Evmos fork (mezod) |
| Finality source | CometBFT commit: > 2/3 of voting power; 15 of 21 validators, all power 1 |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 12,844,413 gas, 16.3 KB (live) |
| Rotation | Same as a typical bundle at the rotation header. Bundle + one hop is 22,792,493 gas, 18.9 KB and does **not** fit 15M; a missed rotation is caught up with one bundle per rotation header |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | `mezo_31612-1` | header `chain_id` in `test/e2e/fixtures/cometbft-live/mezo.json` |
| `storeKey` | `evm` | mezo-org/mezod `x/evm/types/key.go`; fixture `storeKey` |
| `evmStateKeyPrefix` | `0x02` | mezod `KeyPrefixStorage`; fixture `evmStateKeyPrefix` |
| `keyScheme` | `ED25519` | `/validators` key type |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | `0x69710c87447405cea8bb088381905ce133e4dd42` | fixture `target` |

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/evm/key?prove=true` at `H-1`. The fixture used `rpc.lavenderfive.com/mezo`.
- Rotations: rare, because every validator has power 1; only membership changes rotate the set.
  Each one needs its own bundle transaction, since bundle + hop exceeds 15M.
- History: ABCI proofs at `H-1` of each rotation header.
- Signatures: 15 of 21 (equal power, so ordering does not shrink the set); no aggregator.

## Chain-specific trust and caveats

- Equal voting power means 15 Ed25519 signatures per commit, 12.84M gas per bundle (86% of
  Hedera's limit). About 18 Ed25519 signatures fit in one bundle (family README §7), so a larger
  equal-power set would need the accumulator, which `CometBftVerifier` does not use yet.
- Mezo stores every written word as 32 B, deleting only on empty input (mezod source).
- No ClprService is deployed on Mezo yet; the live bundle proves absence of the channel slots.

## Live verification

- Fixture: `test/e2e/fixtures/cometbft-live/mezo.json` (header 12,208,006, hop header 12,208,001,
  captured 2026-10-01).
- Refresh: `npm run cometbft-live:refresh mezo`.
- Replay: `forge build && npm run test:e2e:cometbft-live`.
- Verified: full `verifyBundle` (15 Ed25519 signatures, `evm` multistore, five IAVL non-existence
  proofs); bundle + hop (does not fit); an existence proof of a non-zero slot; negatives (flipped
  signature byte, below threshold, stale anchor, wrong set, tampered IAVL proof, another chain id).

## Hiero → Mezo

Not built. Mezo runs an EVM, so the direction would deploy a Hiero verifier contract on Mezo. It
waits on the Hiero proof source, like every Hiero → chain direction.
