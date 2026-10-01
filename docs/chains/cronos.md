# Cronos → Hiero

Status: live-verified on Cronos mainnet (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `cronosmainnet_25-1` / `cosmos:cronosmainnet_25-1` |
| Chain type | L1, Cosmos SDK + CometBFT 0.38.13, Ethermint EVM |
| Finality source | CometBFT commit: > 2/3 of voting power; 7 of 10 validators by power |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 7,835,260 gas, 15.9 KB (live) |
| Rotation | Same as a typical bundle at the rotation header; a missed rotation adds one hop: 12,606,099 gas, 17.3 KB for bundle + hop (live) |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | `cronosmainnet_25-1` | header `chain_id` in `test/e2e/fixtures/cometbft-live/cronos.json` |
| `storeKey` | `evm` | crypto-org-chain/ethermint `x/evm/types/key.go` `StoreKey`; fixture `storeKey` |
| `evmStateKeyPrefix` | `0x02` | ethermint `KeyPrefixStorage`; confirmed live (`0x02‖WCRO‖slot0` returns "Wrapped CRO", `0x03` returns nothing) |
| `keyScheme` | `ED25519` | `/validators` key type |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | WCRO `0x5c7f8a570d578ed84e63fdfa7b1ee72deae1ae23` | fixture `target` |

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H` (paged, 100 per page),
  `abci_query /store/evm/key?prove=true` at `H-1` for each channel slot.
- Rotations: one bundle per validator-set change; the relay must not let the anchor fall behind the
  unbonding period.
- History: ABCI proofs at `H-1` of every rotation header. The public node
  (`cronos-rpc.publicnode.com`) served about 500k blocks of history.
- Signatures: send the 7 highest-power signers; no aggregator.

## Chain-specific trust and caveats

- Same as the family baseline. Cronos has 10 validators, so a bundle plus one hop fits 15M.
- No ClprService is deployed on Cronos yet; the live bundle proves absence of the channel slots on
  WCRO (five IAVL non-existence proofs).

## Live verification

- Fixture: `test/e2e/fixtures/cometbft-live/cronos.json` (header 97,207,461, hop header 97,207,456,
  captured 2026-10-01).
- Refresh: `npm run cometbft-live:refresh cronos`.
- Replay: `forge build && npm run test:e2e:cometbft-live`.
- Verified: full `verifyBundle` with a real commit (7 Ed25519 signatures through `Ed25519Verifier`),
  the `evm` multistore proof and five IAVL non-existence proofs; bundle + hop; an existence proof of
  WCRO slot 0; negatives (flipped signature byte, below threshold, stale anchor, wrong set, tampered
  IAVL proof, another chain id).

## Hiero → Cronos

Not built. Cronos runs an EVM, so the direction would deploy a Hiero verifier contract on Cronos. It
waits on the Hiero proof source, like every Hiero → chain direction.
