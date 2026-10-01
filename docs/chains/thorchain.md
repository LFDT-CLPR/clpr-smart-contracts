# THORChain → Hiero

Status: live-verified on THORChain mainnet (2026-10-01). No CLPR Service can be deployed today (App
Layer halted, uploads whitelisted).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `thorchain-1` / `cosmos:thorchain-1` |
| Chain type | L1, thornode 3.20.3 (Cosmos SDK v0.53.0) + CometBFT 0.38.19, CosmWasm App Layer (wasmd v0.54.0) |
| Finality source | CometBFT commit: > 2/3 of voting power; 67 of 99 validators, all power 100 |
| Verifier | `CosmWasmVerifier` + `CometBftCommitAccumulator` ([README](../../src/verifiers/evm/thorchain/README.md)) |
| Trust tier | Honest 2/3 of each THORChain set the anchor reaches; bootstrap checkpoint at a churn; anchor kept current across churns; the CLPR Service contract's admin |
| Typical bundle | 5 transactions: 4 × `accumulate` (11,141,574–11,914,216 gas, 5.9–6.0 KB) + bundle by hash 583,234 gas, 3.0 KB (live) |
| Rotation | Same 5 transactions at the churn header: 4 × 11,101,964–11,260,593 + 583,609 gas (live) |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Accumulator `chainId` | `thorchain-1` | fixture `chainId` |
| Accumulator `keyScheme` | `ED25519` | `/validators` key type |
| Accumulator `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| Verifier `storeKey` | `wasm` | thornode `app/app.go` mounts `wasmtypes.StoreKey` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | the set hash at a recent churn | `/commit?height=…` at deployment |
| CLPR Service layout | as Provenance: `0x03 ‖ contract(32) ‖ 0x000a "clpr_queue" ‖ channelId` | fixed by `CosmWasmVerifier` |
| Live probe contract | Rujira swap router `thor1n5a08r0zvmqca39ka2tgwlkjy9ugalutk7fjpzptfppqcccnat2ska5t4g` | fixture `contract` |

## Relayer requirements

- RPC methods: `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/wasm/key?prove=true` at `H-1`.
- Four `accumulate` transactions per header (16–17 signatures each), then the bundle by hash.
- Rotations: churns only, every `CHURNINTERVAL = 43200` blocks (about 3 days) plus ad-hoc churn-outs.
- History: `gateway.liquify.com` serves ABCI proofs back to the June 2026 churn. Other public
  endpoints (ninerealms, publicnode) did not answer on 2026-10-01.

## Chain-specific trust and caveats

- Equal power: 67 Ed25519 signatures per commit, about 46.6M gas per bundle in total.
- A churned-out node can withdraw its bond, so a relay that misses a churn must catch up promptly.
- **App Layer halted**: mimir `HALTWASMGLOBAL = 1` on 2026-10-01 blocks store, instantiate, execute
  and migrate. State stays provable.
- **Upload whitelist**: 3 addresses may store code (all Rujira), 11 may instantiate, unless mimir
  `MimirKeyWasmPermissionless` is set (it is not).
- Upgrades are approved by node operators (2/3 of active nodes), not `x/gov`.

## Live verification

- Fixture: `test/e2e/fixtures/thorchain-live/thorchain.json` (churn `R = 27,914,371` with 95
  validators, header `B = 28,052,921` with 99; captured 2026-10-01).
- Refresh: `npm run thorchain-live:refresh`.
- Replay: `forge build && npm run test:e2e:thorchain-live` (7 tests).
- Verified: inline commit too large, R and B each accumulated over 4 transactions, rotation and
  typical bundles by hash, catch-up by hash, two real contract entries, and negatives (replayed
  batch, flipped signature, not finalized, wrong set, stale anchor, another channel, tampered IAVL
  proof).

## Hiero → THORChain

Not built. It needs a CosmWasm CLPR Service (deployable only after the halt is lifted and the code is
whitelisted) that verifies Hiero proofs. It waits on the Hiero proof source, like every Hiero →
chain direction.
