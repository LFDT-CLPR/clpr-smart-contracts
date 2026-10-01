# Injective → Hiero

Status: live-verified on Injective mainnet (2026-10-01). The fixture and replay are on branch
`feat/rwaprofiles-verifier`.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `injective-1` / `cosmos:injective-1` |
| Chain type | L1, Cosmos SDK + CometBFT v1.0.1 (InjectiveLabs fork), Injective `x/evm` |
| Finality source | CometBFT commit: > 2/3 of voting power; 15 of 45 validators by power |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 12,598,455 gas, 15.0 KB (live, recorded at a rotation header) |
| Rotation | The same bundle (returns the new anchor). Bundle + one hop: 22,784,596 gas, 18.6 KB, does **not** fit 15M; a lone hop 10.11M |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | `injective-1` | header `chain_id` in `injective.json` |
| `storeKey` | `evm` | injective-core `v1.20.3-safeharbor.2` `injective-chain/modules/evm/types/key.go` |
| `evmStateKeyPrefix` | `0x02` | same file; confirmed live: IAVL value of `0x02‖wINJ‖slot 5` equals `eth_getStorageAt` (0x64) at the same height |
| `keyScheme` | `ED25519` | `/validators` key type |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | wINJ `0x0000000088827d2d103ee2d9a6b781773ae03ffb` | fixture `target` |

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/evm/key?prove=true` at `H-1`, `/blockchain` to find rotation headers.
- Rotations: **about 12 per hour, about 290 per day** (4 set changes in 2,000 blocks, 20 min,
  scanned 2026-10-01). Every delegation change rotates the set; each needs its own bundle
  transaction, because bundle + hop does not fit.
- History: the official sentry (`sentry.tm.injective.network`) serves ABCI proofs only about 100
  blocks back. The fixture used Polkachu's RPC, which served 5,000+ blocks. A production relay needs
  a node with longer history.
- Signatures: the 15 highest-power signers; no aggregator.

## Chain-specific trust and caveats

- **Source is closed.** Injective stopped publishing source on 2026-09-09; the node runs v1.20.4.
  The layout was checked against the last public tag (`v1.20.3-safeharbor.2`) and confirmed live.
- **CometBFT v1.0.1 fork** (`InjectiveLabs/cometbft v1.0.1-inj.9`, not public). Upstream v1.0.1
  `Header.Hash`, `CanonicalizeVote`, `VoteSignBytes` and `Validator.Bytes` are identical to v0.38
  (diffed), and the live commit verifying on-chain confirms the fork kept them.
- **Tight on gas.** A rotation bundle needs 12.60M gas, 84% of Hedera's limit.
- About 290 rotation transactions a day at 10–12.6M gas each. CometBFT skipping verification would
  remove most of them; it is not implemented (family README §6).
- No ClprService is deployed on Injective's EVM yet; the live bundle proves absence of the channel
  slots on wINJ.

## Live verification

- Fixture: `test/e2e/fixtures/cometbft-live/injective.json` on `feat/rwaprofiles-verifier` (header
  185,333,798, a rotation header; hop header 185,333,793; captured 2026-10-01 from
  `injective-rpc.polkachu.com`).
- Refresh (on that branch): `npm run cometbft-live:refresh injective`.
- Replay (on that branch): `forge build && npm run test:e2e:cometbft-live`.
- Verified: full `verifyBundle` at a rotation header (returns the new anchor), bundle + hop (does not
  fit), the commit alone through `applyHops`, an existence proof of wINJ slot 5 equal to
  `eth_getStorageAt`, and the family negatives.

## Hiero → Injective

Not built. Injective runs an EVM, so the direction would deploy a Hiero verifier contract on
Injective's EVM. It waits on the Hiero proof source, like every Hiero → chain direction.
