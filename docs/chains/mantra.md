# MANTRA → Hiero

Status: live-verified on MANTRA mainnet (2026-10-01). The fixture and replay are on branch
`feat/rwaprofiles-verifier`.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `mantra-1` / `cosmos:mantra-1` |
| Chain type | L1, Cosmos SDK + CometBFT 0.38.22 (node), EVM from cosmos/evm v0.6 (MANTRA fork) |
| Finality source | CometBFT commit: > 2/3 of voting power; 8 of 38 validators by power |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 7,764,628 gas, 12.7 KB (live, recorded at a rotation header) |
| Rotation | The same bundle: the fixture header is a rotation header and returns the new anchor. Bundle + one hop: 13,410,752 gas, 15.4 KB; a lone hop 5.61M |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | `mantra-1` | header `chain_id` in `mantra.json` |
| `storeKey` | `evm` | MANTRA-Chain/evm `x/vm/types/key.go` `StoreKey` |
| `evmStateKeyPrefix` | `0x02` | MANTRA-Chain/evm `KeyPrefixStorage`; confirmed live: IAVL value of `0x02‖wMANTRA‖slot 0` equals `eth_getStorageAt` (0x01) at the same height |
| `keyScheme` | `ED25519` | `/validators` key type |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | wMANTRA `0xe3047710ef6cb36bcf1e58145529778ea7cb5598` | fixture `target` |

Source versions: the node reports app `v8.7.0-pre.1`, which has no public tag, so the layout was
checked against MANTRA-Chain/mantrachain `main` (2026-09-29), which pins
`cosmos/evm => MANTRA-Chain/evm v0.6.3-v8-mantra-1`.

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/evm/key?prove=true` at `H-1`, `/blockchain` to find rotation headers.
- Rotations: **about 7 per hour, about 170 per day** (13 set changes in 2,000 blocks, 1.85 h,
  scanned 2026-10-01). `validators_hash` covers voting power, so every delegation change rotates the
  set, and the sequential light client needs one bundle per change whether or not messages flow.
- History: `rpc.mantrachain.io` kept ABCI proofs about 300k blocks back (earliest 18,185,503).
- Signatures: the 8 highest-power signers; no aggregator.

## Chain-specific trust and caveats

- Same trust as the family baseline.
- Operational cost is the main difference: about 170 rotation transactions a day at about 7.8M gas
  each. CometBFT skipping verification would remove most of them; it is not implemented (family
  README §6).
- No ClprService is deployed on MANTRA yet; the live bundle proves absence of the channel slots on
  wMANTRA.

## Live verification

- Fixture: `test/e2e/fixtures/cometbft-live/mantra.json` on `feat/rwaprofiles-verifier` (header
  18,485,555, a rotation header; hop header 18,485,550; captured 2026-10-01 from
  `rpc.mantrachain.io`).
- Refresh (on that branch): `npm run cometbft-live:refresh mantra`.
- Replay (on that branch): `forge build && npm run test:e2e:cometbft-live`.
- Verified: full `verifyBundle` at a rotation header (returns the new anchor), bundle + hop, the
  commit alone through `applyHops`, an existence proof of wMANTRA slot 0 equal to `eth_getStorageAt`,
  and the family negatives.

## Hiero → MANTRA

Not built. MANTRA runs an EVM, so the direction would deploy a Hiero verifier contract on MANTRA. It
waits on the Hiero proof source, like every Hiero → chain direction.
