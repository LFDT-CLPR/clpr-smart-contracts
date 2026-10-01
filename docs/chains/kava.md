# Kava → Hiero

Status: live-verified on Kava mainnet (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `kava_2222-10` / `cosmos:kava_2222-10` (EVM chain id 2222) |
| Chain type | L1, Cosmos SDK v0.47 (Kava fork) + CometBFT 0.37 (node reports 0.37.16), EVM from `kava-labs/ethermint v0.21.0-kava-v27.0` |
| Finality source | CometBFT commit: > 2/3 of voting power; 7 of 50 validators by power |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 8,285,366 gas, 17.6 KB (live, recorded at a rotation header) |
| Rotation | The same bundle: the fixture header is a rotation header and returns the new anchor. Bundle + one hop: 13,438,331 gas, 20.7 KB; a lone hop 5,090,505 gas, 3.3 KB |

All three fit Hedera's 15M gas and 128 KB calldata limits.

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | `kava_2222-10` | header `chain_id` in `kava.json` |
| `storeKey` | `evm` | kava-labs/ethermint `x/evm/types/key.go`: `StoreKey = ModuleName = "evm"` |
| `evmStateKeyPrefix` | `0x02` | same file: `prefixCode = iota + 1`, then `prefixStorage`; confirmed live: the IAVL value of `0x02‖WKAVA‖slot 0` is the `name()` short string "Wrapped Kava", equal to `eth_getStorageAt` at the same height |
| `keyScheme` | `ED25519` | `/validators` key type `tendermint/PubKeyEd25519` |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | WKAVA `0xc86c7c0efbd6a49b35e8714c5f59d99de09a225b` | fixture `target` |

Source versions: the node reports app `0.28.2`. Kava-Labs/kava `v0.28.2` `go.mod` replaces
`cometbft => kava-labs/cometbft v0.37.18-kava.1`, `cosmos-sdk => kava-labs/cosmos-sdk
v0.47.15-iavl-v1-kava.1` and `ethermint => kava-labs/ethermint v0.21.0-kava-v27.0`, and pins
go-ethereum v1.10.26. The Ethermint state DB writes each word as 32 bytes. CometBFT 0.37 hashes
headers and builds precommit sign bytes as 0.38 does; the live commit verifying on-chain confirms it.

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/evm/key?prove=true` at `H-1`, `/blockchain` to find rotation headers.
- Rotations: **about 4 per hour, about 100 per day** (13 set changes in 2,000 blocks, 3.17 h,
  scanned 2026-10-01). `validators_hash` covers voting power, so every delegation change rotates
  the set, and the sequential light client needs one bundle per change.
- History: `kava-rpc.polkachu.com` served blocks from height 22,444,194 (about 377k blocks) and
  answered `abci_query` at height 22,000,000.
- Signatures: the 7 highest-power signers; no aggregator.

## Chain-specific trust and caveats

- Same trust as the family baseline.
- About 100 rotation transactions a day at about 8.3M gas each, whether or not messages flow
  (family README §6.3.1).
- No ClprService is deployed on Kava yet; the live bundle proves absence of the channel slots on
  WKAVA.

## Live verification

- Fixture: `test/e2e/fixtures/cometbft-live/kava.json` (header 22,820,128, a rotation header; hop
  header 22,820,123; captured 2026-10-01 from `kava-rpc.polkachu.com`).
- Refresh: `npm run cometbft-live:refresh kava`.
- Replay: `forge build && npm run test:e2e:cometbft-live`.
- Verified: full `verifyBundle` at a rotation header (returns the new anchor), bundle + hop, the
  commit alone through `applyHops`, an existence proof of WKAVA slot 0 equal to `eth_getStorageAt`,
  and the family negatives (flipped signature, below threshold, stale anchor, wrong set, tampered
  IAVL proof, another chain id).

## Hiero → Kava

Not built. It waits on the Hiero proof source, like every Hiero → chain direction. Kava's EVM has
**no EIP-2537 (BLS12-381) precompiles**: it runs go-ethereum v1.10.26, and on 2026-10-01 an
`eth_call` to `0x0b` (BLS12_G1ADD) on `evm.kava.io` returned empty while the BN254 pairing
precompile `0x08` worked. `src/verifiers/hiero/TSSVerifier.sol` uses BLS12-381, so a Hiero
verifier on Kava needs a BLS12-381 implementation in Solidity or a different proof path. This
affects only the Hiero → Kava direction; Kava → Hiero runs on Hedera, which has EIP-2537.
