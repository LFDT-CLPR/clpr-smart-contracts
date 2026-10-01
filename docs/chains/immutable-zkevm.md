# Immutable zkEVM → Hiero

Immutable zkEVM → Hiero · status: live-verified on Immutable zkEVM mainnet and testnet (2026-10-01)

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `13371` / `eip155:13371`; testnet `13473` / `eip155:13473` |
| Chain type | EVM chain run by Immutable on a go-ethereum fork with Clique proof of authority (immutable/immutable-geth); despite the name, its blocks are sealed by Clique signers, not proven by a ZK proof |
| Finality source | None; Clique seal by an authorized signer |
| Verifier | `SignerReplayVerifier` with `SignerReplayProfiles.immutableZkEvm` ([family README](../../src/verifiers/evm/signer/README.md)) |
| Trust tier | **Single key.** One Clique signer on mainnet and one on testnet; the verifier trusts that key |
| Typical bundle | Mainnet: 1,536,232 gas, 18,404 B calldata (1-header run) |
| Rotation | Mainnet, checkpoint 44,220,000 → 44,250,000 (same signer): 1,540,088 gas, 18,404 B calldata |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 13371 (mainnet), 13473 (testnet) | `eth_chainId` |
| `epochLength` / `boundaryOffset` | 30000 / 0 | `params/config.go` Clique `Epoch: 30000`; live checkpoint headers |
| `sealFields` | 0 (all fields) | `consensus/clique/clique.go` `encodeSigHeader` |
| `entrySize` / `trailerSize` | 20 / 0 | Checkpoint `extraData` (vanity, signer addresses, seal) |
| Signer (2026-10-01) | Mainnet `0x48a999207837f3ae1a036dd6cf5c99225d70d13f`; testnet `0x5c1ddf199349e8c3d4d22187baadf98fb9f5ba3d` | Checkpoint headers 44,220,000 and 44,250,000 (mainnet), 45,870,000 and 45,900,000 (testnet) |
| Bootstrap | A recent checkpoint and its next header(s) | `eth_getBlockByNumber` |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `eth_getBlockByNumber`, `eth_getProof`, `eth_chainId`. The public RPC (`rpc.immutable.com`) served
  state 1,000,000 blocks back.
- One header per bundle is enough (one signer). A checkpoint every 30000 blocks (about 17 hours at 2 s blocks) moves
  the anchor when a bundle's state block is a checkpoint; this is optional because the anchor has no age limit.

## Chain-specific trust and caveats

- The chain's own security is one Immutable-operated signer; the verifier adds nothing and removes nothing.
- Immutable's seal hash puts `excessBlobGas` before `blobGasUsed` and forces both, and `parentBeaconBlockRoot`, to
  zero, so the verifier's field-order encoding matches.
- Clique votes can add signers between checkpoints; the verifier sees them only at the next checkpoint.

## Live verification

- Fixtures: `test/e2e/fixtures/signer-replay-live/immutable-mainnet.json`, `immutable-testnet.json` (and
  `-vectors.json`), captured 2026-10-01. Probe contracts: mainnet `0x6c12ad6f0bd274191075eb2e78d7da5ba6453424`,
  testnet `0x307d214799d3b1625d1ec70f83d170d5fd0ee5a1` (recently called contracts with storage; code hash pinned,
  channel slots empty).
- Verified: config on checkpoint B0, bundle with the next checkpoint B1 as `h_0` (rotation), the same bundle under
  the rotated anchor.
- Refresh: `npx tsx test/e2e/relay/buildSignerReplayLiveProof.ts --refresh --network immutable-mainnet` (or
  `immutable-testnet`). Replay: `npm run test:e2e:signer-kaia-live`, `forge test --match-contract SignerReplayLive -vv`.

## Hiero → Immutable zkEVM

Not built. The chain runs an EVM, so the reference Hiero verifier could be deployed there; it is blocked on the same
Hiero proof source as Hiero → Ethereum.
