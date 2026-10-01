# Provenance → Hiero

Status: live-verified on Provenance mainnet (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `pio-mainnet-1` / `cosmos:pio-mainnet-1` |
| Chain type | L1, Cosmos SDK v0.53 fork + CometBFT 0.38.22, CosmWasm (wasmd v0.61.10-pio-2) |
| Finality source | CometBFT commit: > 2/3 of voting power; 18 of 100 validators by power |
| Verifier | `CosmWasmVerifier` + `CometBftCommitAccumulator` ([README](../../src/verifiers/evm/provenance/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the 21-day unbonding period; the CLPR Service contract's admin |
| Typical bundle | 13,113,627 gas, 8.9 KB, one transaction (live) |
| Rotation | 13,120,821 gas, 8.9 KB (live, bundle at the rotation header). Missed rotation: accumulate both commits (7.0M + 6.9M + 12.7M), then a 536,951-gas bundle by hash |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Accumulator `chainId` | `pio-mainnet-1` | fixture `chainId` |
| Accumulator `keyScheme` | `ED25519` | `/validators` key type |
| Accumulator `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| Verifier `storeKey` | `wasm` | provenance-io/wasmd `x/wasm/types/keys.go` |
| Verifier `accumulator` | the accumulator above | — |
| `bootstrapValidatorsHash`, `bootstrapHeight` | a recent header's set hash and height | `/commit?height=…` at deployment |
| CLPR Service layout | queue record at `0x03 ‖ contract ‖ 0x000a "clpr_queue" ‖ channelId`, service item at `0x03 ‖ contract ‖ "clpr_service"` | fixed by `CosmWasmVerifier` |
| Live probe contract | Figure "Crypto-Backed Loan" pool `pb1msvy4f0vcdm9kx4x56lrk5ctlnh88ag84k4ggskywzwvf2nzlmtqnm5ged` | fixture `contract` |

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/wasm/key?prove=true` at `H-1`.
- Rotations: one in 820 blocks scanned (about 1 h at about 4.3 s per block). Any power change
  rotates the set. Each rotation is one bundle, 13.12M gas.
- Catch-up across a rotation needs the split: `accumulate` transactions first, then a bundle by
  header hash.
- History: ABCI proofs at `H-1` for each rotation header.
- Signatures: the 18 highest-power signers fit one transaction; above about 20, use `accumulate`.

## Chain-specific trust and caveats

- **Contract admin.** A CosmWasm contract with an admin can be migrated. The CLPR Service should be
  instantiated with no admin or with governance as admin.
- **Headroom.** 1.88M gas is left in a one-transaction bundle.
- **Deployment is permissionless.** Code upload and instantiation are open to everybody; a store-code
  transaction costs a flat $100 fee (README §12).
- **Hiero → Provenance** must verify within Provenance's 4,000,000 per-transaction gas limit.
- No CLPR Service is deployed yet; the live bundle proves absence of the queue record on a real
  contract.

## Live verification

- Fixture: `test/e2e/fixtures/provenance-live/provenance.json` (rotation `R = 33,796,997`, bundle
  header `B = 33,796,999`, captured 2026-10-01 from `rpc.provenance.io`).
- Refresh: `npm run provenance-live:refresh`.
- Replay: `forge build && npm run test:e2e:provenance-live` (13 tests).
- Verified: bundle at R in one transaction (returns the new anchor), bundle at B from that anchor,
  two real contract entries by existence proof, the inline catch-up that does not fit, the split
  path (R in two batches, B in one, bundles by hash), and negatives (flipped signature, below
  threshold, wrong set, stale header, tampered IAVL proof, another channel, another chain id).

## Hiero → Provenance

Not built. It needs a CosmWasm CLPR Service that verifies Hiero proofs inside the 4M gas
per-execute limit, using CosmWasm 3's BLS12-381, Ed25519 and secp256k1/r1 host functions. It waits on
the Hiero proof source, like every Hiero → chain direction. Sketch: README §12.
