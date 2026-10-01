# ZIGChain → Hiero

Status: live-verified on ZIGChain mainnet (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `zigchain-1` / `cosmos:zigchain-1` |
| Chain type | L1, Cosmos SDK v0.53.8 + CometBFT 0.38.25 + CosmWasm (wasmd v0.60.9); node v5.1.2 |
| Finality source | CometBFT commit: > 2/3 of voting power; 4 of 14 validators by power |
| Verifier | `CosmWasmVerifier` with `CometBftCommitAccumulator` ([CosmWasm README](../../src/verifiers/evm/provenance/README.md), [family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | 3,312,486 gas, 3.8 KB (live, one transaction, commit + state proof) |
| Rotation | 3,320,815 gas, 3.8 KB: a bundle at the rotation header returns the new anchor. Catch-up with one inline hop: 6,156,159 gas, 5.2 KB |

All fit Hedera's 15M gas and 128 KB calldata limits in one transaction. The accumulator split is
optional here (measured: commit of 4 signatures 2.98M, bundle by header hash 0.49M).

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Accumulator `chainId` | `zigchain-1` | header `chain_id` in `zigchain.json`; ZIGChain/networks `zigchain-1/chain-id.txt` |
| Accumulator key scheme | `ED25519` (0) | `/validators` key type `tendermint/PubKeyEd25519` |
| Accumulator `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `storeKey` | `wasm` | wasmd v0.60.9 `x/wasm/types/keys.go`: `StoreKey = ModuleName = "wasm"` |
| Contract storage key | `0x03 ‖ contract(32 B) ‖ key` | same file: `ContractStorePrefix = 0x03`, `GetContractStorePrefix`; confirmed live by existence proofs |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| Live probe contract | cw721-base `zig1ue76v4feau5mpkh0rf9fyh0zqsps8mw5awqp2wayltaqvqlgrufswxrqjv` (code 63) | fixture `contract` |

Source versions: ZIGChain's node source is not public. The node's
`/cosmos/base/tendermint/v1beta1/node_info` lists its Go build dependencies, all upstream modules
with no replacements: `cometbft v0.38.25`, `wasmd v0.60.9`, `wasmvm/v2 v2.3.5`, `iavl v1.2.8`,
`cosmos-sdk v0.53.8`, `cosmossdk.io/store v1.1.2`. The protocol details were checked against those
upstream tags.

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/wasm/key?prove=true` at `H-1`, `/blockchain` to find rotation headers.
- Rotations: about 2.6 per hour (7 set changes in 3,000 blocks, 2.66 h, scanned 2026-10-01). Each
  is one bundle of about 3.3M gas.
- History: `zigchain-rpc.polkachu.com` reports earliest block 0 (full history). Other public RPCs
  are listed in ZIGChain/networks `zigchain-1/rpc-nodes.txt`.
- Signatures: the 4 highest-power signers; no aggregator.

## Chain-specific trust and caveats

- Same trust as the family baseline.
- Power is concentrated: the top 4 of 14 validators hold more than 2/3. This makes bundles cheap,
  and it also means 4 validators can finalize a header.
- No CosmWasm CLPR Service is deployed. The bundle proves the CLPR queue record key absent on a real
  contract; the CosmWasm README sketches the service and its queue-record layout.
- ZIGChain has no EVM, so a ZIGChain CLPR Service would be a CosmWasm contract (or a native module).

## Live verification

- Fixture: `test/e2e/fixtures/zigchain-live/zigchain.json` (rotation header 12,567,644 and header
  12,567,646 signed by the new set; captured 2026-10-01 from `zigchain-rpc.polkachu.com`).
- Refresh: `npm run zigchain-live:refresh`.
- Replay: `forge build && npm run test:e2e:zigchain-live` (12 tests).
- Verified: one-transaction `verifyBundle` at the rotation header (returns the new anchor) and at
  the next header from that anchor; the cw2 `contract_info` Item (`crates.io:cw721-base` 0.20.0) and
  Map `tokens`["1"] by existence proof through `verifyContractEntry`; catch-up with an inline hop;
  the split path through the accumulator; negatives (flipped signature, below threshold, wrong set,
  stale anchor, tampered IAVL proof, another channel's key, another chain id).

## Hiero → ZIGChain

Not built. ZIGChain has no EVM, so the direction needs a CosmWasm Hiero verifier. It waits on the
Hiero proof source, like every Hiero → chain direction.
