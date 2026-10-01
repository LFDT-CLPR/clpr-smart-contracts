# Osmosis → Hiero

Status: family-covered (`CosmWasmVerifier`, CometBFT family). Not live-verified with a bundle yet.
The proof path was checked live on 2026-10-01 (commit shape, signer count, ICS-23 storage proof
against `app_hash`). The open item is not the verifier but where the CLPR queue lives: code upload on
Osmosis is restricted to 54 allow-listed addresses or a governance proposal.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `osmosis-1` / `cosmos:osmosis-1` |
| Chain type | L1, Cosmos SDK v0.50.14 (`osmosis-labs/cosmos-sdk v0.50.14-v30-osmo` fork) + CometBFT 0.38 + CosmWasm (wasmd v0.53.3, wasmvm v2.2.4); node `OsmosisApp` 31.1.0 |
| Finality source | CometBFT commit: > 2/3 of voting power, instant finality. 69 validators (cap 70); the 18 largest hold > 2/3 |
| Signature scheme | Ed25519 (`tendermint/PubKeyEd25519` for all 69 validators) over the canonical vote |
| State commitment | IAVL v1.2.6 per module store, simple Merkle multistore root in the next header's `app_hash` |
| Verifier | `CosmWasmVerifier` + optional `CometBftCommitAccumulator`, from the CometBFT family (LFDT-CLPR/clpr-smart-contracts#6; README `src/verifiers/evm/provenance/README.md` on that branch) |
| Trust tier | Family baseline: honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the 14-day unbonding period |
| Typical bundle | Not measured on Osmosis. Estimate ~13M gas, ~9 KB in one transaction: 18 Ed25519 signatures, the same count as the measured Provenance bundle (13,120,660 gas, 8.9 KB, 100 validators) |
| Rotation | Same as a bundle (a bundle at the rotation header returns the new anchor). The set hash changes ~26 times per hour (see below) |

## Classification

**(a) Buildable now with an existing family.** Osmosis is a standard CometBFT + wasmd chain, the case
`CosmWasmVerifier` was written for. No contract change is needed; only a deployment profile. The
hard part is on the Osmosis side (where the CLPR Service runs) and in relay cost, not in the
verifier.

## Evidence (live, 2026-10-01)

| Check | Result | How |
|---|---|---|
| Network and versions | `osmosis-1`, CometBFT 0.38.22 (RPC `node_info`), app 31.1.0 | `/status`, `/abci_info` on three public RPCs (Polkachu, osmosis.zone, publicnode) |
| Build deps | wasmd v0.53.3, wasmvm/v2 v2.2.4, iavl v1.2.6, cometbft v0.38.23, cosmos-sdk v0.50.14, store v1.1.1 | LCD `/cosmos/base/tendermint/v1beta1/node_info` |
| Validator set | 69 validators, all Ed25519; largest 10.18% of power, top 5 32.56%; 18 signers clear 2/3 | `/validators?height=71681645` |
| Commit | 68 of 69 signed (`block_id_flag` 2) | `/commit?height=71681645` |
| Storage proof | `abci_query /store/wasm/key?prove=true` returns `ics23:iavl` + `ics23:simple`; recomputed root equals header `H+1` `app_hash` | `script/hard51/osmosis_wasm_proof_check.py` at height 71,681,811, key `0x03 ‖ contract ‖ "contract_info"` of `osmo14hj2…r9g9` (code 1) |
| Set churn | 19 `validators_hash` changes in 2,000 blocks (0.72 h, 1.30 s blocks): ~26/h, ~630/day | `/blockchain` scan, heights 71,679,722–71,681,721 |
| Unbonding | `unbonding_time` 1,209,600 s (14 days), `max_validators` 70 | LCD `/cosmos/staking/v1beta1/params` |
| History | Polkachu RPC earliest block 69,687,202 (~2M blocks, ~30 days) | `/status` |

The running node reports 31.1.0, whose commit is not in the public repository; the last public
release is v31.0.3 (2026-05-14). Its `go.mod` replaces `cosmos-sdk` and `cosmossdk.io/store` with
Osmosis forks. The live proof check above shows the fork still produces standard ICS-23 IAVL and
simple-Merkle proofs, so the fork does not change what the verifier checks.

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Accumulator `chainId` | `osmosis-1` | header `chain_id` |
| Key scheme | `ED25519` (0) | `/validators` key type |
| `storeKey` | `wasm` | wasmd v0.53.3 `x/wasm/types/keys.go`: `StoreKey = ModuleName = "wasm"`; proof op key `wasm` (live) |
| Contract storage key | `0x03 ‖ contract(32 B) ‖ key` | same file: `ContractStorePrefix = 0x03`; live existence proof |
| `bootstrapValidatorsHash`, `bootstrapHeight` | `validators_hash` and height of a recent header | `/commit?height=…` at deployment |
| CLPR Service contract | none deployed (see below) | — |

## Where the CLPR queue would live

The verifier needs a contract (or module) on Osmosis whose storage holds the CLPR queue record. Code
upload permissions on 2026-10-01 (LCD `/cosmwasm/wasm/v1/codes/params`):

| Item | Value |
|---|---|
| `code_upload_access` | `AnyOfAddresses`, 54 addresses |
| `instantiate_default_permission` | `Everybody` |
| Recent codes 1902–1904 | creator `osmo10d07y265gmmuvt4z0w9aw880jnsr700jjeq4qp`, the `x/gov` module account (first 20 bytes of `sha256("gov")`) |

Three routes, in order of effort:

1. **Governance `MsgStoreCode` proposal** for a CosmWasm CLPR Service, then instantiate it (anyone may
   instantiate) with no admin or the gov module as admin. This is how recent codes reached the chain.
   Needs a proposal deposit, a vote and, in practice, an audit. The contract design is the one
   sketched for Provenance in the CosmWasm README §8 (queue record rewritten after every state
   change, `clpr_service` manifest commitment).
2. **Upload by an allow-listed address**: one of the 54 holders uploads the reviewed code.
3. **A native `x/clpr` module**, as built for dYdX: needs an Osmosis software upgrade. Heavier than
   routes 1–2 for no verifier benefit.

Until one of these happens, a bundle can only prove the queue record absent on an existing contract.

## Relayer requirements

- RPC methods: `/status`, `/commit?height=H`, `/validators?height=H`,
  `abci_query /store/wasm/key?prove=true` at `H-1`, `/blockchain` to find rotation headers.
- Rotations: the verifier is sequential, so the relay must submit a bundle (or hop) at every
  `validators_hash` change: ~630 per day at the measured rate, each about one commit (~13M gas,
  estimate). That is the main cost of Osmosis on this family. The remedy is CometBFT skipping
  verification (>1/3 of the trusted set plus >2/3 of the new set, within the trusting period),
  listed in the CometBFT README §6.3.1 and not implemented.
- Signatures: the 18 largest-power signers fit one transaction (the one-transaction path holds up to
  ~20). A catch-up across a rotation needs `CometBftCommitAccumulator` (two or more transactions).
- History: public RPCs keep about 30 days, enough for the 14-day unbonding window.

## Chain-specific trust and caveats

- Same trust as the family baseline.
- High churn: delegation changes move `validators_hash` ~26 times per hour. Missing rotations
  beyond the unbonding period would leave the anchor on a set that may have unbonded.
- The node runs an unpublished release (31.1.0) on forked SDK/store modules. Confirmed formats live;
  re-check after each Osmosis upgrade (`/abci_info` version).
- Osmosis also runs `ibc-08-wasm` light clients and IBC hooks; neither is used here.

## Live verification

- Done: `python3 script/hard51/osmosis_wasm_proof_check.py osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9`
  recomputes the `app_hash` of `H+1` from the ICS-23 proofs (MATCH at heights 71,681,708 and
  71,681,811, 2026-10-01). Standard library only, no node.
- Not done: a recorded fixture replayed through `CosmWasmVerifier` on anvil. It belongs on the
  CometBFT family branch next to the ZIGChain fixture (`buildProvenanceLiveFixture.ts` takes a
  `CosmWasmChainSpec`), with a rotation header R and B = R+2.

## Hiero → Osmosis

Not built. It would run inside the CosmWasm CLPR Service. wasmvm v2.2.4 embeds cosmwasm-std v2.2.2,
whose `Api` exposes `bls12_381_pairing_equality`, `bls12_381_hash_to_g1/g2`,
`bls12_381_aggregate_g1/g2`, `secp256r1_verify`, `secp256k1_verify` and `ed25519_verify`, so
signature checks are host calls. It waits on the Hiero proof source, like every Hiero → chain
direction.

## References

- osmosis-labs/osmosis v31.0.3: `go.mod` (replace directives), `app/keepers/keepers.go` (wasm keeper,
  `wasmtypes.StoreKey`).
- CosmWasm/wasmd v0.53.3 `x/wasm/types/keys.go`.
- CosmWasm/wasmvm v2.2.4 `libwasmvm/Cargo.toml`; CosmWasm/cosmwasm v2.2.2 `packages/std/src/traits.rs`.
- Live: `osmosis-rpc.polkachu.com`, `rpc.osmosis.zone`, `osmosis-rpc.publicnode.com`,
  `osmosis-api.polkachu.com`, `lcd.osmosis.zone`, `osmosis-rest.publicnode.com`.
