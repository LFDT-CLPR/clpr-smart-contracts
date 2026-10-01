# Initia → Hiero

Initia → Hiero · status: live-verified on Initia mainnet `interwoven-1` (2026-10-01)

"Live-verified" here means: the state path (header `app_hash` → `move` store root → a real Move resource and a real
Move table entry) runs on-chain in `InitiaMoveVerifier` on real data, and the same header's commit (5 Ed25519
signatures carrying more than 2/3 of the power) is checked off-chain when the fixture is built and on-chain by the
CometBFT family's `CometBftCommitAccumulator` (PR #6, measured separately). No CLPR Service is deployed on Initia,
so the CLPR record path runs on synthetic data in the Foundry tests.

Family README: [New-runtime verifiers, batch 3](../../src/verifiers/evm/runtimes3/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `cosmos:interwoven-1`; `verifyConfig` requires the `cosmos:` namespace |
| Chain type | L1, Cosmos SDK + CometBFT 0.38.22 (node version in the fixture), MoveVM (`x/move`) |
| Finality source | CometBFT commit: more than 2/3 of the voting power signs the header (Ed25519, 10 validators) |
| Verifier | [`InitiaMoveVerifier`](../../src/verifiers/evm/runtimes3/InitiaMoveVerifier.sol) + `CometBftCommitAccumulator` and `Ed25519Verifier` from PR #6 |
| Trust tier | Light client: trusts > 2/3 of each validator set the anchor reaches and the bootstrap set |
| Typical bundle | header check 3,459,586 gas, 1,508 B (PR #6, live) + store proof 532,778 gas, 3,460 B (live); about 4.0 M gas and 5.0 KB together (estimate) |
| Rotation | same transaction as a bundle at the rotation header; each missed set change costs one header check (3.46 M gas inline or 3.59 M per `accumulate`) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `headerSource` | a `CometBftCommitAccumulator(chainId = "interwoven-1", ED25519, ed25519Verifier)` (PR #6) | `ICometBftHeaderSource.sol`; PR #6 `CometBftCommitAccumulator.sol` constructor |
| `bootstrapValidatorsHash`, `bootstrapHeight` | the `validators_hash` and height of the header the configuration is proven under | `/commit?height=…` |
| IAVL store and prefix | store `move`, VM prefix `0x21` | initia `x/move/types/keys.go` (`StoreKey`, `VMStorePrefix`) |
| Resource key | `0x21 ‖ addr ‖ 0x02 ‖ BCS(StructTag{addr, "clpr", "Service", []})` | `keys.go:GetResourceKey`; checked live against `0x1::dex::ModuleStore` |
| Table entry key | `0x21 ‖ handle ‖ 0x03 ‖ BCS(channelId as address)` | `keys.go:GetTableEntryKey`; checked live against a `dex` pairs entry |
| Table handle | first 32 bytes of the proven `Service` resource (a Move `Table` is `handle ‖ length`) | `verifyConfig` (`_decodeServiceResource`); live `ModuleStore` raw bytes |
| Service address | the 32-byte Move address of the CLPR module | ledger configuration |

## Relayer requirements

* CometBFT RPC: `/commit` and `/validators` (paged, 100 per page) at the state header and at every rotation header
  since the anchor; `/blockchain` to find rotation headers.
* `abci_query` on `/store/move/key` with `prove=true` at height H−1 (its state is committed in header H). The public
  RPC `https://rpc.initia.xyz` serves these proofs; no archive node is needed for recent heights.
* Signatures: Ed25519, sent as recorded; the CometBFT family's relay helper (`relay/cometbft.ts`) picks the smallest
  set of signatures that clears 2/3 (5 of 10 in the fixture).
* Cadence: the validator-set hash changed 58 times in 4,000 headers (about 23 per hour, 2026-10-01). Submit often,
  or pre-accumulate each rotation header with `accumulate`.

## Chain-specific trust and caveats

* Finality depends on PR #6's contracts; this branch only declares their ABI. The accumulator address is immutable in
  the verifier.
* Voting power moves often, so the anchor changes often; an anchor older than the unbonding period must not be used.
* The `Service` / `ChannelQueue` Move layout is this family's proposal; no CLPR Move module exists yet.

## Live verification

* Fixture: `test/e2e/fixtures/initia-live/initia.json` (header 22505954, captured 2026-10-01).
* Refresh: `npm run initia-live:refresh`. Replay: `forge build && npm run test:e2e:initia-live`.
* Verified: header hash = block id and > 2/3 of the power signed (off-chain); on-chain key derivation for the
  resource and the table entry; the table handle read from the proven resource; both proofs under the header's
  `app_hash`; rejection of a tampered value, another key, a wrong set and a stale anchor.

## Hiero → Initia direction

Not started. It needs a Hiero state-proof verifier in Move (or a Cosmos SDK module) on Initia, comparable to the
dYdX `x/clpr` module work for Cosmos chains.
