# Stellar → Hiero

Stellar → Hiero · status: live-verified on pubnet, testnet (2026-10-01)

The date is the `capturedAt` time of both live fixtures. Finality, checkpoints and a real tier-1
rotation pass `verifyBundle` completely on live data. The event half runs on real Soroban events of
other contracts, because no CLPR service is deployed on Stellar yet (see
[Chain-specific trust and caveats](#chain-specific-trust-and-caveats)).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `stellar:pubnet`, `stellar:testnet` (the verifier's `chainId`; pinned by `verifyConfig`) |
| Chain type | L1, stellar-core with Soroban smart contracts |
| Finality source | SCP EXTERNALIZE statements whose signers satisfy the trusted quorum set (tier-1 on pubnet) |
| Verifier | `StellarScpVerifier` + `Ed25519Verifier`; family README: [`src/verifiers/evm/stellar/README.md`](../../src/verifiers/evm/stellar/README.md) |
| Trust tier | Light client: a tier-1 slice (7 of 10 organizations, 2 of 3 validators each = 14 Ed25519 signatures) plus the Soroban service contract's upgrade authority |
| Typical bundle | Pubnet: 2 transactions, 13.38M gas / 83.7 KB + 1.92M gas / 68.4 KB (harness). Testnet: 1 transaction, 2.21M gas / 32.2 KB (harness). |
| Rotation | Pubnet 5 of 7 → 7 of 10 organizations: 10.58M gas / 113.2 KB |

Gas is `eth_estimateGas` on anvil from `test/e2e/tests/verifiers/stellar-live.spec.ts`. "Harness" means
the production steps up to the emitter check (`StellarScpVerifierHarness.proveEvent`). Details are in the
family README's "Gas and calldata" section.

## Deployment profile

| Parameter | Pubnet | Testnet | Read from |
|---|---|---|---|
| Network passphrase | `Public Global Stellar Network ; September 2015` | `Test SDF Network ; September 2015` | `test/e2e/relay/buildStellarLiveProof.ts` (`NETWORKS`) |
| `networkId` (constructor) | `0x7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979` | `0xcee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472` | `test/e2e/fixtures/stellar-live/{pubnet,testnet}.json` (`networkId`) |
| `chainId` (constructor) | `stellar:pubnet` | `stellar:testnet` | `test/e2e/relay/buildStellarLiveProof.ts` (`NETWORKS`), fixtures (`caip2`) |
| `ed25519` (constructor) | address of a deployed `Ed25519Verifier` | same | `test/e2e/tests/verifiers/stellar-live.spec.ts` (`deploy`) |
| Initial quorum set (config proof) | threshold 7 of 10 organizations, each 2 of 3, 30 validators | threshold 2 of 3, 3 validators | fixtures (`qset`, `qsetSummary`) |
| Initial quorum-set hash | `0x040355b75766e6799d1ef69ce03f114530a06d922dd64b5e885da907a453841d` | `0x59d361aef699a1ca165dfcea7ebdedf8f9889c35cf76b35cfcb173cd72a2d669` | fixtures (`qsetHash`) |
| Service address | 32-byte contract id of the Soroban CLPR service (not deployed) | same | `src/verifiers/evm/stellar/StellarScpVerifier.sol` (`_contractId`) |
| History archive | `https://history.stellar.org/prd/core-live/core_live_001` | `https://history.stellar.org/prd/core-testnet/core_testnet_001` | `test/e2e/relay/buildStellarLiveProof.ts` (`NETWORKS`) |
| Stellar RPC | `https://mainnet.sorobanrpc.com` | `https://soroban-testnet.stellar.org` | `test/e2e/relay/buildStellarLiveProof.ts` (`NETWORKS`) |

The pubnet quorum set changes when tier-1 changes. Before the September 2026 expansion it was 5 of 7
organizations, 21 validators (`0x958e72b8…9294`, `rotation.oldQsetHash` in `pubnet.json`). Check the
current set against the network (stellarbeat.io or the `D` values in the archive's SCP history) before
completing a channel.

## Relayer requirements

- **History archive.** Per checkpoint (64 ledgers), the `ledger`, `transactions`, `results` and `scp`
  files, plus `.well-known/stellar-history.json` for the current ledger. The SCP files hold the
  EXTERNALIZE envelopes and the quorum sets they reference. The archive keeps full history, so no archive
  node is needed.
- **Stellar RPC.** `getTransactions` for the attesting transaction's envelope, result and contract
  events. The archive does not hold the events in decoded form.
- **Own node.** Not required. A watcher node on the overlay gives EXTERNALIZE envelopes without the ~6
  minute checkpoint delay.
- **Tx-set size.** On pubnet the relayer waits for a slot whose tx set fits next to the signatures (the
  capture script limits it to 122,000 B). About 1.4 % of pubnet ledgers qualify, about one every 6
  minutes. Testnet tx sets fit in one transaction.
- **Signature selection.** The relayer sends the smallest signer set that satisfies the quorum set,
  sorted by node id (`scpFor` in `buildStellarLiveProof.ts`).
- **Rotations.** Only when tier-1 changes. The relayer must relay a rotation while an old-set slice
  still declares the new set.
- **Signature aggregators.** None. Each signature is a separate Ed25519 check (~834k gas).

## Chain-specific trust and caveats

- Pubnet bundles need two transactions. Pubnet in one transaction is 150 KB, over Hedera's 128 KB.
- Pubnet step 1 uses 13.38M of 15M gas. A tier-1 that needs 16 signatures does not fit.
- Soroban contracts can replace their own Wasm. The verifier pins only the service's contract id, so it
  trusts the service's upgrade authority.
- Testnet is SDF's 3 validators (2 of 3), a much weaker trust base than pubnet. If testnet is reset, the
  channel needs a new config.
- No CLPR service exists on Stellar. The `clpr_queue` / `clpr_manifest` event format is the verifier's
  proposal for a Soroban port.
- Protocol versions differ between the networks at capture time (pubnet 28, testnet 29). The same code
  verifies both, because the verifier does not check `ledgerVersion`.

## Live verification

| Item | Pubnet | Testnet |
|---|---|---|
| Fixture | `test/e2e/fixtures/stellar-live/pubnet.json` | `test/e2e/fixtures/stellar-live/testnet.json` |
| Captured | 2026-10-01T04:34:42Z | 2026-10-01T04:32:16Z |
| Finality slot | 64,708,579 (14 of 30 envelopes, 77.6 KB tx set) | 4,961,087 (2 of 3 envelopes, 27.4 KB tx set) |
| Headers walked | 3 (64,708,578 down to 64,708,576) | 2 (4,961,086 down to 4,961,085) |
| Event | RedStone `REDSTONE` update in ledger 64,708,576, result set of 184 transactions | `new_block_event` in ledger 4,961,085, result set of 15 transactions |
| Rotation | slot 64,150,367: `958e72b8…` → `040355b7…`, 10 old-set endorsers | none |

Refresh: `npm run stellar-live:refresh` (both networks).
Replay: `forge build && npm run test:e2e:stellar-live` (23 tests: 11 on testnet, 12 on pubnet).

The replay checks `verifyConfig`, step 1 (a complete `verifyBundle`), step 2 and the single-transaction
form through the harness, the pubnet rotation (a complete `verifyBundle`), and seven negative cases per
network on real data. `verifyBundle` on the live events stops at `WrongAttestationEvent`, as expected,
because the events are not `clpr_queue`.

## Hiero → Stellar direction

Not started. It needs a Soroban `ClprService` port and a Hiero proof verifier running on Soroban, and it
depends on a Hiero proof source for every chain.
