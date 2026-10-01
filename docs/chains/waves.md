# Waves → Hiero

Waves → Hiero · status: in progress (finality live-verified on Waves testnet, 2026-10-01; CLPR state path blocked)

`WavesFinalityVerifier` proves that a Waves block is final under Waves' BLS-endorsement finality, on real testnet
data. It is **not** a CLPR verifier yet:

* **Blocked: no state proof.** Waves keeps no state Merkle tree. The header's `stateHash` chains per-transaction
  snapshot hashes, so proving one Ride data entry needs every snapshot of its block, including the block's initial
  snapshot that the public REST API does not serve. No public endpoint proves a data entry.
* **Blocked: generator balances are not provable.** Finality weighs generating balances, which are account state;
  the generator set must be trusted input.
* **Mainnet finality is not active.** Deterministic Finality (feature 25) is `VOTING` on mainnet and active on
  testnet since height 4,044,000 (`/activation/status`, 2026-10-01).

Family README: [New-runtime verifiers, batch 3](../../src/verifiers/evm/runtimes3/README.md).

## Quick facts

| | |
|---|---|
| Chain id | testnet, chain byte `T` (84); mainnet `W` (finality not active) |
| Chain type | L1, Waves-NG proof of stake with Deterministic Finality (BLS endorsements), Ride smart accounts |
| Finality source | generators holding at least 2/3 of the period's generating balance endorse the block (BLS12-381 min-pk, DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`) |
| Verifier | [`WavesFinalityVerifier`](../../src/verifiers/evm/runtimes3/WavesFinalityVerifier.sol) (finality only, not an `IClprVerifier`) |
| Trust tier | the generator set (keys and balances) is trusted; under it, 2/3 of the balance signs |
| Typical bundle | finality check 244,916 gas, 1,796 B (live, 5 generators); no state proof |
| Rotation | trusted generator-set update per generation period (3,000 blocks on testnet, 10,000 configured for mainnet) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| Generator set | period `[4284001, 4287000]`, 5 generators, keys from each `CommitToGeneration` transaction, balances from `/blockchain/finality` | fixture `raw.finality`, `raw.commits` |
| Endorsement message | `finalizedId ‖ BE32(finalizedHeight) ‖ endorsedId` | Waves `block/BlockEndorsement.scala` (`mkMessage`), `state/package.scala` (`Height.toByteArray`) |
| Block id | BLAKE2b-256 of the `waves.Block.Header` protobuf | `block/Block.scala` (`protoHeaderHash`) |
| Threshold | endorsed × 3 ≥ total × 2 | `block/FinalizationVoting.scala` (`isFinalized`) |

## Relayer requirements

* REST: `/blockchain/finality` (generation period, generators, balances), `/transactions/info/{id}` for each
  `CommitToGeneration` (BLS key), `/blocks/headers/seq` and `/blocks/headers/at`.
* The public endpoint balances connections over nodes that can lag by days; open a fresh connection per request and
  check the returned heights (the capture script does both).
* Pick a block whose BLS endorsers alone reach 2/3. On testnet this happens when the producer is not one of the two
  large generators; the capture takes the newest such block among the last 100 headers.

## Chain-specific trust and caveats

* The producer's own weight is not counted (it would need a Curve25519 signature check), and conflicting endorsers
  are not subtracted: both make the check stricter than the node's.
* The endorsed block's height is not in its header; the signed `finalizedHeight` bounds it to the set's period.

## Live verification

* Fixture: `test/e2e/fixtures/waves-live/waves.json` (captured 2026-10-01): block 4284331 endorsed by generators 3
  and 4 (847,644,672,271,982 of 996,293,420,051,088, 85.1 %), voting in block 4284332.
* Refresh: `npm run waves-live:refresh`. Replay: `forge build && npm run test:e2e:waves-live`.
* Verified on-chain: block id from the header protobuf (BLAKE2b on EIP-152); BLS aggregate on EIP-2537; the 2/3
  threshold; rejection of a tampered header, a wrong finalized height, too few endorsers, unordered indexes and
  inflated balances.

## Hiero → Waves direction

Not started.
