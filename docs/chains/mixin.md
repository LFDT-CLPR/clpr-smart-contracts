# Mixin → Hiero

Mixin → Hiero · status: live-verified on Mixin mainnet (2026-10-01)

`MixinKernelVerifier` checks the Mixin kernel's collective (CoSi) signature on-chain: one ed25519
signature over the BLAKE3 snapshot hash under the sum of the signers' keys. It tracks the node set
by applying the kernel's NodeAccept and NodeRemove transactions, and reads the CLPR queue record that
an MTG app writes into a transaction's `extra`. Full design:
[MixinKernelVerifier README](../../src/verifiers/evm/mixin/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | No registered CAIP-2 namespace; the tests use `mixin:mainnet` |
| Chain type | L1 DAG kernel (Mixin Network), UTXO transactions, no smart contracts |
| Finality source | Kernel CoSi from at least `base × 2 / 3 + 1` consensus nodes (43 on 2026-10-01, threshold 29) |
| Verifier contract | `src/verifiers/evm/mixin/MixinKernelVerifier.sol` + `Ed25519Verifier` · [family README](../../src/verifiers/evm/mixin/README.md) |
| Trust tier | More than 2/3 of kernel nodes honest; the MTG app's k-of-n members decide record content (operator trust) |
| Typical bundle | 1,208,229 gas, 3,364 B (live, 29 of 43 signers) |
| Rotation | 3,248,524 gas, 6,308 B (live NodeAccept + NodeRemove + record) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `caip2` | `"mixin:mainnet"` (deployment's choice) | `test/e2e/tests/verifiers/mixin-live.spec.ts` |
| `ed25519` | Address of a deployed `Ed25519Verifier` on Hedera | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| Ready node keys (anchor `nodesHash`) | 43 keys on 2026-10-01T07:14Z, kernel order | `test/e2e/fixtures/mixin-live/mainnet.json` (`nodes`) |
| Pending node | none at capture | `mainnet.json` (`base.pending`) |
| Thread tip | the MTG app's config transaction (`verifyConfig`) | `MixinKernelVerifier.sol:verifyConfig` |
| Node-list source | `listallnodes(t, false)`: ACCEPTED, accepted more than 12 h before t, ordered by timestamp then id; signer key = the spend key of the node's `signer` address | `test/e2e/relay/buildMixinLiveProof.ts` |

## Relayer requirements

- Kernel RPC (`https://kernel.mixin.dev` or an own node): `getsnapshot`, `gettransaction`,
  `listallnodes`, `listsnapshots`, `getinfo`. No archive beyond what the kernel keeps.
- Watch the node list: about one NodeRemove and one NodeAccept per day on mainnet. Include each
  change, in order, in the next bundle (or a rotation-only bundle), so the anchor never trusts removed
  nodes for long.
- Compute the affine x coordinate of each masked signer key off-chain.
- Kernel timestamps are nanoseconds above 2^53; parse them as integers, not JSON numbers.

## Chain-specific trust and caveats

- Mixin has no contracts (MVM is retired): the CLPR endpoint is an MTG app, trusted for record
  content. The kernel only proves that the thread holder wrote the record, in order, once.
- Records fit the 256-byte `extra` limit (190 bytes).
- Snapshots finalized only through the kernel's "node removal time fork check" fallback cannot be
  used.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/mixin-live/mainnet.json` |
| Captured | 2026-10-01T07:30:09Z (`capturedAt`), kernel `v0.19.9-512c1fe4` |
| Refresh | `npm run mixin-live:refresh` |
| Replay | `forge build && npm run test:e2e:mixin-live` |
| What was verified | From the 43-node list before them, the NodeAccept `6e23d5a6…` (snapshot `fc16a363…`, round 0, 30 of 44 with the new key appended) and the NodeRemove `a994e695…` (snapshot `9bc7416e…`, 30 of 44); then snapshot `f950e127…` (29 of 43) under the resulting list, and transaction `a579a31b…` spending output 0 of `64c7c629…`. Negatives: replayed changes, skipped changes, wrong node set, below threshold, a moved mask bit, a flipped signature byte. No MTG app writes CLPR records yet, so `verifyBundle` stops at the record decode |

## Hiero → Mixin direction

Not built on this branch. Mixin has no contracts, so the only path is an MTG app whose members each
verify Hiero bundles off-chain and co-sign the delivery transaction (attestor-tier trust, k-of-n).
