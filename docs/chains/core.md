# Core → Hiero

Status: live-verified on Core mainnet (2026-10-01). A full bundle (one real epoch rotation plus account and storage
proofs at a finalized state block) runs on the unmodified verifier.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `1116` / `eip155:1116` |
| Chain type | L1, Satoshi Plus consensus (`consensus/satoshi`), which keeps Parlia's header and vote formats |
| Finality source | BLS vote attestation of at least 2/3 of the validator set |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)), no code change |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted |
| Typical bundle | Live, no rotation: 1,429,957 execution gas, 1,745,153 gas (`eth_estimateGas`), 19,812 B calldata |
| Rotation | Live, 1 rotation: 1,794,991 execution gas, 2,145,690 gas (`eth_estimateGas`), 22,436 B calldata; one rotation adds about 0.37M execution gas and 2,624 B |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 1116 | `eth_chainId` and the header seals, checked by the capture code |
| `epochLength` | 200 | Live epoch blocks 39,173,800, 39,174,000 and 39,174,200 |
| Validators | 20 | Live epoch block 39,174,000 |
| `turnLength` | 1 | Live epoch block 39,174,000 |
| `activeFrom` after epoch block `E` | `E + 11` (`checkLen = (20/2 + 1) x 1 − 1 = 10`) | `ClprParlia.checkLen`, Parlia `minerHistoryCheckLen` |
| Bootstrap epoch block | Not chosen yet; the fixture uses 39,174,000 | Pick a recent epoch block at deployment |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `eth_chainId`, `eth_getBlockByNumber`, `eth_getProof`.
- `rpc.coredao.org` prunes state after roughly a few thousand blocks. `core.drpc.org` and `rpc.ankr.com/core`
  served `eth_getProof` 5,000 blocks back. Catch-up beyond that needs an archive node.
- Blocks are 3 s apart (200 blocks in 600 s in the fixture), so an epoch lasts 10 minutes and one rotation is needed
  per 10 minutes of absence (BSC uses 1000-block epochs).
- With `turnLength` 1 the new set takes over 11 blocks (about 33 s) after each epoch block.
- Catch-up: by linear extrapolation of the live numbers, one transaction holds at most about 33 rotations (gas
  bound; the calldata bound is about 42), which covers about 5.5 hours of absence. Gas per rotation grows with the
  rotation count (see the synthetic numbers in the family README), so a relayer should stay well below this.

## Chain-specific trust and caveats

- `consensus/satoshi` uses Parlia's `extraData` layout, `minerHistoryCheckLen` and `updateAttestation` unchanged
  (coredao-org/core-chain commit `06a3e0a`).
- The verifier does not check how Core elects its validators (Satoshi Plus delegation), only that each epoch block
  is finalized by the previous set.
- Core changes its validator set once per day (a "round"). The captured epochs had the same set, so the rotation in
  the fixture republishes it. A set change follows the same code path as BSC mainnet, where the fixture's rotation
  is a real change.
- The captured attestations had 18 of 20 votes, above the quorum of `ceil(2 x 20 / 3) = 14`.
- An anchor with the wrong epoch length is rejected on the real data (`test_live_revertWhen_coreAnchorWithBscEpochLength`).
- No ClprService exists on Core yet. The fixture proves the channel slots of WCORE
  (`0x40375C92d9FAf44d2f9db9Bd9ba41a3317a2404f`), where they are absent, so the storage proofs are MPT exclusion
  proofs.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/bsc-live/core.json` (raw RPC capture), `core-vectors.json` (encoded vectors) |
| Captured | 2026-10-01 from `rpc.coredao.org`, `core.drpc.org` and `rpc.ankr.com/core` |
| Anchor epoch | 39,174,000 |
| Rotation | to epoch 39,174,200, finalized 18/20 by the attestation carried in block 39,174,202 |
| State block | 39,174,343, finalized 18/20 by the attestation carried in block 39,174,345 |
| Refresh | `npm run bsc-live:refresh -- --network core` |
| Replay | `forge test --match-test test_live_core -vv` and `npm run test:e2e:bsc-live` (anvil) |

Verified: `verifyConfig` on the real epoch block reproduces the trust anchor; `verifyBundle` rotates into the next
epoch and proves the account and storage against the finalized state root; the same state verifies under the
rotated anchor without a rotation. The anvil replay also rejects a tampered BLS signature, a dropped voter bit, the
state proof without its rotation step, a tampered storage node and a wrong validator set.

## Hiero → Core

Not built. It would use the reference Hiero verifier on Core's EVM and is blocked on the same Hiero proof source as
Hiero → Ethereum.
