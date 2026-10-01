# BOT Chain → Hiero

Status: live-verified on BOT Chain mainnet (2026-10-01). A full bundle (one real epoch rotation plus account and
storage proofs at a finalized state block) runs on the unmodified verifier.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `677` / `eip155:677` |
| Chain type | L1, BSC-derived client (Geth v1.5.13 fork) running Parlia with fast finality |
| Finality source | BLS vote attestation of at least 2/3 of the validator set |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)), no code change |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted. With 7 validators, 3 colluding validators are enough to block finality and 5 to forge it |
| Typical bundle | Live, no rotation: 947,205 execution gas, 1,097,399 gas (`eth_estimateGas`), 9,124 B calldata |
| Rotation | Live, 1 rotation: 1,288,750 execution gas, 1,460,454 gas (`eth_estimateGas`), 10,820 B calldata; one rotation adds about 0.34M execution gas and 1,696 B |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 677 | `eth_chainId` and the header seals, checked by the capture code |
| `epochLength` | 1000 | Live epoch blocks 25,129,000, 25,130,000 and 25,131,000 |
| Validators | 7 | Live epoch block 25,130,000 |
| `turnLength` | 16 | Live epoch block 25,130,000 |
| `activeFrom` after epoch block `E` | `E + 64` (`checkLen = (7/2 + 1) x 16 − 1 = 63`) | `ClprParlia.checkLen`, Parlia `minerHistoryCheckLen` |
| Bootstrap epoch block | Not chosen yet; the fixture uses 25,130,000 | Pick a recent epoch block at deployment |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `eth_chainId`, `eth_getBlockByNumber`, `eth_getProof`.
- `rpc.botchain.ai` is the only public RPC. It serves `eth_getProof` with deep history (checked 20,000 blocks back).
  A production relayer should not depend on a single endpoint and needs its own node.
- Blocks are 0.75 s apart (1000 blocks in 750 s in the fixture), so an epoch lasts 12.5 minutes and one rotation is
  needed per 12.5 minutes of absence.
- With `turnLength` 16 the new set takes over 64 blocks (about 48 s) after each epoch block.
- Catch-up: by linear extrapolation of the live numbers, one transaction holds at most about 38 rotations (gas
  bound; the calldata bound is about 71), which covers about 7.9 hours of absence. Gas per rotation grows with the
  rotation count (see the synthetic numbers in the family README), so a relayer should stay well below this.

## Chain-specific trust and caveats

- The set is small (7 validators). The quorum is `ceil(2 x 7 / 3) = 5` votes.
- The 7-validator set did not change across the captured epochs, so the rotation in the fixture republishes the
  same set. A set change follows the same code path as BSC mainnet, where the fixture's rotation is a real change.
- No ClprService exists on BOT Chain yet. The fixture proves the channel slots of the ValidatorSet system contract
  (`0x0000000000000000000000000000000000001000`), where they are absent, so the storage proofs are MPT exclusion
  proofs.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/bsc-live/botchain.json` (raw RPC capture), `botchain-vectors.json` (encoded vectors) |
| Captured | 2026-10-01 from `rpc.botchain.ai` |
| Anchor epoch | 25,130,000 |
| Rotation | to epoch 25,131,000, finalized 7/7 by the attestation carried in block 25,131,002 |
| State block | 25,131,961, finalized 7/7 by the attestation carried in block 25,131,963 |
| Refresh | `npm run bsc-live:refresh -- --network botchain` |
| Replay | `forge test --match-test test_live_botchain -vv` and `npm run test:e2e:bsc-live` (anvil) |

Verified: `verifyConfig` on the real epoch block reproduces the trust anchor; `verifyBundle` rotates into the next
epoch and proves the account and storage against the finalized state root; the same state verifies under the
rotated anchor without a rotation. The anvil replay also rejects a tampered BLS signature, a dropped voter bit, the
state proof without its rotation step, a tampered storage node and a wrong validator set.

## Hiero → BOT Chain

Not built. It would use the reference Hiero verifier on BOT Chain's EVM and is blocked on the same Hiero proof
source as Hiero → Ethereum.
