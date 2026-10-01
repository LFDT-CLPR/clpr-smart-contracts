# Cardano → Hiero · status: live-verified on preprod, mainnet (2026-10-01); mainnet bundles blocked

The verifier proves a CLPR state UTxO in a phase-2-valid transaction of a block certified by Mithril.
Design, trust model and gas are in the family README:
[`src/verifiers/evm/cardano/README.md`](../../src/verifiers/evm/cardano/README.md).

## Quick facts

| Item | Value |
|---|---|
| CAIP-2 | mainnet `cip34:1-764824073`; preprod `cip34:0-1`; preview `cip34:0-2` |
| Chain type | L1, Ouroboros Praos proof-of-stake |
| Finality source | Mithril certificates (stake-based threshold multi-signature by registered stake pools), not Ouroboros itself |
| Verifier | `CardanoMithrilVerifier` + `MithrilStmVerifier` + `ClprBlake2sHasher` |
| Trust tier | Mithril honest-stake assumption for (k, m, φ_f) over Mithril-registered stake. Plus the bootstrap AVK, and the open key-encoding gap (family README, Limits). |
| Typical bundle | Preprod, live: 2,153,379 gas, 5,092 B (with one epoch rotation) |
| Rotation | Every epoch (5 days). Mainnet, live: rotation + certificate 11,218,993 gas, 79,204 B. |

## Deployment profile

| Parameter | Mainnet | Preprod | Source |
|---|---|---|---|
| Aggregator | `https://aggregator.release-mainnet.api.mithril.network/aggregator` | `https://aggregator.release-preprod.api.mithril.network/aggregator` | Mithril network configurations |
| Bootstrap anchor | epoch, AVK (root, leaves, total stake) and parameters of one epoch, picked by governance | same | aggregator `/certificate/{hash}` |
| Protocol parameters (fixture epochs) | k = 1,944, m = 16,948, φ_f = 0.2 (epochs 657–658) | k = 5, m = 100, φ_f = 0.7 (epochs 315–316) | certificate `metadata.parameters` |
| Signed entity for bundles | not available (`CardanoBlocksTransactions` not signed) | `CardanoBlocksTransactions` | aggregator `capabilities.signed_entity_types`, 2026-10-01 |
| Service address | 28-byte CLPR Plutus script hash (no script deployed yet) | same | script |
| Contracts | `ClprBlake2sHasher`, `MithrilStmVerifier`, `CardanoMithrilVerifier(stm, blake2s)` | same | no per-network constants |

Preview (`cip34:0-2`) signs `CardanoBlocksTransactions` (pre-release-preview aggregator, 2026-10-01), so it is
covered by the same profile. It was not live-verified here.

## Relayer requirements

- **Mithril aggregator**: `/certificates`, `/certificate/{hash}` for the epoch chain, and
  `POST /proof/v2/cardano-transaction` for the MKMap proof.
- **Transaction and block data**: Koios (`preprod.koios.rest`) for transaction lookup. Cardano's HTTP APIs
  expose no raw headers, so block header and body come over Ouroboros node-to-node BlockFetch from a public
  relay (`preprod-node.play.dev.cardano.org:3001` was used).
- **Cadence**: one rotation per epoch. Mainnet bundles carry at most one rotation, so a stalled channel catches
  up one epoch per bundle.
- **Archive**: none. The aggregator serves the whole certificate chain, and a relay serves old blocks.

## Chain-specific trust and caveats

- Mithril's stake base is the pools registered with Mithril in the epoch, not all Cardano stake.
- Mithril certifies data a block-number offset behind the tip (100 blocks on preprod), so bundles lag the tip
  by at least that much.
- Signature encodings are checked byte for byte. Key points are bound only by x-coordinate and flags,
  which leaves one joint-negation case open (family README, Limits).
- Plutus script hashes are immutable, so the CLPR script cannot change under a channel.

## Live verification

| Network | Fixture | What was verified | Captured |
|---|---|---|---|
| preprod | `test/e2e/fixtures/cardano-live/preprod.json` | Anchor at epoch 315; rotation to 316; a `CardanoBlocksTransactions` certificate of 316; the aggregator's MKMap proof; the block from a public relay; transaction `0ce1d5c3…45fb` in block 5,239,912, its output and inline datum at a script address | 2026-10-01 |
| mainnet | `test/e2e/fixtures/cardano-live/mainnet.json` | Certificate of epoch 658 (57 signatures, 1,946 lottery indexes) and rotation 657 → 658 | 2026-10-01 |

```bash
forge test --match-path 'test/verifiers/*/cardano/*'
npm run test:e2e:cardano-live
npm run cardano-live:refresh
```

## Hiero → Cardano direction

Not started. It needs a Plutus validator that verifies Hiero block proofs, and the CLPR Service as a Plutus
script. Plutus V3 has BLS12-381 builtins (CIP-0381). Whether a Hiero proof fits the per-transaction script
execution budget is not measured here.
