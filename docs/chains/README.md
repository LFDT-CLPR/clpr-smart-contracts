# Chain pages

One page per chain covered on this branch. Each page lists the deployment profile, relayer needs, trust
caveats and live-verification results for one chain. The design is in the verifier README linked from
each page.

| Chain | Status | Page | Verifier |
|---|---|---|---|
| Algorand | live-verified on mainnet and testnet (2026-10-01) | [algorand.md](algorand.md) | [`AlgorandStateProofVerifier`](../../src/verifiers/evm/algorand/README.md) |
| Cardano | live-verified on preprod and mainnet (2026-10-01); mainnet bundles blocked | [cardano.md](cardano.md) | [`CardanoMithrilVerifier`](../../src/verifiers/evm/cardano/README.md) |
