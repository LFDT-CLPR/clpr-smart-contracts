# Chain pages

One page per chain this branch's Arbitrum Nitro verifier covers. Each page lists the chain's deployment
profile, relayer needs, caveats and live results.

| Chain | Verifier family | Status | Page |
|---|---|---|---|
| Arbitrum One | Arbitrum Nitro (BoLD) | family-covered (layout checked on L1, 2026-10-01) | [arbitrum-one.md](arbitrum-one.md) |
| Robinhood Chain | Arbitrum Nitro (BoLD) | family-covered (layout checked on L1, 2026-10-01) | [robinhood-chain.md](robinhood-chain.md) |
| Arbitrum Nova | Arbitrum Nitro (BoLD) | family-covered (layout checked on L1, 2026-10-01) | [arbitrum-nova.md](arbitrum-nova.md) |
| Reya | Arbitrum Nitro (BoLD, AnyTrust) | family-covered (layout checked on L1, 2026-10-01) | [reya.md](reya.md) |
| Plume | Arbitrum Nitro (BoLD, AnyTrust, whitelisted validator) | live-verified on mainnet data (anvil), 2026-10-01 | [plume.md](plume.md) |

Arbitrum Sepolia is live-verified too (see the family README). The CometBFT chains merged into this
branch keep their documentation in `src/verifiers/evm/cometbft/README.md`.
