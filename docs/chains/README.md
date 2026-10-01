# Chain pages

One page per source chain that a verifier on this branch covers. A developer integrating one chain
reads only that chain's page: status, deployment profile, relayer requirements, chain-specific
trust and the live fixture. The protocol design of each verifier is in its README.

This branch adds two EVM L1s that are not served by an existing family: Arc (Malachite) and Plasma
(PlasmaBFT). It also carries the CometBFT family commits; that family's chains are documented in
its own README.

| Chain | Status | Page | Verifier README |
|---|---|---|---|
| Arc | live-verified on Arc testnet (2026-10-01) | [arc.md](./arc.md) | [ArcMalachiteVerifier](../../src/verifiers/evm/arc/README.md) |
| Plasma | live-verified on Plasma mainnet (2026-10-01); no committee rotation yet | [plasma.md](./plasma.md) | [PlasmaBftVerifier](../../src/verifiers/evm/plasma/README.md) |

Dates are the fixture capture timestamps (`capturedAt` in each `test/e2e/fixtures/<chain>-live/*.json`).
