# Chain pages

One page per chain served by the verifiers that this branch adds.

| Chain | Verifier | Status | Page |
|---|---|---|---|
| dYdX | `CosmosModuleVerifier` with the native `x/clpr` module | in progress (localnet bundle and live mainnet commit + store proof verified 2026-10-01; module not on mainnet) | [dydx.md](dydx.md) |

This branch also carries the CometBFT, Provenance and THORChain verifiers from
`feat/provenance-verifier`. Their chain pages are on `feat/polythor-verifier`, the most complete
CometBFT-family branch.
