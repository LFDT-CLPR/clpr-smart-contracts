# Chain pages

One page per source chain that a verifier on this branch covers. A developer integrating one chain
reads only that chain's page: status, deployment profile, relayer requirements, chain-specific trust
and the live fixture. The protocol design of each verifier is in its README.

This branch adds three non-EVM-storage chains whose CLPR endpoint publishes a queue record instead
of exposing EVM storage: the XRP Ledger (UNL validations), Hyperliquid HyperEVM (attestor tier) and
the Mixin kernel (CoSi).

| Chain | Status | Page | Verifier README |
|---|---|---|---|
| XRP Ledger | live-verified on XRPL mainnet and testnet (2026-10-01) | [xrp-ledger.md](./xrp-ledger.md) | [XrplVerifier](../../src/verifiers/evm/xrpl/README.md) |
| Hyperliquid (HyperEVM) | live-verified on HyperEVM mainnet (2026-10-01); **attestor-trusted**, test attestor keys | [hyperliquid.md](./hyperliquid.md) | [HyperEvmVerifier](../../src/verifiers/evm/hyperliquid/README.md) |
| Mixin | live-verified on Mixin mainnet (2026-10-01), including node-set rotation | [mixin.md](./mixin.md) | [MixinKernelVerifier](../../src/verifiers/evm/mixin/README.md) |

Dates are the fixture capture timestamps (`capturedAt` in each `test/e2e/fixtures/<chain>-live/*.json`).
