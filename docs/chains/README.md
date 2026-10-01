# Chain pages

One page per source chain that a verifier on this branch covers. A developer integrating one chain
reads only that chain's page: status, deployment profile, relayer requirements, chain-specific
trust and the live fixture. The protocol design is in the family README.

This branch adds the Ed25519 light-client family: NEAR, TON, and Aurora (an EVM running inside a
NEAR contract), with a multi-transaction Ed25519 signature accumulator for quorums that do not fit
one Hedera transaction.

| Chain | Status | Page | Family README |
|---|---|---|---|
| NEAR | live-verified on NEAR mainnet and testnet (2026-10-01) | [near.md](./near.md) | [NEAR, TON and Aurora verifiers](../../src/verifiers/evm/neartons/README.md) |
| TON | live-verified on TON mainnet and testnet (2026-10-01) | [ton.md](./ton.md) | [NEAR, TON and Aurora verifiers](../../src/verifiers/evm/neartons/README.md) |
| Aurora | family-covered: the aurora-engine storage proof is live-verified on an Aurora silo on NEAR mainnet (2026-10-01); Aurora mainnet's engine state is refused by public NEAR RPCs | [aurora.md](./aurora.md) | [NEAR, TON and Aurora verifiers](../../src/verifiers/evm/neartons/README.md) |

Dates are the fixture capture timestamps (`capture.capturedAt` in each
`test/e2e/fixtures/<chain>-live/*.json`).
