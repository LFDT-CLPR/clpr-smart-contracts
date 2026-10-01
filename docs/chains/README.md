# Chain pages

One page per source chain that a verifier on this branch covers. A developer integrating one chain
reads only that chain's page: status, deployment profile, relayer requirements, chain-specific
trust and the live fixture. The protocol design is in the family README.

This branch adds the BLS12-381 (G1 signatures) family: the Internet Computer, verified end to end,
and the consensus half of MultiversX.

| Chain | Status | Page | Family README |
|---|---|---|---|
| Internet Computer | live-verified on ICP mainnet (2026-10-01) | [internet-computer.md](./internet-computer.md) | [Internet Computer and MultiversX verifiers](../../src/verifiers/icpmvx/README.md) |
| MultiversX | in progress: header proofs live-verified on MultiversX mainnet (2026-10-01); storage proofs and rotation blocked on public endpoints | [multiversx.md](./multiversx.md) | [Internet Computer and MultiversX verifiers](../../src/verifiers/icpmvx/README.md) |

Dates are the fixture capture timestamps (`recordedAt` in each `test/e2e/fixtures/<chain>-live/mainnet.json`).
