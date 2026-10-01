# Per-chain pages

One page per source chain covered on this branch. Each page lists the chain's deployment profile, relayer needs,
chain-specific caveats and live verification. The design, proof format, gas and upgrade analysis live in the family
README: [New-runtime verifiers, batch 3 (Initia, Fuel Ignition, Waves)](../../src/verifiers/evm/runtimes3/README.md).

| Chain | Status | Page |
|---|---|---|
| Initia | live-verified on Initia mainnet `interwoven-1` (2026-10-01); header signatures through the CometBFT family's accumulator (PR #6) | [initia.md](./initia.md) |
| Fuel Ignition | live-verified on Fuel Ignition + Ethereum mainnet (2026-10-01); weaker trust tier (trusts the Fuel committer) | [fuel-ignition.md](./fuel-ignition.md) |
| Waves | in progress: finality live-verified on testnet (2026-10-01); CLPR state path blocked (no state proofs) | [waves.md](./waves.md) |
