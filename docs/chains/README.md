# Chain pages

One page per chain this branch's verifiers cover. Each page lists the chain's deployment profile, relayer
needs, caveats and live results.

| Chain | Verifier family | Status | Page |
|---|---|---|---|
| Base | OP Stack dispute games | family-covered (Base Sepolia live-verified on anvil, 2026-09-30) | [base.md](base.md) |
| OP Mainnet | OP Stack dispute games (super roots) | family-covered | [op-mainnet.md](op-mainnet.md) |
| Ink | OP Stack dispute games (super roots) | family-covered | [ink.md](ink.md) |
| Unichain | OP Stack dispute games (super roots) | live-verified on mainnet data to the L2 state root (anvil), 2026-10-01 | [unichain.md](unichain.md) |
| Celo | OP Stack dispute games (OP Succinct Lite) | family-covered | [celo.md](celo.md) |
| World Chain | OP Stack dispute games (permissioned) | family-covered | [world-chain.md](world-chain.md) |
| Soneium | OP Stack dispute games (permissioned, super roots) | family-covered | [soneium.md](soneium.md) |
| X Layer | OP Stack dispute games (OP Succinct Lite, permissioned) | live-verified on mainnet data to the L2 state root (anvil), 2026-10-01 | [x-layer.md](x-layer.md) |
| RISE | OP Stack dispute games (OP Succinct Lite) | live-verified on mainnet data to the L2 state root (anvil), 2026-10-01 | [rise.md](rise.md) |
| Ronin | OP Stack dispute games (permissioned) | live-verified on mainnet data to the L2 state root (anvil), 2026-10-01 | [ronin.md](ronin.md) |
| BOB | OP Stack dispute games (permissioned) | live-verified on mainnet data, full FINALIZED bundle (anvil), 2026-10-01 | [bob.md](bob.md) |
| MegaETH | OP Stack dispute games (Kailua, portal as registry) | live-verified on mainnet data to the L2 state root (anvil), 2026-10-01 | [megaeth.md](megaeth.md) |
| Rollux | OP Stack output oracle on Syscoin | blocked: settles on Syscoin NEVM, which no verifier here covers | [rollux.md](rollux.md) |

Blast, Mantle, Katana and Fraxtal (output-oracle settlement) have their pages on the output-oracle branch
(`feat/opadapters-verifier`).
