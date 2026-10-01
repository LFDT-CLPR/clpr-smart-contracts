# Chain pages

One page per chain this branch's verifiers cover. Each page lists the chain's deployment profile, relayer
needs, caveats and live results.

| Chain | Verifier family | Status | Page |
|---|---|---|---|
| Blast | OP output oracle (`L2OutputOracle`) | live-verified on mainnet data (anvil), PROPOSED full bundle, 2026-10-01 | [blast.md](blast.md) |
| Mantle | OP output oracle (`OPSuccinctL2OutputOracle`) | live-verified on mainnet data (anvil), FINALIZED and PROPOSED, 2026-10-01 | [mantle.md](mantle.md) |
| Katana | OP output oracle (AggLayer `AggchainFEP`) | live-verified on mainnet data (anvil), FINALIZED, 2026-10-01 | [katana.md](katana.md) |
| Fraxtal | OP output oracle (`L2OutputOracle`, no state validation) | live-verified on mainnet data (anvil), FINALIZED full bundle, 2026-10-01 | [fraxtal.md](fraxtal.md) |

The OP Stack dispute-game chains (Base, OP Mainnet, Ink, Unichain, Celo, World Chain, Soneium, X Layer)
have their pages on the X Layer branch (`feat/xlayer-verifier`).
