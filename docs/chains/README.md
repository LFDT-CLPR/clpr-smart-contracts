# Chain pages

One page per source chain that this branch verifies into Hiero. Each page lists the chain's quick facts, its exact
deployment profile, what a relayer needs, chain-specific caveats and how the live data was verified. Design, trust
model and proof format are in the verifier READMEs:
[Rootstock (`RootstockVerifier`)](../../src/verifiers/evm/rootstock/README.md) and
[Stacks (`StacksVerifier`)](../../src/verifiers/stacks/README.md). Both are Bitcoin L2s with different trust:
Rootstock rests on merged-mining proof of work, Stacks on its signer set.

| Chain | Status | Trust | Page |
|---|---|---|---|
| Rootstock | live-verified on mainnet headers (2026-10-01); full bundle on RSKj regtest | Merged-mining proof of work, `k` confirmations | [rootstock.md](rootstock.md) |
| Stacks | live-verified on mainnet (2026-10-01): signatures, rotation, MARF proofs; queue record synthetic | 70% of the reward cycle's signer weight | [stacks.md](stacks.md) |
