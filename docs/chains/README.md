# Chain pages

One page per chain that a verifier family on this branch covers. Each page lists the chain's deployment profile,
relayer requirements, caveats and live-verification status. The design, trust model, proof format and gas are in the
family README: [ZKsync Era verifier](../../src/verifiers/evm/zksync/README.md).

| Chain | Status | Page |
|---|---|---|
| ZKsync Era | live-verified on ZKsync Sepolia (2026-10-01) | [zksync-era.md](./zksync-era.md) |
| Abstract | family-covered | [abstract.md](./abstract.md) |

Other EraVM ZK Stack chains that settle on Ethereum, such as Sophon, Lens and Cronos zkEVM, are family-covered by the
same verifier with their own diamond address and protocol range. They have no separate page. Their public RPCs did not
serve `zks_getProof` on 2026-10-01, so a relayer needs its own node. Chains that settle on ZKsync Gateway and ZKsync OS
chains are not covered (see the family README).
