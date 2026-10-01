# Chain pages

One page per chain that a verifier family on this branch covers. Each page lists the chain's deployment profile,
relayer requirements, caveats and live-verification status. The design, trust model, proof format and gas are in the
family README: [Starknet verifier](../../src/verifiers/evm/starknet/README.md).

| Chain | Status | Page |
|---|---|---|
| Starknet (mainnet and Sepolia) | live-verified on Starknet Sepolia (2026-10-01) | [starknet.md](./starknet.md) |

Starknet-stack chains that settle on Ethereum through a StarkWare core contract with the same state commitment can use
the same contracts with their own core address and layout. None was checked for this branch, so none is listed.
Chains that settle on Starknet (L3s) and StarkEx are not covered (see the family README).
