# Anubis → Hiero

Status: family-covered. Headers and a vote attestation were checked live; no full bundle was run.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `6714` / `eip155:6714` |
| Chain type | L1, BSC-derived client (Geth v1.0.1 fork) running Parlia with fast finality |
| Finality source | BLS vote attestation of at least 2/3 of the validator set |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)), no code change |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted |
| Typical bundle | Not measured on Anubis. BSC mainnet with the same 21-validator size: 1,953,408 gas, 23,684 B |
| Rotation | Not measured on Anubis. BSC mainnet: about 0.41M gas and 5.4 KB per rotation |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 6714 | Live headers, checked by the capture code (family README, "Parlia-family chains") |
| `epochLength` | 1000 | Live epoch blocks |
| Validators | 21 | Live epoch block |
| `turnLength` | 1 | Live epoch block |
| Bootstrap epoch block | Not chosen yet | Pick a recent epoch block at deployment |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- Same RPC methods as BNB Smart Chain: `eth_chainId`, `eth_getBlockByNumber`, `eth_getProof`.
- `eth_getProof` support on Anubis RPCs was not checked.
- One rotation per 1000-block epoch of absence.

## Chain-specific trust and caveats

- Same as the family baseline. The check verified header hashes, the chain-id seal, the epoch layout and a 21 of 21
  BLS attestation with the verifier's ciphersuite.

## Live verification

No fixture is committed for Anubis. A full live run needs a capture with `eth_getProof` from an Anubis RPC.

## Hiero → Anubis

Not built. It would use the reference Hiero verifier on Anubis's EVM and is blocked on the same Hiero proof source
as Hiero → Ethereum.
