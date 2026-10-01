# Telos → Hiero · status: family-covered

Telos runs Savanna finality on Spring, like Vaulta, and is served by
[`SavannaVerifier`](../../src/verifiers/evm/antelope/README.md) with no code changes.

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11` / `antelope:4667b205c6838ef70ff7988f6e8257e8` |
| Testnet | `antelope:1eaa0824707c8c16bd25145493bf062a` |
| Chain type | L1, Antelope (Spring v1.2.2 on the queried API nodes, 2026-10-01) |
| Finality source | Strong BLS QC of the finalizer policy (21 finalizers, threshold 15, generation 154 mainnet / 306 testnet on 2026-10-01) |
| Verifier | `SavannaVerifier` ([family README](../../src/verifiers/evm/antelope/README.md)) |
| Trust tier | More than 2/3 of finalizer weight honest; initial policy trusted at channel setup |
| Typical bundle | 437,329 gas, 3,812 B calldata (synthetic, same policy shape) |
| Rotation | 978,807 gas, 6,628 B calldata (synthetic) |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Constructor `chainId` | `antelope:4667b205c6838ef70ff7988f6e8257e8` | `get_info.chain_id` |
| Initial trust anchor | `(generation, sha256(packed policy), 0, 0)` | `get_finalizer_info` at setup |
| Service address | 8-byte little-endian name of the CLPR Service account | none deployed yet |
| Required protocol features | `ACTION_RETURN_VALUE` (block 249642093), `SAVANNA` (block 478429234) | `get_activated_protocol_features` |

## Relayer requirements

Same as Vaulta: a Spring node with SHiP finality data and traces, the validation-tree state from a snapshot,
`get_block` for QCs, an account with resources to push `queuestate`, and one rotation proof per policy change.

## Chain-specific trust and caveats

None in the native chain. Telos EVM is a contract on the native chain; a CLPR channel to Telos EVM would still be
proven through native Telos actions and is not covered here.

## Live verification

Not recorded. The Jungle4 checks (policy digest, QC signatures, validation tree) exercise the same code path.

## Hiero → Telos direction

Not started (same needs as Vaulta; Telos has `BLS_PRIMITIVES2` active).
