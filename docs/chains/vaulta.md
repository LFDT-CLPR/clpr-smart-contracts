# Vaulta → Hiero · status: in progress (live QCs verified on Jungle4 2026-10-01; full live bundle needs SHiP)

Vaulta (formerly EOS) runs Savanna finality on Spring. Bundles are verified by
[`SavannaVerifier`](../../src/verifiers/evm/antelope/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906` / `antelope:aca376f206b8fc25a6ed44dbdc66547c` |
| Testnet | Jungle4, `antelope:73e4385a2708e6d7048834fbc1079f2f` |
| Chain type | L1, Antelope (Spring v1.0.5 on the queried API node, 2026-10-01) |
| Finality source | Strong BLS QC of the finalizer policy (21 finalizers, threshold 15, generation 321 on 2026-10-01) |
| Verifier | `SavannaVerifier` ([family README](../../src/verifiers/evm/antelope/README.md)) |
| Trust tier | More than 2/3 of finalizer weight honest; initial policy trusted at channel setup |
| Typical bundle | 437,329 gas, 3,812 B calldata (synthetic, same policy shape) |
| Rotation | 978,807 gas, 6,628 B calldata (synthetic, one policy change) |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Constructor `chainId` | `antelope:aca376f206b8fc25a6ed44dbdc66547c` | `get_info.chain_id`, CAIP-2 `antelope` namespace |
| Initial trust anchor | `(generation, sha256(packed policy), 0, 0)` from `verifyConfig` | `get_finalizer_info.active_finalizer_policy` at setup, packed as Spring packs `finalizer_policy` |
| Service address | 8-byte little-endian `eosio::name` of the CLPR Service account | the account the CLPR contract is deployed to (none yet) |
| Required protocol features | `ACTION_RETURN_VALUE` (block 269183454), `SAVANNA` (block 396090329) | `get_activated_protocol_features` |

## Relayer requirements

- A Spring node with SHiP (`state_history_plugin`, `trace-history = true`, `finality-data-history = true`) for the
  action receipts and the `finality_data` (base digest, reversible-blocks root, QC-claim data) of each block.
- The validation tree's subtree roots: start from a Spring v8 snapshot (`block_state` holds them), then append one
  finality leaf per block from SHiP.
- `get_block` for the QC extension of the block after C (strong votes only).
- An Antelope account with CPU/NET to push `queuestate` once per bundle.
- One rotation proof per finalizer policy change.

## Chain-specific trust and caveats

None beyond the family baseline. Vaulta's policy generation changes whenever the elected producer set changes;
each change is one rotation proof.

## Live verification

- Testnet fixture: `test/e2e/fixtures/vaulta-live/jungle4.json` (Jungle4 snapshot at block 289703167, 2026-10-01).
- Refresh: `npm run antelope:jungle4:refresh -- --snapshot <spring-v8-snapshot.bin>`.
- Replay: `npm run test:e2e:antelope-live` and `forge test --match-test live_jungle4`.
- Verified: the live policy (generation 129) packs to the snapshot's last pending policy digest; real QCs on
  blocks 289703165 and 289703166 (21/21 strong votes) verify in `SavannaVerifier` against the snapshot's finality
  digests; the snapshot's validation tree (132,793,544 leaves) folds to the `finality_mroot` of block 289703168.
- Not yet verified on live data: a full `verifyBundle` (needs SHiP finality data; see the family README).
  Vaulta mainnet itself has not been recorded.

## Hiero → Vaulta direction

Not started. It needs a CLPR Service and a Hiero verifier as an Antelope (WASM) contract. Vaulta has
`CRYPTO_PRIMITIVES` and `BLS_PRIMITIVES2` host functions, which are the starting point for signature checks.
