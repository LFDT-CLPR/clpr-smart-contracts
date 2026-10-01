# XPR Network → Hiero · status: live-verified on XPR mainnet and testnet (2026-10-01), finality and inclusion

XPR Network (formerly Proton) runs legacy Antelope DPoS (Leap; Savanna not activated). Bundles are verified by
[`AntelopeDposVerifier`](../../src/verifiers/evm/antelope/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0` / `antelope:384da888112027f0321850a169f737c3` |
| Testnet | `antelope:71ee83bcf52142d61019d95f9cc5427b` |
| Chain type | L1, Antelope (Leap v5.0.0 on the queried API nodes, 2026-10-01) |
| Finality source | DPoS last-irreversible-block rule over K1-signed headers (21 producers, 12-block rounds, LIB lag about 333 blocks) |
| Verifier | `AntelopeDposVerifier` ([family README](../../src/verifiers/evm/antelope/README.md)) |
| Trust tier | More than 2/3 of producers honest; initial producer schedule trusted at channel setup |
| Typical bundle | live finality + inclusion 3,733,705 gas, 45,636 B `verifyBundle` calldata (mainnet block 406287064) |
| Rotation | 8,672,871 gas, 92,868 B calldata (synthetic, 21 producers) |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| Constructor `chainId` | `antelope:384da888112027f0321850a169f737c3` | `get_info.chain_id` |
| Initial trust anchor | `(schedule version, keccak256(version, producers, signer addresses))` | `get_block_header_state.active_schedule` (version 1414 on mainnet, 824 on testnet, 2026-10-01); signer = keccak address of each producer's K1 block-signing key |
| Service address | 8-byte little-endian name of the CLPR Service account | none deployed yet |
| Required protocol features | `ACTION_RETURN_VALUE` (mainnet block 220936766, testnet 223041057), `WTMSIG_BLOCK_SIGNATURES` | `get_activated_protocol_features` |

## Relayer requirements

- `get_block` for every block from X until the LIB rule holds (about 333 blocks), and
  `get_block_header_state(X)` for the block-root accumulator and pending schedule hash; the relayer appends block
  ids to the accumulator to get each signed header's root.
- The receipts of block X: Hyperion `/v2/history/get_transaction` (used by the refresh script) or any node with the
  trace API.
- An account with CPU/NET to push `queuestate` once per bundle.
- One rotation proof per producer schedule change, with each new producer's key in uncompressed form.

## Chain-specific trust and caveats

- Producers whose signing authority needs several keys, or uses R1/WebAuthn keys, never count toward the rule.
- If XPR activates Savanna, its channels must move to `SavannaVerifier` (see the family README, "Upgrades and forks").

## Live verification

- Fixtures: `test/e2e/fixtures/xpr-live/mainnet.json` (block 406287064, 334 headers, 30 signed) and
  `test/e2e/fixtures/xpr-live/testnet.json` (block 408676493, 333 headers, 30 signed), recorded 2026-10-01.
- Refresh: `npm run antelope:xpr:refresh -- mainnet` (or `testnet`).
- Replay: `npm run test:e2e:antelope-live` and `forge test --match-test live_xpr`.
- Verified: real header chains, 30 real producer signatures and the DPoS rule prove a real action receipt
  (`arbx::arb` on mainnet) against the block's `action_mroot`; `verifyBundle` then rejects it as not a CLPR
  `queuestate` action (`NotServiceAction`). A tampered signature, a chain one header short of the rule, and a
  wrong schedule version are rejected.

## Hiero → XPR Network direction

Not started. It needs a CLPR Service and Hiero verifier as an Antelope (WASM) contract; XPR has
`CRYPTO_PRIMITIVES` but not `BLS_PRIMITIVES2`.
