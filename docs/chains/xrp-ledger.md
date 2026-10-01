# XRP Ledger → Hiero

XRP Ledger → Hiero · status: live-verified on XRPL mainnet and testnet (2026-10-01)

`XrplVerifier` proves CLPR messages sent by a channel's outbox account: AccountSet transactions with
one `clpr/v1` memo each, in a ledger validated by at least 80% of the committed UNL. Full design:
[XrplVerifier README](../../src/verifiers/evm/xrpl/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | network id 0 / `xrpl:0` (mainnet); network id 1 / `xrpl:1` (testnet) |
| Chain type | L1, XRP Ledger consensus (rippled), no smart contracts |
| Finality source | UNL validations (secp256k1) on the ledger hash, at least `ceil(0.8 × UNL)` |
| Verifier contract | `src/verifiers/evm/xrpl/XrplVerifier.sol` with `XrplLightClient.sol`, `XrplUnlKeys.sol`, `ClprSha512Hasher.sol` · [family README](../../src/verifiers/evm/xrpl/README.md) |
| Trust tier | 80% of the configured UNL honest; the outbox's k-of-n signer list decides message content (operator trust) |
| Typical bundle | 6,890,892 gas, 15,204 B (testnet, 1 message via the skip list); 5,883,034 gas, 11,812 B for one mainnet tx in a validated ledger (28 of 35 validations) |
| Rotation | 7,665,815 gas, 13,700 B (mainnet, one validator manifest applied) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `caip2` | `"xrpl:0"` (mainnet), `"xrpl:1"` (testnet) | `test/e2e/tests/verifiers/xrpl-live.spec.ts` |
| `lightClient` | `XrplLightClient` address (constructed with `ClprSha512Hasher` and `XrplUnlKeys`) | `src/verifiers/evm/xrpl/XrplLightClient.sol` |
| UNL (anchor `unlHash`, `unlCount`) | Mainnet: vl.ripple.com list sequence 85, 35 validators. Testnet: vl.altnet.rippletest.net sequence 59, 6 validators | `test/e2e/fixtures/xrpl-live/mainnet.json`, `testnet.json` (`unl`) |
| Outbox account (channel service address) | Testnet fixture: `rhXvf3QDFwuaQQWasGgPkBTUwnRYXd2DFg`, 2-of-3 signer list, master disabled | `test/e2e/fixtures/xrpl-live/messages.json` |
| `seqBase` | Testnet fixture: 21,187,269 | `messages.json` (`seq_base`) |
| `minLedgerSeq` | 0 at setup; raised to the ledger of each applied manifest | `XrplVerifier.sol:verifyBundle` |

## Relayer requirements

- **Validations live:** subscribe to the `validations` stream (WebSocket) and keep the blobs for the
  ledgers that contain outbox messages. They are not served later.
- **Ledgers:** `ledger` with `binary` and `expand` (tx + meta for the whole ledger) to rebuild the
  transaction-tree path. Public full-history servers work (`xrplcluster.com`).
- **State paths** (AccountRoot at config, skip list): the rippled peer protocol (`TMGetLedger`), port
  51235, as in `test/e2e/relay/xrplPeer.ts`. No public RPC returns SHAMap inner nodes.
- **Reach:** messages older than the validated ledger are linked by parent hash (about 100k gas per
  ledger) or the skip list (last 256 ledgers, about 15 minutes).
- **Manifests:** when a UNL validator rotates its signing key, include its manifest in the next
  bundle.

## Chain-specific trust and caveats

- UNL membership changes are not proven; they need a channel re-configuration.
- The outbox must be a multisig with the master key disabled and no regular key (checked at config).
  Tickets, Batch and Delegate are rejected, so the Sequence order is the message order.
- One outbox account per channel. Serialized memos are at most 1024 bytes (about 800 bytes of
  message payload advertised).

## Live verification

| Item | Value |
|---|---|
| Fixtures | `test/e2e/fixtures/xrpl-live/mainnet.json`, `testnet.json`, `messages.json` |
| Captured | mainnet 2026-10-01T05:10:37Z, testnet 2026-10-01T05:24:08Z (`capturedAt`) |
| Refresh | `npm run xrpl-live:refresh` |
| Replay | `forge build && npm run test:e2e:xrpl-live` |
| What was verified | Mainnet ledger 107,352,581: 35 UNL validations (28 used), a memo Payment with its metadata, an AccountRoot state proof, one real ed25519-master manifest. Testnet: `verifyConfig` on the outbox AccountRoot (6 of 6), and `verifyBundle` on the five live `clpr/v1` outbox messages linked through the skip list of ledger 21,187,460 |

## Hiero → XRP Ledger direction

Not built on this branch. XRPL has no contracts that can verify Hiero proofs. The release-today path
is a k-of-n multisig of operators who each verify Hiero bundles off-ledger and then sign the
delivery from an executor account (attestor-tier trust). Smart Escrows (XLS-100) could enforce k-of-n
signatures on-ledger once the amendment is enabled; it is not on mainnet or testnet as of
2026-10-01.
