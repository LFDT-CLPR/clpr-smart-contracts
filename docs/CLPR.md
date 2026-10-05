# CLPR EVM Smart Contracts — Index

This is the **entry point** for working on the CLPR EVM/Solidity implementation.
Load this file first; it tells you which other docs to read for a given task.

## What this repo is

A Foundry project implementing the CLPR cross-ledger messaging protocol as
EVM smart contracts. The protocol itself (concepts, wire formats, algorithms)
is defined in two external spec documents — this implementation must conform
to them and intentionally does not duplicate them.

| Spec doc | Purpose |
|---|---|
| `../clpr-spec/clpr-service.md` | High-level concepts, roles, trust model, recovery scenarios |
| `../clpr-spec/clpr-service-spec.md` | Normative protobuf, state model, algorithms, pseudo-API |
| `DRIFT-REVIEW-2026-05.md` | Open implementation-vs-spec drift (read this before fixing anything material) |

When this repo's docs say "spec §X", the §-number refers to `clpr-service-spec.md`
(unless the doc explicitly says `clpr-service.md §X`).

## Repo layout (what lives where)

```
src/
  ClprService.sol          immutable router; holds all state; DELEGATECALL only
  ClprServiceStorage.sol   shared storage layout (inherited by router + every logic)
  logic/                   four DELEGATECALL targets (ChannelLogic, MessagingLogic,
                           ConnectorLogic, AdminLogic)
  libraries/               BundleLib, ConnectorLib, EndpointLib (state-mutating
                           helpers taking storage refs); ClprProtobuf*, ClprTypes
                           (pure helpers + shared types/events/errors)
  interfaces/              IClprService (public), IClprApplication / IClprConnector /
                           IClprVerifier (callbacks the protocol invokes outward)
test/                      Foundry tests (see docs/testing.md)
script/
  ClprConfig.sol           default ledger/economic values (mirrored in `script/deploy/config.ts`)
  deploy/                  viem deploy CLI + library (`script/deploy/cli.ts`, shared by e2e + `bin/deploy.sh`)
  trace/                   Hiero contract trace-size estimate (`npm run trace:size`)
```

## "I need to..." → read

| Task | Read |
|---|---|
| Understand how the contracts fit together | `architecture.md` |
| Find or modify on-chain state | `architecture.md` (storage section) |
| Add or change a public function | `architecture.md` (dispatch table) + the matching `logic/*.sol` |
| Touch bundle processing / message dispatch | `bundle-flow.md` + spec §4.2–4.6 |
| Touch channel or connector registration | `lifecycle.md` + spec §5.1, §6.3 |
| Read or write protobuf on-chain | `src/libraries/ClprProtobuf*.sol` + spec §1 |
| Write a new test or understand an existing one | `testing.md` |
| Deploy to a chain (operator) or run two-chain e2e | `README.md` → Deployment; `test/e2e/README.md` |
| Investigate an oddity ("why is X done this way?") | `quirks.md` |
| Write or deploy a verifier that takes large inputs on Hedera / Hiero | `hedera-trace-cap.md` |

## Hard rules to remember when editing

1. **Storage layout is sacred.** `ClprServiceStorage.sol` declares the slot order;
   `ClprService` and all four `logic/*` contracts inherit it in identical
   position. Reordering, inserting, or changing field types rewires the router's
   storage. See `architecture.md` § Storage.
2. **Logic contracts run under DELEGATECALL only.** They never hold state; their
   own `Ownable._owner` slot is dead. Don't reason about logic contracts as
   standalone — they are code-only fragments of the router.
3. **The system is not upgradeable.** Logic contract addresses are `immutable`
   in the router constructor.
4. **Cross-ledger byte-equivalence.** `channelId`, `connectorId`, commitments,
   and signed message hashes must produce the same bytes on every CLPR
   implementation (Hiero, EVM, etc.). See `lifecycle.md`.
5. **Things the spec leaves to the implementation are documented here, not
   there.** ABI shape, storage slots, gas budgets, native-token accounting,
   pull-payment fallback, kill-switch — all in this repo's docs.

## Glossary nudge

The spec defines: Channel, Connector, Endpoint, Bundle, Verifier, Running
Hash, Commit-Reveal, Slashing, Trust Anchor. If a term is unfamiliar, look it
up in `clpr-service.md` §2 first — don't try to infer from code.
