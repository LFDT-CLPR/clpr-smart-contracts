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

## Repo layout (what lives where)

```
src/
  ClprService.sol          immutable router; holds all state; DELEGATECALL only
  ClprServiceStorage.sol   shared storage layout (inherited by router + every logic)
  logic/                   five DELEGATECALL targets (ChannelLogic, MessagingLogic,
                           BundleLogic, ConnectorLogic, AdminLogic) over
                           logic/base/LogicModuleBase.sol
  libraries/
    ClprTypes.sol          shared structs, enums, errors, file-scope events
    service/               BundleLib, ConnectorLib, ManifestLib, EndpointValidation
                           (state-mutating helpers taking storage refs)
    codec/                 ClprProtobuf(+Helpers), ClprConfigHash, BundleDecodeHelper
    crypto/                ECDSA, Sha384
    proof/                 evm/, hiero/, qbft/, beacon/, cometbft/ proof primitives
  verifiers/               IClprVerifier implementations by source-chain family:
                           evm/common (shared EVM base), evm/qbft, evm/ethereum,
                           evm/sei, evm/avalanche, hiero/ (+ TSSVerifier, wraps/)
  dependencies/            SafeDependencies.sol — Safe smart-account re-exports
  interfaces/              IClprService (public), IClprApplication / IClprConnector /
                           IClprVerifier (callbacks the protocol invokes outward),
                           ILogicModule (declared; no contract implements it)
test/                      Foundry tests (see docs/testing.md)
script/
  ClprConfig.sol           default ledger/economic values (mirrored in `script/deploy/config.ts`)
  deploy/                  viem deploy CLI + library (`script/deploy/cli.ts`, shared by e2e + `bin/deploy.sh`)
```

## "I need to..." → read

| Task | Read |
|---|---|
| Understand how the contracts fit together | `architecture.md` |
| Find or modify on-chain state | `architecture.md` (storage section) |
| Add or change a public function | `architecture.md` (dispatch table) + the matching `logic/*.sol` |
| Touch bundle processing / message dispatch | `bundle-flow.md` + the spec's bundle-processing algorithms |
| Touch channel or connector registration | `lifecycle.md` + the spec's channel and connector lifecycle |
| Touch endpoint registration or the endpoint manifest | `src/libraries/service/ManifestLib.sol` + `src/logic/AdminLogic.sol` + `evm-platform-spec.md` (E-9) |
| Read or write protobuf on-chain | `src/libraries/codec/ClprProtobuf*.sol` + `evm-platform-spec.md` (E-12) + the spec's protobuf definitions |
| Reproduce EVM slots, the running hash, or encodings from another platform | `evm-platform-spec.md` |
| Understand what an EVM peer verifier proves (slots, proof shapes) | [`evm/common/README.md`](../src/verifiers/evm/common/README.md) + `evm-platform-spec.md` (E-10) |
| Add or change a source-chain verifier | The family's doc under `src/verifiers/` (table below) + `src/interfaces/IClprVerifier.sol` + `evm-platform-spec.md` |
| Change a storage slot a peer verifier proves | `evm-platform-spec.md` (E-10) + every verifier doc below — remote verifiers derive these slots, so a change needs lockstep peer redeploys |
| Write a new test or understand an existing one | `testing.md` |
| Deploy to a chain (operator) or run two-chain e2e | `README.md` → Deployment; `test/e2e/README.md` |
| Operate the Safe that owns a deployment | `safe-runbook.md`; the kill switch in `runbooks/kill-switch.md` |
| Investigate an oddity ("why is X done this way?") | `quirks.md` |

## Verifier families

Each source-chain family has its reference documentation next to its implementation — trust anchor
layout, proof shape, verification steps, reverts, library map.

| Family | Source | Doc |
|---|---|---|
| Shared EVM base | `src/verifiers/evm/common/ClprEvmBundleVerifier.sol` | [`evm/common/README.md`](../src/verifiers/evm/common/README.md) |
| Besu QBFT | `src/verifiers/evm/qbft/QbftHeaderModeVerifier.sol`, `QbftContractModeVerifier.sol`, legacy `QBFTVerifier.sol` | [`evm/qbft/qbft-verifier.md`](../src/verifiers/evm/qbft/qbft-verifier.md), with [`qbft-header-mode.md`](../src/verifiers/evm/qbft/qbft-header-mode.md) and [`qbft-contract-mode.md`](../src/verifiers/evm/qbft/qbft-contract-mode.md) |
| Ethereum mainnet | `src/verifiers/evm/ethereum/EthMainnetVerifier.sol` | [`evm/ethereum/README.md`](../src/verifiers/evm/ethereum/README.md) |
| Sei (CometBFT) | `src/verifiers/evm/sei/SeiCometBftVerifier.sol` | [`evm/sei/README.md`](../src/verifiers/evm/sei/README.md) |
| Hiero | `src/verifiers/hiero/HieroVerifier.sol` | [`hiero/hiero-verifier.md`](../src/verifiers/hiero/hiero-verifier.md) |
| Avalanche (mock) | `src/verifiers/evm/avalanche/MockAvalancheVerifier.sol` | — test harness only, no cryptographic verification |

Gas measurements live beside the verifiers: [`evm/GAS_REPORT.md`](../src/verifiers/evm/GAS_REPORT.md),
[`evm/qbft/GAS_REPORT.md`](../src/verifiers/evm/qbft/GAS_REPORT.md),
[`hiero/GAS_REPORT.md`](../src/verifiers/hiero/GAS_REPORT.md).

## Hard rules to remember when editing

1. **Storage layout is sacred.** `ClprServiceStorage.sol` declares the slot order;
   `ClprService` and all five `logic/*` contracts (via `logic/base/LogicModuleBase.sol`)
   inherit it in identical position. Reordering, inserting, or changing field types
   rewires the router's storage and the slots peer verifiers prove. See
   `architecture.md` (storage section) and `evm-platform-spec.md` (E-10).
2. **Logic contracts run under DELEGATECALL only.** They never hold state and do
   not inherit `Ownable`; they reach the owner through
   `ClprServiceStorage._getOwner()`, which `sload`s hard-coded slot 38 —
   meaningful only in the router's storage context. Don't reason about logic
   contracts as standalone; they are code-only fragments of the router.
3. **The system is not upgradeable.** Logic contract addresses are `immutable`
   in the router constructor.
4. **Cross-ledger byte-equivalence.** `channelId`, `connectorId`, commitments,
   and signed message hashes must produce the same bytes on every CLPR
   implementation (Hiero, EVM, etc.). See `lifecycle.md`.
5. **Things the spec leaves to the implementation are documented here, not
   there.** ABI shape, storage slots, gas budgets, native-token accounting,
   pull-payment fallback, kill-switch — all in this repo's docs.

## Glossary nudge

The spec defines: Channel, Connector, Endpoint, Endpoint Manifest, Bundle,
Verifier, Running Hash, Commit-Reveal, Slashing, Trust Anchor. If a term is
unfamiliar, look it up in `clpr-service.md` first — don't try to infer from code.
