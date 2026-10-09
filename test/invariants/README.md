# CLPR invariant tests

Forge invariant fuzzing for `ClprService` (`ClprInvariant.t.sol`) using the [handler pattern](https://www.getfoundry.sh/guides/invariant-testing#handler-pattern) (`ClprHandler.sol`).

## How it works

1. **Fuzzer** calls only whitelisted `ClprHandler` functions, with bounded random inputs and optional Forge time/block delays.
2. The handler performs `vm.prank`, funding, `try/catch`, and updates **ghost** registries; most mutators use `reconcileEth` to track `service` balance deltas.
3. After **each** handler call, Forge runs every `invariant_`* function on `ClprInvariantTest`, which reads the **deployed** `ClprService` (public views + `vm.load` for internal slots).

State lives on the router; logic is `delegatecall`'d from immutable modules — invariants always assert against the `ClprService` instance.

```
Fuzzer → ClprHandler.*() → ClprService (delegatecall)
              ↓
    invariant_*() on ClprInvariantTest (after each step)
```

## Running

```bash
# Invariant suite only
forge test --match-contract ClprInvariantTest

# Storage slot guard (separate contract, run after layout changes)
forge test --match-contract ClprStorageLayoutGuardTest

# Full CI test run includes both
forge test
```

Configuration: root `[foundry.toml](../../foundry.toml)` `[invariant]` block.

## Files


| File                                                                            | Role                                                                                  |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `[ClprInvariant.t.sol](ClprInvariant.t.sol)`                                    | `setUp`, `invariant_*` functions, ACL/kill-switch probes on `service`                 |
| `[ClprHandler.sol](ClprHandler.sol)`                                            | Fuzz target: protocol actions + ghosts                                                |
| `[ClprStorageLayoutGuard.t.sol](ClprStorageLayoutGuard.t.sol)`                  | Asserts `ClprServiceStorageSlots` match `storage-layout.json`                         |
| `[ClprServiceStorageSlots.sol](../helpers/ClprServiceStorageSlots.sol)`         | Top-level slot constants + `ClprStorageLayoutLib`                                     |
| `[ClprInvariantEthLib.sol](../helpers/ClprInvariantEthLib.sol)`                 | Sums liabilities via `vm.getMappingLength` / `getMappingSlotAt`                       |
| `[ClprConnectorRegisterHelper.sol](../helpers/ClprConnectorRegisterHelper.sol)` | External wrapper so `registerConnector` can `try/catch` without being a fuzz target   |
| `[InvariantBundleHelper.sol](../helpers/InvariantBundleHelper.sol)`             | Mock `QueueMetadata` builders for bundle handler actions                              |
| `[MockClprVerifier.sol](../mocks/MockClprVerifier.sol)`                         | Deterministic `verifyBundle` / `verifyConfig`; peer seeds for roster checks           |
| `[MockClprApplication.sol](../mocks/MockClprApplication.sol)`                   | Inbound DATA message target                                                           |
| `[EthRejector.sol](../mocks/EthRejector.sol)`                                   | Rejects `receive`; holds `pendingWithdrawals` when slash/charge direct transfer fails |


## Handler setup

`ClprHandler` constructor (called from `setUp`):

- Funds 5 fuzz **actors** and tracks accounts (connectors, `ethRejector`, owner, etc.).
- **Bootstraps** one completed channel + one live connector so messaging/bundle actions are always reachable.
- Registers `ethRejector` as an endpoint (for slash/charge-fail scenarios).
- Sets `initialServiceBalance` and starts ETH ghost baselines after bootstrap.

`setUp` also:

- Calls `vm.startMappingRecording()` **before** deploying `ClprService` and the handler (records all mapping keys touched on `service`, including `setUp` config writes and handler bootstrap).
- Creates `aclProbe` (`makeAddr`) — never registered as an endpoint by the handler; used only in invariant ACL/kill-switch probes. `notePendingCandidate(aclProbe)` allows pending-withdrawal fuzzing only.

## Fuzz targets

Listed in `_targetHandlerMutators()` — **not** fuzzed: view getters, `syncPendingWithdrawalAccounts`, `notePendingCandidate`, ghost accessors.


| Handler function                                                   | Purpose                                                           |
| ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `registerChannel` / `completeChannel` / `closeChannel`    | Channel lifecycle                                              |
| `registerEndpoint` / `removeEndpoint` / `topUpBond`                | Endpoint bonds                                                    |
| `registerConnector`                                                | Via `ClprConnectorRegisterHelper` (external `try/catch`)          |
| `removeConnector` / `topUpConnectorStake`                          | Connector admin; remove pays a tracked actor recipient            |
| `sendMessage`                                                      | Outbound enqueue                                                  |
| `submitEmptyBundle`                                                | Empty bundle when outbound fully acked; optional `vm.warp(0–3s)`  |
| `submitInboundBundle`                                              | Single inbound DATA message                                       |
| `submitInboundSlashPendingEthRejector`                             | Underfunded connector → slash → `pendingWithdrawals[ethRejector]` |
| `submitInboundChargeFailSlashPendingEthRejector`                   | `payForExecution` revert → slash → pending on `ethRejector`       |
| `submitAckBundle`                                                  | Ack pending outbound; optional `vm.warp(0–3s)`                    |
| `collectPending`                                                   | Pull-payment when `pendingWithdrawals > 0`                        |
| `collectPendingWhileDisabled`                                      | Same while kill switch off (sets INV-KILL ghosts)                 |
| `probeReEnableWhenDisabled`                                        | Owner `setClprEnabled(true)` then `false` while disabled          |
| `setVerifierRevert`                                                | Toggle mock verifier revert (**no** `reconcileEth`)               |
| `setTightResourceCaps`                                             | Low `maxChannels` / `maxConnectors`                            |
| `attemptCompleteAtChannelCap` / `attemptRegisterAtConnectorCap` | Exercise cap boundaries                                           |
| `setClprEnabled` / `updateLedger` / `updateEconomic`               | Kill switch + admin config                                        |


**Slash / charge-fail paths:** temporarily `transferOwnership` to `ethRejector` so the service owner (fallback payout recipient) also rejects ETH, forcing `pendingWithdrawals` credits.

## Handler model

- `targetContract(address(handler))` + `targetSelector` — constrain *what* the fuzzer calls.
- **Bounded inputs** — actors, stakes, bonds, queue/rate limits capped.
- **Ghost variables** — registries for channels, connectors, endpoints, commitments, inflight/quota, cap violations, bundle/enqueue violations, kill-switch probe outcomes.
- `reconcileEth` modifier — on mutators that move ETH through `service`; updates `ghostEthIn` / `ghostEthOut`.
- `try/catch`* — failed preconditions revert inside the handler; exploration continues (`fail_on_revert = false`).
- `queueLimitsRevision` — bumped on successful `updateLedger` / `updateEconomic`; per-channel `lastEnqueueLimitsRevision` updated on successful `sendMessage`.

## Run configuration


| Setting            | Value   | Rationale                                                                        |
| ------------------ | ------- | -------------------------------------------------------------------------------- |
| `runs`             | 256     | Random sequences **per** `invariant_`* function                                  |
| `depth`            | 100     | Handler calls per sequence                                                       |
| `fail_on_revert`   | `false` | Handler `try/catch` expects many reverts; invariants check state after each step |
| `max_time_delay`   | 10      | `submitBundle` rate limit uses `block.timestamp`                                 |
| `max_block_delay`  | 10      | Aligned with time delay                                                          |
| `shrink_run_limit` | 5000    | Cap shrink attempts on counterexample                                            |


### Runtime

Each of the `invariant_*` functions runs its own campaign: **256 × 100 = 25,600** handler calls per invariant (Forge reports `calls: 25600` per test). After **every** handler call, **all** invariants run — total work scales with invariant count.

Full `forge test` also runs `ClprStorageLayoutGuardTest` and unit tests.

### Time warping

- Forge `max_time_delay` / `max_block_delay` apply between handler calls.
- Handler `vm.warp(0–3)` only in `submitEmptyBundle` and `submitAckBundle` (not inbound/slash handlers).

## Invariant functions

### State properties (read `service` / handler ghosts)


| Function                                                 | Property IDs                            | What it checks                                                                                                      |
| -------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `invariant_ethSolvency`                                  | INV-ETH-1                               | `balance >= Σ lockedStake + Σ bonds + Σ pendingWithdrawals` (all recorded mapping keys)                             |
| `invariant_ethBalanceConservation`                       | INV-ETH-2                               | `balance + ghostEthOut == ghostEthIn + initialServiceBalance`                                                       |
| `invariant_channelCountMonotonic`                     | INV-CNT-1                               | `channelCount` never decreases                                                                                   |
| `invariant_channelMapsAndCounters`                    | INV-MAP, INV-CMT, INV-CNT               | Commitment/reverse-index/pending flags vs ghosts; `channelCount` vs slot + `ghostCompletedChannelCount`       |
| `invariant_connectorAndEndpointCounts`                   | INV-MAP, INV-CNT-2/3                    | Connector/endpoint counts vs ghosts; `endpointExists` / `connectorExists` (slot 20) / `hasConnector` / stake ghosts |
| `invariant_configBoundsAndLimits`                        | INV-CFG                                 | On-chain `connectorQueueQuotaPct < 100`; no successful over-cap create (handler ghosts)                             |
| `invariant_queueAndOrderingBounds`                       | INV-CONN, INV-CON, INV-PEER, INV-CONN-4 | Message ordering, queue depth, peer roster, inflight/quota, enqueue violation ghosts                                |
| `invariant_killSwitch_ownerReEnableAllowedWhenDisabled`  | INV-KILL-1                              | `ghostReEnableBlockedByDisabled` must stay false                                                                    |
| `invariant_killSwitch_collectPendingAllowedWhenDisabled` | INV-KILL-1                              | `ghostCollectPendingBlockedByDisabled` must stay false                                                              |


### Direct `service` probes (outside handler; `expectRevert`)

When kill switch is **off**, one mutating call per test (early return if enabled). Expect `ClprDisabled`:

`invariant_aclKillSwitchWhenDisabled`, `_registerChannel`, `_registerEndpoint`, `_sendMessage`, `_submitBundle`, `_updateEconomic`, `_closeChannel`, `_completeChannel`, `_topUpBond`, `_removeEndpoint`, `_topUpConnectorStake`, `_removeConnector`, `_completeConnector`, `_updateLedger`.

When kill switch is **on** or regardless of switch — wrong caller probes using `aclProbe` (or `address(this)` where owner is required):


| Function                                              | Expected revert                                          |
| ----------------------------------------------------- | -------------------------------------------------------- |
| `invariant_aclSetClprEnabledRequiresOwner`            | any                                                      |
| `invariant_aclUpdateEconomicRequiresOwner`            | any                                                      |
| `invariant_aclUpdateLedgerRequiresOwner`              | any                                                      |
| `invariant_aclCloseChannelRequiresOwner`           | any                                                      |
| `invariant_aclRemoveConnectorRequiresAdmin`           | any                                                      |
| `invariant_aclSubmitBundleRequiresRegisteredEndpoint` | `ClprEndpointNotRegistered` (only if kill switch **on**) |


These probes do not use `reconcileEth`; they use `value: 0` and expect revert, so they do not affect INV-ETH-2.

## Property details

### INV-ETH

- **INV-ETH-1:** Global liability sum via `ClprInvariantEthLib` + mapping recording from `setUp`.
- **INV-ETH-2:** Tracks balance changes only on handler paths wrapped in `reconcileEth`. Bare ETH via `ClprService.receive()` or unexpected successful invariant probes are out of scope (not exercised today).

`ClprInvariantEthLib` uses hardcoded struct member offsets for `Connector.lockedStake` and `RegisteredEndpoint.bond`; top-level slots are guarded by `ClprStorageLayoutGuardTest`, struct members are not.

### INV-CONN / INV-CON (in `invariant_queueAndOrderingBounds`)


| ID         | Check                                                                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| INV-CONN-1 | On **ACTIVE** channels, if `lastEnqueueLimitsRevision == queueLimitsRevision`: outbound depth `<= maxQueueDepth`                                   |
| INV-CONN-2 | Completed channels: `acked < next`; monotonic `ackedMessageId`, `nextMessageId` (high-water in test contract)                                      |
| INV-CONN-3 | `nextMessageId >= 1`; monotonic `receivedMessageId`                                                                                                   |
| INV-CON-1  | Removed connector (not live, not `hasConnector`): inflight == 0                                                                                       |
| INV-CON-2  | Live connector on ACTIVE channel: quota cap when limits revision stable (same waiver as INV-CONN-1)                                                      |
| INV-CON-3  | Inflight/quota ghosts match on-chain maps                                                                                                             |


**Waivers:** After `updateLedger` / `updateEconomic` tightens limits, INV-CONN-1 and INV-CON-2 are skipped until the next **successful** `sendMessage` on that channel (`queueLimitsRevision` / `lastEnqueueLimitsRevision`).

At enqueue: `ghostQueueDepthViolatedOnEnqueue` / `ghostQuotaViolatedOnEnqueue` must stay false.

### INV-PEER

Peer roster on completed channels matches deduplicated **64-byte** signing keys from `MockClprVerifier` seed endpoints (`_peerEndpointCount`, signer array, `registered` flag per signer). Not a property of arbitrary production verifiers.

### INV-KILL / INV-ACL

- **Kill switch off:** mutating entrypoints revert `ClprDisabled` (handler + invariant spot probes). Exceptions: `setClprEnabled` (owner), `collectPending` (not gated by `whenEnabled` in `AdminLogic`), reads.
- **INV-KILL-1 positives:** handler `probeReEnableWhenDisabled` / `collectPendingWhileDisabled` set `ghost*BlockedByDisabled` if they ever catch `ClprDisabled`. Success ghosts (`ghostReEnableWhenDisabledOk`, `ghostCollectPendingWhenDisabledOk`) record exploration but are **not** asserted by invariants.

### INV-CFG

- On-chain quota percent always `< 100`.
- Cap ghosts: no **successful** handler complete/register observed above `maxChannels` / `maxConnectors` when caps are non-zero. Does not continuously re-check caps on every state.

## Storage layout

Internal reads use `[ClprServiceStorageSlots.sol](../helpers/ClprServiceStorageSlots.sol)`. After changing `ClprService` storage, regenerate `storage-layout.json` and run:

```bash
forge test --match-contract ClprStorageLayoutGuardTest
```

