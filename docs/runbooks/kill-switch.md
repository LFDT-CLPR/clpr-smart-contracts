# Runbook — CLPR Kill Switch (`setClprEnabled(false)`)

**Audience:** on-call engineer responding to a live incident.
**Goal:** halt all state-changing activity on `ClprService` fast, safely, and reversibly — without waiting for the protocol designers.

> Read the [Triggers](#triggers) section before flipping the switch. Disabling
> the service stops **all** endpoints and connectors, not just the misbehaving
> one — it is a blunt, protocol-wide instrument. Use it when the blast radius of
> *not* acting is larger than the blast radius of halting.

---

## TL;DR — the flip

If you have already decided (see [Triggers](#triggers)) that halting is the right call:

**What you need first** (the `<…>` values used throughout this runbook):

- `<CLPR_SERVICE>` — the `ClprService` address. Find it in the "Owned contract"
  row of [`docs/safe-runbook.md`](../safe-runbook.md) section 1, or in the deploy's
  address output (`CLPR_SERVICE` key).
- `<RPC_URL>` — an RPC endpoint for the target network.
- Access to the Safe's signers to reach the signing threshold.

```bash
# 1. Encode the call (this is the calldata the Safe tx must carry)
cast calldata "setClprEnabled(bool)" false
# → 0x52c3aa160000000000000000000000000000000000000000000000000000000000000000
#   (this value is fixed; target contract = ClprService)

# 2. Sign + execute as a Safe transaction targeting ClprService.
#    Mechanics (hashing, collecting threshold signatures, executing) live in
#    docs/safe-runbook.md section 3 "Routine owner-only operations".

# 3. VERIFY the flag actually changed (see "Verify it took effect" below).
#    A Safe tx with status 1 does NOT prove the halt landed.
cast storage <CLPR_SERVICE> 2 --rpc-url <RPC_URL> | cut -c25-26
# → "00" = halted
```

`setClprEnabled` is `onlyOwner`, and the owner is the Safe multisig, so flipping
the switch still requires the Safe's signing threshold. **You cannot do this
alone** — page co-signers early (see [Paging tree](#paging-tree)).

---

## What the kill switch does

- `setClprEnabled(false)` sets `_clprEnabled = false` and emits
  `ClprEnabledChanged(false)`.
- While disabled, **every protocol operation carrying the `whenEnabled` modifier
  reverts with `ClprDisabled()`**. That is all 16 of:

  | Area | Gated operations |
  |------|------------------|
  | Channels | `registerChannel`, `completeChannel`, `closeChannel` |
  | Connectors | `registerConnector`, `completeConnector`, `removeConnector`, `topUpConnectorStake` |
  | Endpoints | `registerEndpoint`, `addEndpoint`, `removeEndpoint`, `updateEndpointManifest` |
  | Messaging | `sendMessage` |
  | Bundles | `submitBundle` |
  | Configuration | `updateLedgerConfiguration`, `updateEconomicConfiguration` |

- **Read-only views are unaffected** — off-chain monitoring and investigation
  continue to work.
- No funds move and no state is destroyed. Bonds and stakes stay locked in the
  contract exactly as they were.

### Three things the switch deliberately does *not* block

These mutating functions keep working while halted. The first is what makes the
switch safe to use; the other two are limits worth knowing before you flip.

- `setClprEnabled` itself is not gated, so the action is fully **reversible**
  with `setClprEnabled(true)`. Halting can never lock you out of un-halting.
- `collectPending()` and `collectPendingTo()` are not gated. Anyone owed the fee asset (ETH, or
  the service's fee token) through the pull-payment path can still withdraw it during a halt — a halt does not trap refunds. If
  your incident calls for freezing withdrawals too, **the kill switch is not
  the tool**; escalate, because no owner call achieves that.
- `transferOwnership` / `renounceOwnership` are plain `Ownable` functions and
  are not gated. `renounceOwnership` would leave the switch permanently stuck
  in its current state — never propose it during an incident.

---

## Triggers

The switch is worth flipping only when it actually reduces harm. For each
scenario below: confirm the signal, decide whether halting *helps*, then act.

| Trigger | Signals to look for | Does halting help? | Decision |
|---------|---------------------|--------------------|----------|
| **Verifier compromise** | Bundles verifying that should not (forged proofs accepted), a disclosed vulnerability in the active verifier (Hiero / QBFT / Sei), or a trust-anchor key you no longer trust. | **Yes.** `submitBundle` runs `whenEnabled`; disabling stops all bundle processing, cutting off the exploit path immediately. | **Flip.** Then escalate to security — this is the highest-severity trigger. |
| **Peer-chain halt** | The peer chain has stopped finalizing / is reorging / is unreachable, so bundle proofs are stale or unverifiable. Watch for a spike in failed `submitBundle` calls or stuck cross-chain state. | **Usually yes**, if endpoints/connectors would otherwise act on stale peer-chain state or accrue incorrect slashes while the peer chain is down. | **Flip if** the halt is causing incorrect on-chain effects. If the system merely stalls harmlessly, halting may add little — prefer monitoring. |
| **Fee token halted** | The service's fee token (`getFeeToken()` is non-zero) pauses transfers, or its blocklist or transfer policy blocks the `ClprService` address. Every `payForExecution` then fails, so each inbound DATA message slashes a connector that can pay (`docs/quirks.md`). | **Yes.** `submitBundle` stops, so no connector is slashed for a transfer the token refused. | **Flip** until the token resumes transfers or unblocks the service. A block on a single connector is not a reason to halt: its admin removes it with `removeConnector`. |
| **Anomalous slash rate** | Connector `slashCount` climbing far faster than baseline; connectors approaching `slashBanThreshold` en masse; slashing that does not correspond to real misbehavior (possible logic bug or coordinated abuse). | **Yes**, to stop irreversible economic damage to honest connectors while you investigate. | **Flip** if slashing appears incorrect or runaway. Legitimate slashing of a single bad actor is **not** a reason to halt the whole protocol. |

If the situation does not clearly match a trigger above but you believe halting
is warranted, **page the escalation contacts and halt anyway** — a reversible
halt during an ambiguous incident is cheaper than data you cannot claw back. Err
toward flipping.

---

## Invocation via Safe (cast / CLI)

The switch is an `onlyOwner` call on `ClprService`, executed as a Safe
transaction whose **target is `ClprService`** and whose **calldata** is the
encoded `setClprEnabled(bool)` call.

```bash
# Encode calldata for the halt
cast calldata "setClprEnabled(bool)" false
```

Submit that calldata as a Safe transaction to the `ClprService` address, collect
the Safe's `<threshold>` signatures, and execute. The full signing procedure —
computing the hash, gathering signatures, executing — is in
[`docs/safe-runbook.md`](../safe-runbook.md) section 3. `ClprService`'s `onlyOwner`
checks the Safe before the call is delegated to `AdminLogic`, which then runs
against the router's storage.

Two mechanical traps in that procedure are worth knowing before you start. Both
are covered in section 3:

- **Signatures must be concatenated in ascending signer-address order.** The
  correct number of individually-valid signatures in the wrong order fails with
  `GS026`. Too few fails with `GS020`.
- **Keep `safeTxGas` and `gasPrice` at `0`.** With a non-zero `safeTxGas`, a
  reverting inner call still produces a receipt with `status: 1 (success)`.

### Verify it took effect

**A successful Safe transaction is not proof that the halt landed.** The Safe can
authorize and execute a transaction whose inner call reverted: the receipt shows
`status: 1 (success)` and the Safe emits `ExecutionFailure` rather than
`ExecutionSuccess`. Always verify the flag itself.

```bash
# 1. AUTHORITATIVE CHECK — read _clprEnabled directly out of storage.
#    It is internal (no public getter), but it lives at byte offset 20 of
#    slot 2, packed immediately above the _bundleDecodeHelper address.
cast storage <CLPR_SERVICE> 2 --rpc-url <RPC_URL>
# halted:  0x000000000000000000000000<20-byte _bundleDecodeHelper address>
# enabled: 0x000000000000000000000001<20-byte _bundleDecodeHelper address>
#
#    _bundleDecodeHelper occupies the low 20 bytes (the trailing 40 hex chars),
#    so the flag byte is chars 25-26 of the 0x-prefixed word:
cast storage <CLPR_SERVICE> 2 --rpc-url <RPC_URL> | cut -c25-26
# → "00" while halted, "01" while enabled
#
#    Do NOT eyeball the leading zeros — the top bytes of the word read "00" in
#    both states.
```

> The slot number comes from `storage-layout.json` (`_clprEnabled`, slot 2,
> offset 20). `ClprService` is not upgradeable, so it cannot shift under a live
> deployment — but re-confirm it against `storage-layout.json` for the exact
> commit you deployed.

```bash
# 2. Confirm both events in the execution tx. `cast receipt` does NOT decode
#    logs, so match on topic0 by hand.
cast receipt <TX_HASH> --rpc-url <RPC_URL>
```

| Topic0 | Event | What you need to see |
|--------|-------|----------------------|
| `0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e` | `ExecutionSuccess` (from the Safe) | Present. If you instead see `ExecutionFailure` (`0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23`), **the halt did not happen.** |
| `0x229dad167f612424b3006f4bba5e443fe4d604c7c884fe483bfadac82339b10d` | `ClprEnabledChanged` (from `ClprService`) | Present, with `data` = `0x00…00` for the halt (`0x00…01` for a re-enable). |

```bash
# 3. Behavioural sanity check — confirm a gated op is now blocked.
#    registerEndpoint() takes no args, so it is the simplest probe. `cast call`
#    SIMULATES via eth_call and never broadcasts — use it, never `cast send`,
#    because if the halt did NOT take effect this is a real mutating (and
#    payable) operation.
cast call <CLPR_SERVICE> "registerEndpoint()" --rpc-url <RPC_URL>
# → halted:  reverts with ClprDisabled()  (custom error 0xb098fbc6)
# → enabled: returns 0x (the call would have succeeded)
```

Record the execution tx hash in the [post-mortem](#post-mortem-template) and in
the Safe change log (`docs/safe-runbook.md` section 5).

---

## Re-enabling the service

Re-enable with the mirror-image call once the incident is resolved:

```bash
cast calldata "setClprEnabled(bool)" true
# → 0x52c3aa160000000000000000000000000000000000000000000000000000000000000001
```

**Before re-enabling, confirm:**

- The root cause is understood and mitigated (patched verifier, recovered peer
  chain, fixed/contained slashing) — not merely quiet.
- If a verifier or trust anchor was involved, it has been rotated / updated via
  the appropriate owner call.
- The re-enable decision has the same sign-off as the halt (threshold signers +
  escalation owner agree).

Then execute as a Safe transaction (same mechanics as above) — note this
consumes a fresh Safe nonce, so the halt signatures cannot be reused — and run
the same three verification checks, inverted:

```bash
cast storage <CLPR_SERVICE> 2 --rpc-url <RPC_URL> | cut -c25-26
# → "01" = enabled

cast call <CLPR_SERVICE> "registerEndpoint()" --rpc-url <RPC_URL>
# → returns 0x, i.e. a previously-halted operation would now succeed
```

Plus `ClprEnabledChanged` with `data` = `0x00…01` and `ExecutionSuccess` in the
execution receipt.

---

## Paging tree

> **This is an open-source project — the concrete identities, schedules, and
> channels below are defined by the operating organization.** Fill in the
> `<…>` placeholders for your deployment. The "on-call engineer" role is the
> intended reader of this runbook; the roles below are the escalation chain.

| Level | Role | When to page | Contact |
|-------|------|-------------|---------|
| 0 | On-call engineer (you) | You are already here. | — |
| 1 | Safe co-signers | Immediately — you need the threshold to sign anything. | `<Safe signers — see docs/safe-runbook.md section 1>` |
| 2 | Protocol / Operations lead | On any confirmed trigger, in parallel with signing. | `<name / channel / schedule>` |
| 3 | Security lead / team | Verifier compromise, key compromise, or anything you suspect is an attack. | `<name / channel / schedule>` |

Page **up** the moment you are unsure. Halting first and explaining later is the
correct order for a reversible switch.

---

## Post-mortem template

Copy this into an incident doc after the situation is stable.

```markdown
# Kill-switch incident — <YYYY-MM-DD>

## Summary
One-paragraph plain-language description of what happened.

## Trigger
- Which trigger fired (verifier compromise / peer-chain halt / anomalous slash
  rate / other): 
- Signal(s) that alerted us: 
- Time first observed (UTC): 

## Timeline (UTC)
| Time | Event |
|------|-------|
|      | First signal observed |
|      | Decision to halt |
|      | `setClprEnabled(false)` executed — tx `<0x…>` |
|      | Root cause identified |
|      | `setClprEnabled(true)` executed — tx `<0x…>` |

## Impact
- Duration of halt: 
- Operations blocked / affected parties: 
- Funds/stake at risk (and whether any was lost — should be none): 

## Root cause
What actually went wrong.

## Resolution
What was changed/fixed before re-enabling.

## Follow-ups
- [ ] Action item — owner — due
- [ ] Update this runbook if the response revealed a gap
```

---

## See also

- [`docs/safe-runbook.md`](../safe-runbook.md) — Safe multisig operation: signer
  rotation, threshold changes, transaction signing mechanics, emergency
  procedures.
- `src/logic/AdminLogic.sol` — `setClprEnabled` implementation.
- `src/logic/base/LogicModuleBase.sol` — the `whenEnabled` modifier. To
  regenerate the gated-operations list above for a given commit:
  `grep -rn "whenEnabled" src/logic/`
- `storage-layout.json` — authoritative slot/offset for `_clprEnabled`, used by
  the verification step.
