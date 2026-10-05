# Quirks & Footguns

Non-obvious design choices and traps that have already bitten someone. Read
when something looks weird and you're tempted to "clean it up."

## DELEGATECALL router with shared layout

- `ClprService` has no logic of its own. All four `logic/*` contracts inherit
  `ClprServiceStorage` in identical position so storage slots line up.
- Logic contracts' own `Ownable._owner` slot is **dead** — they're only ever
  DELEGATECALL'd; the only state that matters is the router's. Don't try to
  set or use logic-contract owners.
- The system is **not upgradeable**. Logic addresses are `immutable`.
- Reason: EIP-170 24KB code size limit. Not a proxy pattern.

## No `view` annotations on read functions

Solidity 0.8 forbids `delegatecall` inside `view`. So `getChannel`,
`getMessage`, etc. are non-view at the ABI level. Off-chain readers via
`eth_call` pay nothing. Don't "fix" this. `deriveConnectorId` is the
exception (uses STATICCALL via `_staticDelegate`) because it's truly `pure`.

## OZ `ReentrancyGuard` namespaced storage

`ReentrancyGuard` (OZ v5) uses ERC-7201 namespaced storage, so it does NOT
occupy a sequential slot. That's why the storage layout in
`ClprServiceStorage` starts cleanly after `Ownable._owner` (slot 0) without
a gap. Don't add explicit gap variables.

## File-scope events

`ChannelStatusChanged` and `MessageQueued` are declared **outside** any
contract in `ClprTypes.sol`. This makes them shareable between the router
and `BundleLib` without duplicate ABI selectors. Don't move them into a
contract.

## Two distinct hashes for connector keying

- **Connector record** key: `keccak256(channelId ‖ connectorId)`
- **Quota counter** inner key: `keccak256(connectorId)` (outer mapping
  already keys by `channelId`)
- **In-flight counter** key: same as connector record key

These are **not interchangeable**. `_connectorKey` and "connectorQueueKey"
look similar in code; mixing them silently corrupts accounting.

## DATA messages aren't deleted on ack

REPLY and CONTROL messages are deleted from the queue when the peer acks
them. DATA messages stay until the matching REPLY arrives — because the
REPLY processing needs the original DATA's `connectorId` to do source-side
accounting (in-flight counter, quota counter, source-side slashing).

`_deleteAckedNonDataMessages` is named accurately. Don't generalize it.

**Redaction interaction (DRIFT-REVIEW C-4 + C?-12 — fixed).** `redactMessage`
zeros the DATA payload and decrements both `_connectorQueueCounts` *and*
`_connectorInflightCount`. The original `connectorId` is preserved in
`MessageValue.connectorIdForReply` at enqueue time and survives payload
redaction. When the eventual REPLY arrives, `_processReplyMessageDecoded`
uses `connectorIdForReply` to perform source-side slashing even though the
payload is empty. The in-flight counter is NOT decremented a second time by
REPLY processing (only `redactMessage` decrements it for the redacted case).
After redaction, `removeConnector` succeeds immediately because inflight = 0.

## In-memory `Channel` mutation

`_finishBundle` and helpers mutate a memory copy of the `Channel` and
write it back at the end (`_channels[id] = channel`). This avoids
intermediate SSTOREs. Don't mix in-place storage writes with this pattern
inside the same call — the in-place writes will be clobbered by the
end-of-call write-back.

## Empty-bundle revert

A bundle is `EmptyBundle` if it has no payloads AND no ack progress AND no
trust-anchor change. Tests that drive pure state transitions with zero
messages must set a non-empty new anchor. Discovered as a footgun in tests;
see `bundle-flow.md` and `testing.md`.

## ECDSA recovery against pubkey-derived address

`ConnectorLib._ecrecoverCheck` recovers via `ecrecover` and compares against
`address(uint160(uint256(keccak256(pubKey))))` — the address derived from
the **64-byte uncompressed pubkey** (X‖Y, no 0x04 prefix). This is *not*
the more common "store address, verify signature against address" pattern.
Reason: the protocol carries the full pubkey through the commitment for
cross-platform parity (the same pubkey bytes must hash identically on every
ledger).

## EVM pubkey encoding is 64-byte uncompressed (S-7/D-6)

The spec (§1.2) allows 33-byte compressed *or* 64-byte uncompressed secp256k1
public keys. The EVM implementation currently accepts only **64-byte
uncompressed** (X‖Y, no 0x04 prefix).

Rationale: On-chain secp256k1 point decompression has no native EVM opcode.
Implementing it in Solidity carries significant gas cost and code-size impact.
The spec acknowledges this is ledger-specific. Per Richard's design decision
(DRIFT-REVIEW S-7): "It is ledger specific for now, and we can pick either."
For v1, EVM picks uncompressed.

If compressed-key support is added in future versions it should be implemented
in the verifier layer (off-chain decompress, supply uncompressed on-chain) or
via a precompile if one becomes available. Don't try to decompress on-chain
in `ChannelLogic` or `EndpointLib`.

## Endpoint deregister is unconditional (I-4)

`EndpointLib.deregister` (called from `AdminLogic.removeEndpoint`) is
unconditional once the caller is registered: no in-flight-message gate exists.

The spec (§6.5) says endpoints "MUST NOT deregister with in-flight sync
submissions." On EVM this does not apply:

> "An endpoint that submits a bundle then deregisters will either pay for both
> transactions or neither will land. If the bundle transaction has not been
> included, it is simply not in the block. If it has been included, the
> endpoint already paid. There is no escape-from-slashing scenario unique to
> EVM because the mempool/nonce ordering prevents submitting then instantly
> vanishing." — Richard (DRIFT-REVIEW I-4)

The spec's guidance was written for ledgers where transaction ordering is not
guaranteed by nonces. On EVM the economic model is enforced by transaction
inclusion: the slashing happens in the same transaction as the bundle
submission, so deregistering after the fact does not help the endpoint.

## Connector signature binds to `address(this)`

The connector reveal signs `keccak256(connectorId ‖ address(this))`. Under
DELEGATECALL, `address(this)` is the **router** address. The signature
therefore binds to a specific router deployment. This is the EVM rendering
of the spec's "service_address" binding (spec §6.3).

## Charge verification by router-balance delta

`ConnectorLib.charge` calls `IClprConnector.payForExecution(amount)` and
then asserts `address(this).balance` grew by exactly `amount`. Because
`ConnectorLib` is an internal library, `address(this)` resolves to the
router. A connector that "succeeds" without transferring (or transfers the
wrong amount) is detected here and slashed. **Don't replace this with a
return-value check** — the ABI return value is unreliable for measuring
actual ETH flow.

## Pull-payment fallback (`_pendingWithdrawals`)

Three-step delivery for any outbound ETH:
1. Push to recipient.
2. On revert, push to `_fallbackRecipient` (the owner).
3. On revert again, credit `_pendingWithdrawals[recipient]`; recipient pulls
   later via `collectPending()`.

This exists because connector charges and slash proceeds are sent to bundle
submitters / connector admins, who may be contracts that revert in
`receive()`. The B8 regression in `ConnectorLib.t.sol` pins this.

## Auto-ban on stake exhaustion

If `lockedStake` drops to zero or `slashCount >= slashBanThreshold`, the
`Connector` entry is **deleted** (not just marked banned). It can be
re-registered later, but every reference to the old key becomes a
`hasConnector == false`. Pinned by the B9 regression.

## Endpoint key-length error reuses signature error

`registerEndpoint(signingKey)` requires `length == 64`; otherwise reverts
with `ClprInvalidSignature`. Selector reused for a structural problem.
Pinned in `test/logic/AdminLogic.t.sol:148` (`EndpointManagerTest.test_register_revert_invalidKeyLength`).
If you change the error, update that test.

## Bundle margin and submitter payout (DRIFT-REVIEW C-5/D-1 — resolved)

When a submitter submits a bundle they front the gas for the entire
transaction. The protocol reimburses them for every DATA message processed,
with the connector paying the full execution cost plus a margin:

```
totalCharge = gasUsed * tx.gasprice * (100 + connector.marginPercent) / 100
```

All of `totalCharge` is transferred to the bundle submitter via
`ConnectorLib.charge` — no split, no owner cut, no protocol treasury. The
margin covers the submitter's overhead (routing, verification, hash checks)
and provides a small profit incentive. The margin is a per-connector
configuration value (`Connector.marginPercent`), not a global setting.

Example: if the application call uses 300,000 gas at a gas price of 1 gwei
with `marginPercent = 10`, the connector pays
`300,000 * 1e9 * 110 / 100 = 330,000 gwei` and the submitter receives all
of it.

**Pre-call bailout:** before invoking the application, the service computes
a conservative ceiling `maxPossibleCharge = maxGasPerMessage * tx.gasprice *
(100 + margin) / 100`. If the connector contract's ETH balance is below this
ceiling, the connector is considered CONNECTOR_UNDERFUNDED, is slashed, and
no application call is made. This prevents the service from advancing an
application call only to find the connector can't pay afterward.

Slash proceeds also go to the submitter (with the pull-payment fallback).
The owner is the fallback recipient for all ETH transfers — meaning the
protocol owner ends up holding ETH from any push-failures. Don't accumulate
large balances on the owner address; they should be swept periodically.

**Interaction with redaction (C-4):** `redactMessage` decrements both the
queue counter (`_connectorQueueCounts`) and the in-flight counter
(`_connectorInflightCount`) for the redacted DATA message. Because the
in-flight counter reaches zero, `removeConnector` succeeds immediately after
redaction and is not bricked by the outstanding slot.

## sendMessage stamps msg.sender — application-layer "from" claims are untrusted

`sendMessage` does not accept a `sender` parameter. The service stamps the on-chain caller address (`msg.sender`) as the sender in the queued DATA message payload using `abi.encodePacked(msg.sender)`. This is the CLPR spec §4.3 step 6 behavior: "*sender* (stamped from transaction caller)." Applications on the destination side that use the `sender` field for routing or authentication can rely on it as the *on-chain identity of the source-side caller*. However, they MUST NOT trust any in-band "from" claim embedded inside `messageData` itself without independent verification — `messageData` is fully application-controlled and can be forged by any caller.

## Bilateral connector requirement

The spec requires a connector to exist on **both** ledgers under the same
`channel_id` and `connector_id`. The EVM side does not enforce this
(it can't know peer-side state). It manifests as: outbound DATA gets a
peer-side `CONNECTOR_NOT_FOUND` reply, which source-side slashes the local
connector. New code that forks connector registration logic must keep the
ID derivation byte-equivalent across ledgers (see `lifecycle.md`).

## Hedera trace-size cap fails as `INSUFFICIENT_GAS`

Hiero consensus nodes cap the serialized contract trace (every call frame's
input and output, precompile calls included, plus storage reads and writes)
at `contracts.maxSerializedTraceDataBytes` = 262,144 B per transaction. Over
the cap, the call is executed, then failed with `INSUFFICIENT_GAS` and rolled
back, with the same gas used at every gas limit. `eth_estimateGas` and anvil
forks don't apply the cap, so they report success.

Because `ClprService` delegates to its logic modules and they call the
verifier, a verifier input is recorded at least three times: a single input
near ~87 KB, or less with per-item precompile calls, fails on Hedera
even though it passes every EVM tool. Don't "fix" this by raising the gas
limit. Measure with `npm run trace:size` and see
[`hedera-trace-cap.md`](hedera-trace-cap.md).
