# Quirks & Footguns

Non-obvious design choices and traps that have already bitten someone. Read
when something looks weird and you're tempted to "clean it up."

## DELEGATECALL router with shared layout

- `ClprService` has no protocol logic of its own. All five `logic/*` contracts
  (`ChannelLogic`, `MessagingLogic`, `BundleLogic`, `ConnectorLogic`,
  `AdminLogic`) inherit `ClprServiceStorage` through `logic/base/LogicModuleBase.sol`,
  so every contract sees identical storage slots.
- Logic contracts do **not** inherit `Ownable` — only the router does. Owner
  checks are the router's `onlyOwner` modifier, evaluated before it delegates.
  Code running inside a module that needs the owner (`AdminLogic.removeEndpoint`,
  the `fallbackRecipient` in `BundleLogic.submitBundle`) calls
  `ClprServiceStorage._getOwner()`, which `sload`s a hard-coded slot and is
  meaningful only in the router's storage context.
- The system is **not upgradeable**. The five logic addresses are `immutable` on
  the router. `_bundleDecodeHelper` is a storage variable instead (slot 2),
  written once in the constructor with no setter: `BundleLogic` reads it under
  DELEGATECALL, and module code cannot see the router's immutables.
- Reason: contract-size limits. EIP-170's 24KB runtime cap drives the module
  split, and EIP-3860's 49152-byte initcode cap is why the modules and
  `BundleDecodeHelper` are deployed separately and passed into the nine-argument
  constructor instead of being created by it (see the `foundry.toml` comment on
  `evm_version`). Not a proxy pattern.

## No `view` annotations on read functions

Solidity 0.8 forbids `delegatecall` inside `view`. So the router's
`getChannel`, `getMessage`, `getLedgerConfiguration`, etc. are non-view at the
ABI level, even though the module functions they dispatch to are `view`.
Off-chain readers via `eth_call` pay nothing. Don't "fix" this.
`deriveConnectorId` is the exception: it keeps `view` on the router and is
dispatched with STATICCALL via `_staticDelegate`, because
`ConnectorLogic.deriveConnectorId` is `pure` and reads no router storage.

## Storage layout: slot 0 is protocol state, `_owner` is slot 38

`ClprServiceStorage` inherits OZ v5 `ReentrancyGuardTransient`, which keeps its
flag in EIP-1153 **transient** storage at a hash-derived slot, so it claims no
sequential slot. Protocol state starts at slot 0 (`_authorizedService`) with no
gap. Don't add explicit gap variables.

`Ownable._owner` is **not** slot 0. `ClprService is ClprServiceStorage, Ownable`,
so `_owner` lands immediately after `ClprServiceStorage`'s last variable
(`economicConfig`), at sequential slot **38**. `ClprServiceStorage._getOwner()`
hard-codes that number, and `ClprStorageLayoutGuardTest`
(`test/invariants/ClprStorageLayoutGuard.t.sol`) pins it against
`storage-layout.json`. The number moves whenever state is appended above it.

Slots 13 and 14 (`_deprecatedPeerEndpointCount`, `_deprecatedPeerEndpointAccounts`)
are unused but must stay: they hold `_channels` at slot 15, which
`ClprEvmBundleVerifier.CHANNELS_BASE_SLOT` hard-codes, as it does the endpoint
manifest commitment at slot 18 (`ENDPOINT_MANIFEST_COMMITMENT_SLOT`). A peer
chain's verifier proves those slots of this contract, so removing the
placeholders breaks every deployed EVM verifier that points at it.

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

These are **not interchangeable**. `ConnectorLib._connectorKey` produces the
record key; the in-flight key is the same hash but inlined, and the quota key
has no named helper. Both are inlined in `MessagingLogic` (`sendMessage` /
`_enqueueDataMessage`) and `BundleLib._processReplyMessageDecoded`.
The trap: in `sendMessage` the local variable named `connectorKey` holds the
**quota** key, not `ConnectorLib._connectorKey`. Mixing them silently corrupts
accounting.

## DATA messages aren't deleted on ack

REPLY and CONTROL messages are deleted from the queue when the peer acks
them. DATA messages stay until the matching REPLY arrives, because REPLY
processing reads the original slot: `connectorIdForReply` for source-side
accounting (in-flight counter, quota counter, source-side slashing) and the
payload's `sender` for the `onClprResponse` callback. The REPLY handler then
deletes the slot.

`_deleteAckedNonDataMessages` is named accurately. Don't generalize it.

## In-memory `Channel` mutation

`BundleLib.processBundle` loads `_channels[id]` into a memory copy in
`_validateAndPrepare`; `_validateAndPrepare` and `_applyBundle` mutate that
copy, and Step 12 writes it back once (`_channels[ctx.channelId] = channel`).
This avoids intermediate SSTOREs. Don't mix in-place writes to `_channels[id]`
with this pattern inside the same call — they are clobbered by the
end-of-call write-back.

Two writes deliberately happen before Step 12: the peer endpoint manifest
(Step 1b writes `_peerEndpointManifests` directly), and the response-ordering
early exit, where `_validateAndPrepare` persists the channel itself and returns
`earlyReturn = true`.

The same pattern means storage holds the **pre-bundle** channel cursors while
`onClprMessage` / `onClprResponse` run. `submitBundle`, `sendMessage`,
`removeConnector` and `collectPending` are `nonReentrant` (the other mutating
entry points are not), and the non-view getters are not guarded, so a read-only
reentrant call observes stale channel state (see the reentrancy note in
`_processReplyMessageDecoded`).

## No-progress revert

A bundle reverts with **`NoProgress`** when none of these hold: new messages, a
new trust anchor that differs from the stored one (a verifier re-reporting the
current anchor is not progress, #529), an endpoint-manifest version advance, ack progress,
or a channel state-machine transition (`BundleLib._checkBundleProgress`, called
right after `verifyBundle`). `BundleLib.EmptyBundle` is declared but never
thrown — don't expect it in a test.

Tests that drive pure state transitions with zero messages must supply one of
the five; a new trust anchor is the usual choice. See `bundle-flow.md` and
`testing.md`.

## ECDSA recovery against pubkey-derived address

`ECDSA._ecrecoverCheck` (`src/libraries/crypto/ECDSA.sol`) recovers via
`ecrecover` over the EIP-191 `"\x19Ethereum Signed Message:\n32"`-prefixed hash
and compares against `address(uint160(uint256(keccak256(pubKey))))` — the
address derived from the **64-byte uncompressed pubkey** (X‖Y, no 0x04 prefix).
Both the channel reveal (`ECDSA._verifySignature`, from
`ChannelLogic.completeChannel`) and the connector reveal
(`ConnectorLib._verifyConnectorSig`) use it. This is *not* the more common
"store address, verify signature against address" pattern. Reason: the
protocol carries the full pubkey through the commitment for cross-platform
parity (the same pubkey bytes must hash identically on every ledger).

## EVM pubkey encoding is 64-byte uncompressed (S-7/D-6)

The spec allows 33-byte compressed *or* 64-byte uncompressed secp256k1 public
keys. The EVM implementation accepts only **64-byte uncompressed** (X‖Y, no
0x04 prefix).

Rationale: On-chain secp256k1 point decompression has no native EVM opcode.
Implementing it in Solidity carries significant gas cost and code-size impact.
The spec acknowledges this is ledger-specific. Per Richard's design decision
(DRIFT-REVIEW S-7): "It is ledger specific for now, and we can pick either."
For v1, EVM picks uncompressed.

Compressed-key support belongs in the verifier layer (off-chain decompress,
supply uncompressed on-chain) or behind a precompile. Don't try to decompress
on-chain in `ChannelLogic` or `ConnectorLib`.

## Channel pubkey-length error reuses the signature error

`ChannelLogic.completeChannel` requires `pubKey.length == 64`; otherwise it
reverts with `ClprInvalidSignature` — a signature selector reused for a
structural problem. `ECDSA._verifySignature` repeats the check, and a signature
that is not 65 bytes reverts with the same error. Pinned by
`ClprService_Channel.test_completeChannel_revert_invalidSignature_pubKeyLength`
(`test/logic/ChannelLogic.t.sol`) and
`EcdsaTest.test_verifySignature_wrongPubKeyLength_reverts`
(`test/libraries/crypto/Ecdsa.t.sol`). If you change the error, update those
tests.

## Endpoint registration is two-step, and validated

`registerEndpoint` takes an `Endpoint` struct (`{ipAddress, port,
tlsCertificate, accountId}`) plus a bond as `msg.value` (`>= minEndpointBond`,
else `ClprInsufficientBond`). It creates a **PENDING** entry only — the endpoint
is not in the manifest peers see until the owner admits it with `addEndpoint`
or `updateEndpointManifest`, which bumps the manifest version
(`ManifestLib.registerEndpoint`, `ManifestLib.addEndpoint`). `Endpoint` carries
no signing key.

`ManifestLib._validateEndpoint` delegates to `EndpointValidation`: the IP must
be empty or a **numeric** IPv4/IPv6 address (no DNS names — reverts
`ClprInvalidEndpointAddress`), and the TLS certificate must be empty or a
DER-encoded X.509 certificate carrying an RSA key with a ≥2048-bit modulus
(else `ClprInvalidEndpointCertificate`). The owner's direct-add path in
`addEndpoint` / `updateEndpointManifest` runs the same validation.

## Endpoint deregister is unconditional (I-4)

`ManifestLib.removeEndpoint` (called from `AdminLogic.removeEndpoint`, by the
registrant or the owner) is unconditional once the entry exists: no
in-flight-message gate exists. The bond is credited in full to
`_pendingWithdrawals[registrant]` rather than pushed; a PENDING entry is
cancelled the same way without bumping the manifest version.

The spec says endpoints "MUST NOT deregister with in-flight sync submissions."
On EVM this does not apply:

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

## Connector and channel signatures bind to `address(this)`

The connector reveal signs `keccak256(connectorId ‖ address(this))`
(`ConnectorLib._verifyConnectorSig`) and the channel reveal signs
`keccak256(channelId ‖ address(this))` (`ECDSA._verifySignature`), both
EIP-191-prefixed. Under DELEGATECALL, `address(this)` is the **router**
address, so each signature binds to a specific router deployment. This is the
EVM rendering of the spec's "service_address" binding.

## Charge verification by router-balance delta

`ConnectorLib.charge` calls `IClprConnector.payForExecution(amount)` and
then asserts the router's fee-asset balance grew by exactly `amount`. Because
`ConnectorLib` is an internal library, `address(this)` resolves to the
router. A connector that "succeeds" without transferring (or transfers the
wrong amount) makes `charge` return `false`, and
`BundleLib._processDataMessageDecoded` slashes it. **Don't replace this with a
return-value check** — the ABI return value is unreliable for measuring
actual ETH flow.

## A fee token that pauses or blocks transfers slashes funded connectors

With a fee token, `payForExecution` moves that token from the connector to the router. If the
token pauses transfers, or blocks the connector or the router address (a blocklist or transfer
policy), that transfer reverts. `ConnectorLib.charge` cannot tell this from a connector that
refuses to pay, so it returns `false` and every inbound DATA message for the connector slashes
it, although its balance covers the charge: `balanceOf` still answers, so the affordability
bound passes. After `slashBanThreshold` such messages the connector is banned and loses its
whole `lockedStake`, and one bundle can carry that many. A pause, or a block on the router,
hits every connector at once.

This is an accepted risk: telling the two cases apart needs token-specific checks or a
different payment interface. While the fee token is paused or blocks the router, the operator
disables the service (`docs/runbooks/kill-switch.md`, trigger *Fee token halted*).

## Pull-payment fallback (`_pendingWithdrawals`)

Three-step delivery for connector charges and slash proceeds
(`ConnectorLib._transferWithFallback`):
1. Push to recipient (the bundle submitter).
2. On revert, push to the fallback recipient — the `owner()` address, passed
   into `ConnectorLib.charge` / `slash` as a parameter, not a stored field.
3. On revert again, credit `_pendingWithdrawals[recipient]`; recipient pulls
   later via `collectPending()`.

This exists because bundle submitters may be contracts that revert in
`receive()`. Other ETH exits differ: `removeConnector` pushes the stake to its
`recipient` and reverts with `ClprTransferFailed` on failure, and
`removeEndpoint` credits `_pendingWithdrawals` directly. The B8 regression in
`test/libraries/service/ConnectorLib_SlashAndCharge.t.sol` pins the
fallback.

## Auto-ban on stake exhaustion

If the post-slash count (`slashCount + 1`) reaches `slashBanThreshold`, the
connector's **entire remaining `lockedStake` is seized** and the `Connector`
entry is **deleted** (not just marked banned) — the geometric penalty formula is
skipped on that branch. The entry is also deleted when a normal geometric slash
leaves zero stake. It can be re-registered later, but every reference to the old
key becomes a `hasConnector == false`. `ConnectorLib.slash`; the
stake-drains-to-zero case is the B9 regression in
`test/libraries/service/ConnectorLib_SlashAndCharge.t.sol`.

## Bundle margin and submitter payout (DRIFT-REVIEW C-5/D-1)

When a submitter submits a bundle they front the gas for the entire
transaction. The protocol reimburses them for every DATA message processed,
with the connector paying the measured execution cost plus a margin
(`BundleLib._processDataMessageDecoded`):

```
actualCharge = gasUsed * tx.gasprice
totalCharge  = (actualCharge + actualCharge * economicConfig.endpointMarginPercent / 100) * scale
```

All of `totalCharge` is transferred to the bundle submitter via
`ConnectorLib.charge` — no split, no owner cut, no protocol treasury. The
margin covers the submitter's overhead (routing, verification, hash checks)
and provides a small profit incentive. The margin is a single service-wide
setting (`EconomicConfig.endpointMarginPercent`) applied identically to every
connector — `Connector` has no margin field. `scale` is 1 when the service runs on native
value and `10^(decimals − 18)` with a fee token (the `feeToken` constructor argument), whose
units every charge is then paid in; results round down. `EconomicConfig.messageExecutionCost` is read only as zero
or non-zero: zero turns the whole charge path off (free execution); otherwise charges are
always measured gas.

Example: if the application call uses 300,000 gas at a gas price of 1 gwei
with `endpointMarginPercent = 10`, the connector pays
`300,000 * 1e9 * 110 / 100 = 330,000 gwei` and the submitter receives all
of it.

**Pre-call gas clamp:** before invoking the application the service computes
`affordableGas = balance / scale * 100 / ((100 + endpointMarginPercent)
* tx.gasprice)`, where `balance` is the connector contract's fee-asset balance. If that is **zero**, the connector is CONNECTOR_UNDERFUNDED —
slashed, and no application call is made. Otherwise the call is dispatched
with `gas: min(maxGasPerMessage, affordableGas)`, so the endpoint never
performs work the connector cannot pay for. It is a *clamp* on the forwarded
gas, not a ceiling check against a fixed maximum charge.

When `tx.gasprice == 0` (some test and L2 environments) or `messageExecutionCost == 0`,
execution is free, so the clamp is skipped entirely.

Slash proceeds also go to the submitter (with the pull-payment fallback).
The owner is the fallback recipient for charge and slash transfers — meaning
the protocol owner ends up holding the fee asset from any push-failures. Don't accumulate
large balances on the owner address; they should be swept periodically.

## sendMessage stamps msg.sender — application-layer "from" claims are untrusted

`sendMessage` does not accept a `sender` parameter. The service stamps the on-chain caller address (`msg.sender`) as the sender in the queued DATA message payload using `abi.encodePacked(msg.sender)`. This is the CLPR spec's send-message behavior: "*sender* (stamped from transaction caller)." Applications on the destination side that use the `sender` field for routing or authentication can rely on it as the *on-chain identity of the source-side caller*. However, they MUST NOT trust any in-band "from" claim embedded inside `messageData` itself without independent verification — `messageData` is fully application-controlled and can be forged by any caller.

## Bilateral connector requirement

The spec requires a connector to exist on **both** ledgers under the same
`channel_id` and `connector_id`. The EVM side does not enforce this
(it can't know peer-side state). It manifests as: outbound DATA gets a
peer-side `CONNECTOR_NOT_FOUND` reply, which source-side slashes the local
connector. New code that forks connector registration logic must keep the
ID derivation byte-equivalent across ledgers (see `lifecycle.md`).
