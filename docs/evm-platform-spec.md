# EVM Platform Specification for CLPR

This document covers EVM-specific implementation choices that are valid bindings
of the platform-agnostic CLPR spec but are not normative across platforms. Each
section below records a binding decision that any EVM deployment of the CLPR
service makes; Hiero or other platform implementations may differ. Where the
platform-agnostic spec is silent, this document provides the normative EVM rule.

`DRIFT-REVIEW-2026-05.md` records its Section 5 items (E-1 through E-8) as
resolved by this document. E-9 onward cover the endpoint manifest and what a
peer ledger must reproduce byte for byte: the storage slots it proves, the
running hash, the wire encoding, the state-proof format and the configuration
digests.

| Section | Binding | Main implementation |
|---|---|---|
| E-1 | Signature scheme and EIP-191 prefix | `ECDSA` |
| E-2 | Connector balance model | `BundleLib`, `ConnectorLib.charge` |
| E-3 | Public-key-to-address derivation | `ECDSA`, `ChannelLogic`, `ConnectorLib` |
| E-4 | Admin authority | `ClprService` (`Ownable`), `ClprServiceStorage._getOwner` |
| E-5 | Per-connector queue quota | `MessagingLogic.sendMessage` |
| E-6 | `IClprConnector` callback surface | `IClprConnector`, `BundleLib` |
| E-7 | Geometric slashing | `ConnectorLib.slash` |
| E-8 | Native-ETH transfer fallback | `ConnectorLib._transferWithFallback` |
| E-9 | Endpoint manifest and bond | `ManifestLib`, `AdminLogic` |
| E-10 | Storage layout and the slots a peer proves | `ClprServiceStorage`, `storage-layout.json` |
| E-11 | Running hash | `MessagingLogic`, `BundleLib` |
| E-12 | Wire encoding | `ClprProtobuf`, `ClprProtobufHelpers`, `BundleDecodeHelper` |
| E-13 | EVM state proofs | `ClprEvmStateProof`, `MerklePatriciaProof`, `RlpCursor` |
| E-14 | Configuration digests | `ClprConfigHash` |

---

## E-1 — Signature scheme and EIP-191 prefix

The EVM CLPR service uses **ECDSA over secp256k1** with an **EIP-191 personal
sign** prefix for both channel-reveal and connector-reveal signatures.

Before calling `ecrecover`, the service wraps the hash with:

```
"\x19Ethereum Signed Message:\n32"
```

### Channel-reveal

1. Compute `msgHash = keccak256(channelId ‖ address(this))`.
   Logic modules run under DELEGATECALL, so `address(this)` is the
   `ClprService` router. The term binds the signature to one deployment, so it
   cannot be replayed on a different CLPR service that derives the same
   `channelId`.
2. Apply EIP-191: `prefixedHash = keccak256("\x19Ethereum Signed Message:\n32" ‖ msgHash)`.
3. `ecrecover(prefixedHash, v, r, s)` must return the address derived from
   the supplied pubkey (see E-3).

### Connector-reveal

1. Compute `msgHash = keccak256(connectorId ‖ address(this))`.
2. Apply EIP-191: `prefixedHash = keccak256("\x19Ethereum Signed Message:\n32" ‖ msgHash)`.
3. `ecrecover` as above.

### Signature bytes

`sig` is exactly 65 bytes, `r ‖ s ‖ v`. `v` is passed to `ecrecover`
unchanged, so it must be 27 or 28; a signer that emits 0 or 1 is rejected. A
wrong length, a failed recovery (`address(0)`) or an address mismatch reverts
`ClprInvalidSignature`.

Implementation: `ECDSA._ecrecoverCheck` (`src/libraries/crypto/ECDSA.sol`).
The channel path reaches it through `ECDSA._verifySignature` from
`ChannelLogic.completeChannel`. The connector path reaches it through
`ConnectorLib._verifyConnectorSig` from `ConnectorLib.completeRegistration`.

---

## E-2 — Connector balance model

The EVM service splits connector funds into two pools:

| Pool | Location | Purpose |
|---|---|---|
| **Operating balance** | Native ETH on the `connectorContract` itself | Pays for inbound message execution charges |
| **Slashable stake** | `Connector.lockedStake` in router storage | Misbehavior bond; subject to geometric slashing (E-7) |

For each inbound DATA message, `BundleLib._processDataMessageDecoded` first
looks up the connector on the channel. A missing connector gets a
`CONNECTOR_NOT_FOUND` reply and no charge. Otherwise it does the following:

1. **Bound the gas.** It computes what the connector can pay for:
   `affordableGas = connectorContract.balance * 100 / ((100 + endpointMarginPercent) * tx.gasprice)`.
   If this is 0, the connector is slashed, the reply is `CONNECTOR_UNDERFUNDED`,
   and the application is not called. Otherwise the application gets
   `min(throttles.maxGasPerMessage, affordableGas)` gas, less the CALL's own
   cost, or the bundle reverts
   with `ExactGasCall.InsufficientGasForCall` (see *Reentrancy & ordering* in
   `bundle-flow.md`). A return that is not an ABI-encoded `bytes` is recorded as
   `APPLICATION_ERROR` with the raw data. With `tx.gasprice == 0` there is no
   bound and no charge.
2. **Charge the gas used.** With `c = gasUsed * tx.gasprice`, the charge is
   `c + c * endpointMarginPercent / 100`. When it is non-zero,
   `ConnectorLib.charge` calls `IClprConnector.payForExecution(charge)` with
   `economicConfig.connectorPaymentGasLimit` gas, less the CALL's own cost, and
   compares the router's ETH balance before and after. The charge fails if the
   connector's balance is below the charge, if the call reverts, or if the
   balance delta is not exactly the charge. A failed charge slashes the
   connector and does not change the reply status. `initialize` and
   `updateEconomicConfiguration` reject a payment budget below
   `ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT` (50,000) with
   `ClprInvalidConfiguration`.
3. **Pay the submitter.** A successful charge goes to the bundle submitter (E-8).
4. **Notify the connector.** `onInboundMessage` gets
   `economicConfig.connectorInboundGasStipend` gas (E-6). With a stipend of 0 it
   is not called.

The platform-agnostic spec charges the connector by debiting a balance the service
holds, so it has no payment call and no budget for one. Both connector hooks are
EVM-only, and each has its own budget:

- `connectorPaymentGasLimit` bounds the payment. It is the only budget whose
  shortfall slashes a connector, so it has a floor. `throttles.maxGasPerMessage`
  stays the application's budget, as the spec defines it, and lowering it never
  changes which connectors are slashed.
- `connectorInboundGasStipend` bounds the notification, whose failure only emits
  an event. The operator sizes it, and 0 turns the notification off.

None of the three budgets is charged to the connector beyond the application's
measured gas. One DATA message can use up to
`maxGasPerMessage + connectorPaymentGasLimit + connectorInboundGasStipend` in
callbacks, plus the service's own work, and `maxMessagesPerBundle` must leave room
for that within the chain's per-transaction gas cap.

`EconomicConfig.messageExecutionCost` is not read by any code path; the charge
is based on gas used.

This model means:
- `topUpConnector` / `withdrawConnectorBalance` from the platform-agnostic
  spec's connector API are **not** exposed by the EVM service. Operating
  balance management is the connector contract's own responsibility.
- Only `topUpConnectorStake` (for the slashable bond) is exposed.
- The spec's `Connector.balance` field does not exist in the EVM storage layout.

---

## E-3 — Public-key-to-address derivation

The EVM CLPR service requires **64-byte uncompressed secp256k1 public keys**
(X‖Y, no `0x04` prefix). The 33-byte compressed form is not supported in v1
because the EVM has no native decompression opcode.

Expected Ethereum address derived from a 64-byte pubkey `P`:

```
expectedAddress = address(uint160(uint256(keccak256(P))))
```

This is the standard Ethereum derivation (keccak of the uncompressed X‖Y bytes,
lower 20 bytes). Both channel-reveal and connector-reveal use this derivation.

The channel path rejects any other key length with `ClprInvalidSignature`, in
`ChannelLogic.completeChannel` and again in `ECDSA._verifySignature`. The
connector path (`ConnectorLib._verifyConnectorSig`) has no explicit length
check: a key of any other length hashes to an address that does not match the
recovered one.

The commit phase binds the raw pubkey, not an address. The channel commitment
is `keccak256(channelId ‖ pubKey)`, the connector commitment is
`keccak256(connectorId ‖ pubKey)`, and both IDs are derived from the pubkey. A
peer on another platform can therefore check a reveal from the pubkey alone.

---

## E-4 — Admin authority: OZ Ownable

The platform-agnostic spec's "CLPR Service admin" role is bound to OZ
`Ownable` on the EVM. The owner address returned by `owner()` is the admin.

`ClprService` applies `onlyOwner` on the router to `closeChannel`,
`setClprEnabled`, `initialize`, `updateLedgerConfiguration`,
`updateEconomicConfiguration`, `addEndpoint` and `updateEndpointManifest`.
Logic modules, which run under DELEGATECALL, read the owner with
`ClprServiceStorage._getOwner`, a raw `sload` of slot 38 (E-10).
`AdminLogic.removeEndpoint` uses it to authorize the owner, and
`BundleLogic.submitBundle` uses it as the transfer fallback recipient (E-8).

Operational deployments may wrap the owner slot with a multi-sig (e.g.,
Gnosis Safe — see `safe-runbook.md`) or a timelock (e.g., OZ
TimelockController) without any change to the CLPR contracts themselves. The
service does not enforce any particular ownership structure beyond "caller is
`owner()`."

`setClprEnabled(bool)` is deliberately excluded from the kill-switch guard
(`whenEnabled`) so the owner can always re-enable the service. It is gated by
`whenInitialized`: the service is deployed with `clprEnabled = false`, and
**any** call — `true` or `false` — reverts `ClprNotInitialized` until the owner
has run `initialize(serviceAddress, throttles, trustAnchor, trustAnchorId,
econConfig)`. `initialize` runs once; a second call reverts
`ClprAlreadyInitialized`. See `runbooks/kill-switch.md` for the operational
procedure.

---

## E-5 — Per-connector queue quota

The platform-agnostic spec leaves "Queue Monopolization" as an open problem;
the EVM service provides a concrete resolution in `MessagingLogic.sendMessage`:

```
connectorQuota = maxQueueDepth * connectorQueueQuotaPct / 100    // uint32 arithmetic
```

- `connectorQueueQuotaPct` is a field of `EconomicConfig`; `maxQueueDepth` is
  a field of the local `LedgerConfiguration.throttles`. The owner sets them via
  `initialize`, `updateEconomicConfiguration` and `updateLedgerConfiguration`.
  `connectorQueueQuotaPct` must be below 100 (`ClprInvalidConfiguration`), and
  `ClprTypes.validateThrottles` rejects zero for `maxGasPerMessage`,
  `maxMessagesPerBundle`, `maxMessagePayloadBytes`, `maxSyncBytes` and
  `maxQueueDepth`. A quota that rounds down to 0 (for example
  `connectorQueueQuotaPct = 0`) rejects every DATA send.
- Each connector's outstanding outbound DATA count is tracked in
  `_connectorQueueCounts[channelId][keccak256(connectorId)]`.
  `MessagingLogic._enqueueDataMessage` increments it. It is decremented when
  the peer's REPLY for the message is processed
  (`BundleLib._processReplyMessageDecoded`).
- `sendMessage` reverts `ClprQueueQuotaExceeded` when the count is already
  **at** the quota (`count >= quota`), so the last accepted message brings the
  count exactly to the quota.

This is an additive enforcement layer on top of the channel-wide queue check
(`nextMessageId - ackedMessageId - 1 >= maxQueueDepth` reverts `ClprQueueFull`);
connectors that stay within quota are unaffected.

---

## E-6 — IClprConnector callback surface

The EVM CLPR service calls the registered connector contract to authorize
outbound messages, pay for inbound execution, and receive best-effort inbound
notifications:

```solidity
/// Called by sendMessage after the queue and quota checks. Returning false reverts the
/// send with ClprConnectorUnauthorized; a revert propagates.
/// `sender` is abi.encodePacked(msg.sender) of the sendMessage caller.
function authorizeOutboundMessage(
    bytes32 channelId,
    bytes calldata targetApplication,
    bytes calldata sender,
    bytes calldata messageData
) external returns (bool authorized);

/// Called during submitBundle when an inbound DATA dispatch has a non-zero charge (E-2),
/// including when the application call reverted (APPLICATION_ERROR). Must transfer exactly
/// `amount` wei to msg.sender (the router); any other outcome slashes the connector. Gas is
/// economicConfig.connectorPaymentGasLimit, less the CALL's own cost, or the bundle reverts.
function payForExecution(uint256 amount) external;

/// Called for each decoded inbound DATA message whose connector is registered and not
/// underfunded, after the charge attempt and whether or not the charge succeeded, when the
/// connector contract has code and the stipend is not 0. Gas is
/// economicConfig.connectorInboundGasStipend, less the CALL's own cost, or the bundle reverts. A revert is
/// caught and emits
/// BundleLib.ConnectorInboundCallbackFailed.
function onInboundMessage(
    bytes32 channelId,
    uint64 messageId,
    bytes calldata sender,
    bytes calldata targetApplication,
    bytes calldata messageData
) external;
```

`payForExecution` is not called when the charge is 0: the target application
has no code (the reply is `APPLICATION_ERROR` and no gas is used) or
`tx.gasprice` is 0.

These methods are EVM-specific and are not expected to appear in the
platform-agnostic spec. Other platform implementations may use different
payment and notification primitives.

---

## E-7 — Geometric slashing (TODO: lift to platform-agnostic spec)

The EVM service implements geometric (exponentially escalating) slashing for
connector misbehavior. `slashCount` is the connector's count before this slash:

```
# non-ban slash (slashCount + 1 < slashBanThreshold)
penalty = min(basePenalty * penaltyMultiplier^slashCount, lockedStake)

# ban slash (slashCount + 1 >= slashBanThreshold): the geometric formula is skipped
penalty = lockedStake
```

`ConnectorLib._geometricPenalty` saturates at `type(uint256).max` and returns
`basePenalty` when `penaltyMultiplier <= 1`.

Parameters are set per deployment in `EconomicConfig`:
- `basePenalty` — penalty for the first infraction.
- `penaltyMultiplier` — integer multiplier applied per slash (e.g., `2` for doubling).
- `slashBanThreshold` — when the **post-slash** count (`slashCount + 1`)
  reaches this value, the connector's whole remaining `lockedStake` is seized
  and the record is deleted (banned). A threshold of 0 or 1 bans on the first
  slash.
- Auto-ban also triggers if a non-ban slash leaves `lockedStake` at zero.

A ban deletes the `Connector` record and its `_connectorExists` flag, and
`BundleLib.processBundle` decrements `_connectorCount` by the number of bans in
the bundle.

`BundleLib` slashes a connector in three cases:
- an inbound DATA message whose connector cannot afford any gas (reply `CONNECTOR_UNDERFUNDED`, E-2);
- an inbound DATA message whose charge fails (E-2);
- an inbound REPLY with status `CONNECTOR_NOT_FOUND` or `CONNECTOR_UNDERFUNDED`
  for one of this ledger's DATA messages. This source-side slash applies to
  the local connector that sent it.

Slash proceeds go to the bundle submitter via `_transferWithFallback` (see E-8).

> **TODO: lift to spec.** Geometric slashing is a sound policy for all CLPR
> implementations (the escalation curve deters repeat offenders while a first
> infraction is recoverable). The Hiero implementation should adopt the same
> formula. Raise a clpr-spec issue to absorb E-7 into the platform-agnostic
> slashing section before the next spec revision.

---

## E-8 — Native-ETH transfer fallback chain

`ConnectorLib._transferWithFallback` covers exactly two flows, both paid to the
bundle submitter: connector **charge** proceeds and **slash** proceeds.

1. **Attempt transfer to the primary recipient** — low-level `.call{value: amount}("")`.
2. **If that fails:** attempt transfer to `fallbackRecipient = owner()`.
3. **If that also fails:** credit `_pendingWithdrawals[recipient] += amount`.
   The recipient itself later calls `collectPending()` to claim the balance.
   `collectPending` pays out only `_pendingWithdrawals[msg.sender]`, so a third
   party cannot claim it.

The other two ETH paths do **not** use this chain:

- **Connector stake return** (`ConnectorLogic.removeConnector`) is a direct
  transfer to the caller-chosen `recipient`. It reverts the whole call with
  `ClprTransferFailed` if the recipient rejects it.
- **Endpoint bond refund** is never pushed. `ManifestLib` credits
  `_pendingWithdrawals[registrant]` directly (E-9).

`AdminLogic.collectPending` reverts `ClprNothingToCollect` on a zero balance and
`ClprTransferFailed` if the transfer fails. It is not behind the kill switch
(`whenEnabled`), so pending balances stay claimable while the service is
disabled.

This pattern ensures that a recipient contract that rejects ETH (e.g., a
contract with no `receive()`) never locks charge or slash proceeds.
`removeConnector` and `collectPending` do revert on a failed transfer; in both
cases the caller controls the recipient, so reverting is safe and keeps the
funds claimable.

---

## E-9 — Endpoint manifest and bond

The platform-agnostic spec leaves the endpoint registry's on-chain shape to the
implementation. On EVM the manifest **is** the endpoint registry: there is no
separate `_endpoints` mapping, and endpoints do not appear inside
`LedgerConfiguration`. The state is `_endpointManifest`
(`ClprTypes.EndpointManifestState`), operated on by `ManifestLib`.

**Two-step admission.**
- `registerEndpoint(Endpoint) payable` is permissionless self-registration. It
  requires no existing entry for the caller (`ClprEndpointAlreadyRegistered`)
  and `msg.value >= economicConfig.minEndpointBond` (`ClprInsufficientBond`),
  and creates a **PENDING** `EndpointManifestEntry {endpoint, bond, status}`.
  The endpoint is not advertised and the manifest version does not change.
- The owner admits it with `addEndpoint(registrant, endpoint)`, which promotes
  a PENDING entry using its self-registered data (`endpoint` is ignored), or
  adds `endpoint` directly with no bond when there is no entry. An already-LIVE
  registrant reverts `ClprEndpointAlreadyRegistered`, and a full live set
  reverts `ClprEndpointManifestFull` (`throttles.maxLocalEndpoints`, 0 = no
  limit). The version increases by 1.
- `updateEndpointManifest(add[], remove[])` applies removals first and then
  additions, so a swap succeeds at full capacity. Removals of unknown
  registrants are skipped; additions follow the `addEndpoint` rules. The
  version increases by 1 at most once, when the batch has any addition or
  removes a LIVE entry.
- `removeEndpoint(registrant)` may be called by the registrant or the owner
  (`ClprEndpointUnauthorized` otherwise), and reverts
  `ClprEndpointNotRegistered` when there is no entry. It removes a LIVE entry
  (version + 1) or cancels a PENDING one (version unchanged).

**The bond is never slashed.** Slashing applies only to connectors. On any
exit, the bond is credited **in full** to `_pendingWithdrawals[registrant]`. It
is always pull, never push, so a contract registrant that rejects ETH cannot
block its own removal. There is no top-up path.

**Registration does not gate `submitBundle`**, which is permissionless. The
manifest is a discovery mechanism, not an access-control list.

**Field validation** is EVM-specific and lives in `EndpointValidation`. It runs
on self-registration and on a direct admin add; promoting a PENDING entry
reuses already-validated data.
- The IP must be empty or a numeric IPv4 (`a.b.c.d`, octets 0–255) or IPv6
  literal (hex groups, optionally `::`). DNS names revert
  `ClprInvalidEndpointAddress`.
- The TLS certificate must be empty or a DER-encoded X.509 certificate with an
  `rsaEncryption` key whose modulus is at least 256 bytes (2048 bits). The
  check is structural only; no signature is verified. Failures revert
  `ClprInvalidEndpointCertificate`.

**Versions and commitment.** The `ClprService` constructor seeds
`_endpointManifest.version = 1` and the commitment, so a new service already
serves a provable empty manifest. The commitment is
`keccak256(ClprProtobuf.encodeEndpointManifest(getEndpointManifest()))` (E-12).
`ManifestLib` recomputes it on every version change, and `AdminLogic` recomputes
it when `serviceAddress` changes, because the address is part of the committed
encoding. Peers prove the commitment at storage slot 18 (E-10).

**Propagation to a peer.** The receiving service keeps the peer's manifest
out-of-line in `_peerEndpointManifests[channelId]`, truncated to its own
`throttles.maxPeerEndpoints` (0 = no limit). Its version is recorded in
`Channel.endpointManifestVersion`. `ChannelLogic.completeChannel` stores the
manifest that `verifyConfig` returns; version 0 means no manifest proof was
supplied. After that, `BundleLib` applies a proven manifest only when its
version is strictly greater than `Channel.endpointManifestVersion`. That is why
0 is the uninitialized sentinel and real manifests start at 1. A manifest that
advances the version counts as bundle progress on its own.

---

## E-10 — Storage layout and the slots a peer proves

Storage packing is left to the platform. On EVM the layout is
`ClprServiceStorage` followed by OZ `Ownable._owner`, snapshotted in
`storage-layout.json`. The layout is **normative for peer verifiers and
relays**. An EVM-family verifier on the other ledger derives slot numbers from
it (`ClprEvmBundleVerifier`), and a relay builds storage proofs for exactly
those slots.

### Top-level slots

| Slot | Variable | Type |
|---|---|---|
| 0 | `_authorizedService` | `address` |
| 1 | `_messageQueues` | `mapping(bytes32 => mapping(uint64 => MessageValue))` |
| 2 | `_bundleDecodeHelper` (offset 0), `_clprEnabled` (offset 20), `_isInitialized` (offset 21) | `address`, `bool`, `bool` |
| 3 | `_channelCount` | `uint256` |
| 4 | `_connectorCount` | `uint256` |
| 5 | `_channelExists` | `mapping(bytes32 => bool)` |
| 6 | `_pendingCommitments` | `mapping(bytes32 => bool)` |
| 7 | `_connectorExists` | `mapping(bytes32 => bool)` |
| 8 | `_pendingConnectorCommitments` | `mapping(bytes32 => bool)` |
| 9 | `_connectorInflightCount` | `mapping(bytes32 => uint256)` |
| 10 | `_connectorQueueCounts` | `mapping(bytes32 => mapping(bytes32 => uint32))` |
| 11 | `_pendingWithdrawals` | `mapping(address => uint256)` |
| 12 | `_channelIdToCommitment` | `mapping(bytes32 => bytes32)` |
| 13 | `_deprecatedPeerEndpointCount` | `mapping(bytes32 => uint32)`, unused |
| 14 | `_deprecatedPeerEndpointAccounts` | `mapping(bytes32 => bytes32[])`, unused |
| 15 | `_channels` | `mapping(bytes32 => Channel)` |
| 16 | `_connectors` | `mapping(bytes32 => Connector)` |
| 17–21 | `_endpointManifest` | `EndpointManifestState`: `version` 17, `commitment` 18, `entries` 19, `liveAccounts` 20, `liveCounter` 21 |
| 22 | `_peerEndpointManifests` | `mapping(bytes32 => ClprEndpointManifest)` |
| 23–30 | `_config` | `LedgerConfiguration` (`serviceAddress` at 25) |
| 31–37 | `economicConfig` | `EconomicConfig` |
| 38 | `_owner` | `address` (OZ `Ownable`) |

`ReentrancyGuardTransient` keeps its flag in EIP-1153 transient storage and
takes no slot. Slots 13 and 14 are declared but unused; they keep `_channels`
at slot 15, which every EVM-family verifier and relay hardcodes.

### `Channel` members

`_channels[channelId]` occupies 17 slots from `cBase = keccak256(abi.encode(channelId, 15))`:

| Offset | Members (byte offset within the slot) | Proven by peers |
|---|---|---|
| +0 | `channelId` | |
| +1 | `verifier` (0), `status` (20), `nextMessageId` (21) | yes |
| +2 | `ackedMessageId` (0), `receivedMessageId` (8), `nextExpectedReplyId` (16) | yes |
| +3 | `peerConfigTimestamp` (0), `lastConfigTimestamp` (12) | |
| +4 | `sentRunningHash` | yes |
| +5 | `receivedRunningHash` | yes |
| +6 | `ownershipCommitment` | |
| +7 | `salt` | |
| +8 | `chainId` | |
| +9 | `peerServiceAddress` | |
| +10, +11 | `peerThrottles` | |
| +12 | `trustAnchor` | |
| +13 | `lastDataMessageId` | |
| +14 | `trustAnchorId` | |
| +15 | `channelContext` | |
| +16 | `endpointManifestVersion` | yes |

### Slots a peer verifier proves

```
cBase          = keccak256(abi.encode(channelId, 15))           // _channels[channelId]
channelSlots   = cBase + 1, cBase + 2, cBase + 4, cBase + 5, cBase + 16
qBase          = keccak256(abi.encode(channelId, 1))            // _messageQueues[channelId]
lastMsgSlot    = keccak256(abi.encode(uint64(nextMessageId - 1), qBase)) + 1
                                                                // MessageValue.runningHashAfterProcessing
manifestSlot   = 18                                             // _endpointManifest.commitment
```

Both ends of a channel key it by the same `channelId`, because the derivation
sorts the two chain IDs. A verifier therefore derives the peer's slots from its
own `channelId`. A storage proof carries the five channel slots, plus
`lastMsgSlot` as an optional sixth entry; the manifest proof carries
`manifestSlot`. On Sei, the same slot numbers appear inside IAVL keys
`0x03 ‖ serviceAddress ‖ slot`.

Solidity packs struct members from the low-order end of the word, so on the
32-byte big-endian word `w` the proven values decode as follows
(`ClprEvmBundleVerifier._buildQueueMetadata`):

| `QueueMetadata` field | Slot | Extraction |
|---|---|---|
| `state` | `cBase + 1` | `uint8(w >> 160)` |
| `nextMessageId` | `cBase + 1` | `uint64(w >> 168)` |
| `receivedMessageId` | `cBase + 2` | `uint64(w >> 64)` |
| `sentRunningHash` | `cBase + 4` | `w` |
| `receivedRunningHash` | `cBase + 5` | `w` |
| `endpointManifestVersion` | `cBase + 16` | `uint64(w)` |

On the receiving side `BundleLib` reads `nextMessageId` (replay defense and
new-message count), `sentRunningHash` (E-11), `receivedMessageId` (the
acknowledgement) and `state` (the channel state machine).
`receivedRunningHash` and `endpointManifestVersion` are returned by the
verifiers but not read by `BundleLib`. The per-verifier details are in
[`src/verifiers/evm/common/README.md`](../src/verifiers/evm/common/README.md).

`_config.serviceAddress` (slot 25) is a `bytes` value. The EVM-family
verifiers require the peer service address to be exactly 20 bytes
(`InvalidServiceAddressLength`), and the manifest's `service_address`, which
comes from `_config.serviceAddress`, must equal it (E-9). For EVM-family peers,
`_config.serviceAddress` must therefore be the raw 20-byte address. Stored as
short `bytes`, it fills slot 25 as `address ‖ zeros ‖ 0x28`, which is the value
`SeiCometBftVerifier.verifyConfig` checks.

### What pins the layout

- The CI `Lint` job regenerates the layout with `forge inspect ClprService
  storage-layout --json` and fails when it differs from `storage-layout.json`.
- `ClprEvmBundleVerifier` hardcodes `CHANNELS_BASE_SLOT = 15`,
  `MESSAGE_QUEUES_BASE_SLOT = 1` and `ENDPOINT_MANIFEST_COMMITMENT_SLOT = 18`.
- `ClprServiceStorage._getOwner` hardcodes slot 38.
- `test/invariants/ClprStorageLayoutGuard.t.sol` checks against
  `storage-layout.json`: the proven `Channel` members' slots and offsets, the
  `EndpointManifestState.commitment` member, `_endpointManifest` at 17, the
  reserved slots 13 and 14, and `_owner` at 38. It does not assert the
  `_channels` or `_messageQueues` base slots.
- `test/verifiers/compliance/ClprEvmStorageComplianceTest.sol` hardcodes
  slots 15 and 18 independently of the verifier.

> Moving any of these slots, or any proven `Channel` member, is a
> **wire-breaking** change: every peer's verifier and relay must be redeployed
> in lockstep.

---

## E-11 — Running hash

Every enqueued outbound message extends the channel's hash chain:

```
runningHash_n = sha256( runningHash_(n-1) ‖ sha256(payload_n) )    // 64-byte preimage
runningHash_0 = bytes32(0)
```

`payload_n` is the protobuf `ClprMessage` bytes stored in
`MessageValue.payload`. Every message kind uses the same step:
- DATA — `MessagingLogic._enqueueDataMessage`;
- CONTROL — `MessagingLogic._maybeEnqueueConfigUpdate`, and the lazy config
  propagation in `BundleLib._applyBundle`;
- REPLY — `BundleLib._enqueueReplyAndEmit` through `BundleLib._enqueueMessage`.

The new value is written to that message's
`MessageValue.runningHashAfterProcessing` and to `Channel.sentRunningHash`.
`ChannelLogic._createChannel` leaves `sentRunningHash` at zero, which is the
seed.

The receiver checks the chain in `BundleLib._validateAndPrepare`:
1. It starts from its `Channel.receivedRunningHash`.
2. It skips the leading payloads it has already received.
3. It folds the remaining payloads with the same step.
4. The result must equal the proven `QueueMetadata.sentRunningHash`, or the
   bundle reverts `ClprRunningHashMismatch`.

On success, `receivedRunningHash` becomes the computed value, and
`receivedMessageId` becomes the peer's `nextMessageId - 1`. The payloads are
bound to the proof only through this check: EVM-family verifiers do not prove
payloads individually.

---

## E-12 — Wire encoding

`ClprProtobuf` hand-encodes the CLPR protobuf schemas, and
`ClprProtobufHelpers` holds the varint, field-key and length-delimited
primitives. Only wire types 0 (varint) and 2 (length-delimited) occur.

### Message payloads

A queued payload is a `ClprMessage` whose top-level field number selects the
message kind (`ClprProtobuf.getMessageType`):

| Field | Kind | Body fields |
|---|---|---|
| 1 | DATA | `connector_id` 1 (bytes, exactly 32), `target_application` 2, `sender` 3, `message_data` 4 |
| 2 | REPLY | `message_id` 1 (varint), `status` 2 (varint, `ReplyStatus` 0–3), `reply_data` 3 |
| 3 | CONTROL | `config_update` 1 → `configuration` 1 → `ClprLedgerConfiguration` |

`ClprLedgerConfiguration` fields are `protocol_version` 1, `chain_id` 2,
`service_address` 3, `timestamp` 4 (`{seconds 1, nanos 2}`), `throttles` 5,
`trust_anchor` 7 and `trust_anchor_id` 8. Field 6 is not defined; a decoder
that meets it reverts `ClprUnknownWireField(6)`. `ClprThrottles` numbers the
`Throttles` members 1–7 in declaration order.

### Bundle content and manifest

- **`ClprBundleContent`** — field 1 is a `QueueMetadata`, field 2 is one
  message payload (repeated, in queue order). `QueueMetadata` fields are
  `next_message_id` 1, `sent_running_hash` 2, `received_message_id` 3,
  `received_running_hash` 4, `state` 5 and `endpoint_manifest_version` 7.
  EVM-family verifiers read only field 2 and take the metadata from the
  storage proof (E-10).
- **`ClprEndpointManifest`** — `version` 1, `service_address` 2 and
  `endpoints` 3 (repeated `ClprEndpoint { service_endpoint 1 {ip 1, port 2},
  tls_certificate 2, account_id 3 }`). The manifest commitment (E-9) is
  `keccak256` over exactly the bytes that `ClprProtobuf.encodeEndpointManifest`
  produces for `getEndpointManifest()`. A relay that re-encodes the manifest
  must reproduce that encoding, including the endpoint order, which is the
  order of `EndpointManifestState.liveAccounts`. A removal changes that order,
  because it swaps the last entry into the removed position.

### Encoding rules

- Scalars and byte strings at their proto3 default (0, empty) are omitted
  (`encodeVarintField`, `encodeBytesField`). A 32-byte hash is always emitted,
  even when it is zero.
- Sub-messages are always emitted, even when empty: the `Timestamp` and
  `ClprThrottles` of a CONTROL message, and the `service_endpoint` of each
  endpoint.
- Fields are written in ascending field-number order.

### Decoding rules

- The helpers fail closed. A varint or length prefix that runs past the buffer
  reverts `ClprProtobufHelpers.TruncatedInput`, and a varint wider than 64 bits
  reverts `ClprProtobufHelpers.VarintOverflow`. Non-minimal varints are accepted.
- `ClprProtobufHelpers.skipField` accepts wire types 0 and 2 only. Any other
  wire type reverts with the string `"Unsupported wire type"`.
- `decodeDataMessage`, `decodeReplyMessage` and `decodeControlMessage` are
  strict, and so are the throttles, endpoint and `QueueMetadata`
  sub-decoders. An unknown field reverts `ClprUnknownWireField(fieldNumber)`.
  An out-of-range value reverts `ClprBundleVerificationFailed`: a status above
  the enum range, a `uint32` field above `type(uint32).max`, a port above
  65535, or a `connector_id` that is not 32 bytes.
- `decodeEndpointManifest` skips unknown top-level fields, but its endpoint
  sub-decoder is strict. `ClprEvmBundleVerifier._decodeBundleContent` skips
  every field except field 2.

### Decode isolation: `BundleDecodeHelper`

`BundleDecodeHelper` is a separate contract. `ClprService` takes its address as
a constructor argument and stores it in `_bundleDecodeHelper` (slot 2). It
exposes `decodeData`, `decodeReply` and `decodeControl` as external calls, so
`BundleLib._dispatchMessages` can wrap a decode in `try`/`catch`; an internal
library call cannot be caught. A failed decode has this effect:

| Payload | Failure | Effect |
|---|---|---|
| any | empty payload, unknown top-level field, or malformed top-level key | The bundle reverts (`ClprBundleVerificationFailedEmptyPayload`, `ClprUnknownWireField`, `TruncatedInput`, `VarintOverflow`). |
| DATA | `ClprUnknownWireField` | The bundle reverts with the original error. |
| DATA | any other decode failure | `BundleParseFailed` is emitted, an `APPLICATION_ERROR` reply is queued, and dispatch continues. |
| REPLY | any | The bundle reverts. The response-ordering pre-scan (`BundleLib._checkResponseOrdering`) decodes REPLYs inline, and dispatch decodes them again without `try`. |
| CONTROL | `ClprBundleVerificationFailedOneOfVariant`, `ClprUnknownWireField`, `TruncatedInput`, `VarintOverflow` | The bundle reverts. |
| CONTROL | any other decode failure | `BundleParseFailed` is emitted, no reply is queued, and dispatch continues. |

`bundle-flow.md` describes the dispatch loop around these calls.

---

## E-13 — EVM state proofs

A peer verifier authenticates a state root in its own way. The Merkle-Patricia
part after that is shared: `ClprEvmStateProof` over `MerklePatriciaProof`,
both reading RLP in place with `RlpCursor`.

- **Account proof.** `ClprEvmStateProof.verifyAccountFields` walks the state
  trie from `stateRoot` along `keccak256(serviceAddress)` in strict mode
  (`MerklePatriciaProof.requireValueRange`). An absent or diverging key reverts
  (`MPTKeyAbsent`, `MPTKeyMismatch`). The leaf must be exactly
  `[nonce, balance, storageRoot, codeHash]`, or the call reverts
  `InvalidAccount`.
- **Storage proof.** The proof is a list of `[slot, proofNodes]` entries with
  no value field; the value is read from the trie leaf.
  `ClprEvmStateProof.indexEntries` validates the shape of every entry up front
  (`InvalidStorageEntry`). `ClprEvmStateProof.verifyIndexedSlots` then finds
  each caller-derived slot by label (`SlotNotProven(slot)` if none) and walks
  the storage trie along `keccak256(slot)`. Entries may appear in any order.
- **Absent storage slots.** The storage walk is lenient
  (`MerklePatriciaProof.valueRangeOrZero`): a valid proof that the key is
  absent yields 0. This is how an unset or deleted slot is proven. Structural
  defects (bad node shape, hash mismatch, truncated proof) still revert.
- **Node support.** The walk supports branch (17-item), extension and leaf
  (2-item) nodes referenced by 32-byte hashes. An inline child reference (a
  node shorter than 32 bytes embedded in its parent) reverts
  `MPTInlineNodeUnsupported`.
- **RLP canonicality.** `RlpCursor` bounds every read but does not reject
  non-canonical encodings. Node contents are hash-checked before they are
  parsed, so this affects only the framing layers that are not hashed: one
  proof has many byte encodings that verify identically. Nothing in the
  repository keys replay protection or deduplication off raw proof bytes, and
  new code must not.

---

## E-14 — Configuration digests

`ClprConfigHash` produces one-word digests that an off-chain party can
recompute to compare configurations without decoding them.

| View | Digest |
|---|---|
| `getLedgerConfigurationHash()` | `keccak256(abi.encode(protocolVersion, chainId, serviceAddress, nanosSinceEpoch, throttles, trustAnchor, trustAnchorId))` over the local `_config` |
| `getChannelPeerConfigHash(channelId)` | `keccak256(abi.encode(chainId, peerServiceAddress, peerConfigTimestamp, peerThrottles, trustAnchor, trustAnchorId))` over the `Channel`; reverts `ClprChannelNotFound` for an unknown channel |

Both digests encode the fields as a flat ABI tuple, not as the struct.
`abi.encode(cfg)` of a struct with dynamic members prepends a 32-byte offset
word, so it produces a different digest. `throttles` is encoded inline as the
seven-word static `Throttles` tuple. Neither digest covers the peer endpoint
manifest. A new `LedgerConfiguration` field changes the digest only when it is
also added to `ClprConfigHash.hashLedgerConfiguration`.
