# Architecture

Read this when changing storage, public API, or moving code between contracts.
Pairs with `CLPR.md`.

## DELEGATECALL router pattern

`ClprService` is the only contract anyone interacts with. It declares the
storage and the public ABI but contains no business logic. Each external
function is a stub that DELEGATECALLs into one of five logic contracts:

```
                          ClprService  (router; state lives here)
                               │ DELEGATECALL
   ┌─────────────┬─────────────┼─────────────┬──────────────┐
   ▼             ▼             ▼             ▼              ▼
ChannelLogic MessagingLogic BundleLogic ConnectorLogic  AdminLogic
```

- Each logic contract and the `BundleDecodeHelper` is deployed on its own
  (`script/deploy/deployCore.ts` `deployClprModules`) and passed to the router
  constructor `constructor(initialOwner, protocolVersion, chainId, channelLogic,
  messagingLogic, bundleLogic, connectorLogic, adminLogic, bundleDecodeHelper)`.
  Every address must be non-zero (`ClprService.ZeroLogicAddress`) and have code
  (`ClprModuleNotDeployed`). The router creates no child contracts.
- The five logic addresses are `immutable` on the router. `bundleDecodeHelper`
  is not: it is written once to the `_bundleDecodeHelper` storage variable.
- `BundleLogic` holds only `submitBundle`; it is separate from `MessagingLogic`
  to keep both under the EIP-170 24 KB runtime limit (`BundleLogic` NatSpec).
- The system is **not upgradeable**. The split organises concerns and fits the
  contract-size limits; it is not a proxy/upgrade pattern.
- `deriveConnectorId` is the one function dispatched via STATICCALL
  (`_staticDelegate`), because it reads no router storage. `deriveChannelId`
  reads `_config.chainId`, so it goes through `_delegate` like the rest.
- The constructor fixes `_config.protocolVersion` and `_config.chainId` (no
  setter changes them), seeds the local endpoint manifest at version 1 with its
  commitment (`ManifestLib.syncCommitment`), and sets `_authorizedService =
  address(this)`. `_clprEnabled` stays `false`: the service is inert until the
  owner runs `initialize(...)` and then `setClprEnabled(true)`.

The router and every logic contract inherit `ClprServiceStorage` (the logic
contracts through `LogicModuleBase`) in the same position, so storage slots line
up under DELEGATECALL.

### Module guards (`LogicModuleBase`)

`LogicModuleBase` is the base of all five logic contracts. It defines three
modifiers:

- `onlyService` — `address(this) == _authorizedService`, else
  `UnauthorizedCaller`. Under DELEGATECALL `address(this)` is the router, so the
  check passes; a direct call to the module's own address fails.
  `_authorizedService` is shared storage, set once in the `ClprService`
  constructor.
- `whenEnabled` — reverts `ClprDisabled` while the kill switch `_clprEnabled`
  is `false`.
- `whenInitialized` — reverts `ClprNotInitialized` until `initialize(...)` has
  run.

Owner checks (`onlyOwner`) are on the router stubs in `ClprService`, not in the
modules. Two module functions do not use `onlyService`:
`ConnectorLogic.removeConnector` (the caller must be the connector's `admin`,
checked in `ConnectorLib.deregister`) and `AdminLogic.collectPending` (pays
`msg.sender` from its own `_pendingWithdrawals` entry). Called directly on the
module address, both run against the module's own empty storage and revert.

### Why functions aren't `view`

Solidity 0.8 forbids `delegatecall` inside `view`. So every storage-reading
function on `IClprService` is non-view at the ABI level; only
`deriveConnectorId` is `view`. Off-chain callers use `eth_call` (a STATICCALL)
and pay no gas; on-chain callers must accept the non-view signature.
`IClprService` documents this; don't "fix" it.

### Logic contract constructors and owner reads

Logic contracts are stateless code executed only via DELEGATECALL. Their
constructors are empty, and they do **not** inherit `Ownable` — only
`ClprService` does (`ClprService is ClprServiceStorage, Ownable, IClprService`).

Because `Ownable` comes after `ClprServiceStorage` in that list, `Ownable._owner`
takes the first sequential slot after `economicConfig`: slot **38** in
`storage-layout.json`. Modules read it with `ClprServiceStorage._getOwner()`,
which `sload`s slot 38 directly. `_getOwner()` is the fallback recipient for
charge and slash proceeds (`BundleLogic.submitBundle` passes it as
`fallbackRecipient`) and authorises owner removal in `AdminLogic.removeEndpoint`.

The slot number moves whenever the layout above it changes.
`ClprStorageLayoutGuardTest` (`test/invariants/ClprStorageLayoutGuard.t.sol`)
checks the test-side constant `ClprServiceStorageSlots.OWNER_SLOT` against the
`_owner` slot in `storage-layout.json`; the literal in `_getOwner()` must be kept
equal to that constant by hand.

## Public ABI dispatch table

Every external function on `ClprService`. `IClprService` declares most of them
but omits `closeChannel`, `redactMessage`, the two configuration updates, the
counters (`channelCount`, `connectorCount`, `endpointCount`),
`pendingCommitments`, `pendingConnectorCommitments`, `pendingWithdrawals` and
`collectPending`.

| `ClprService` function | Logic contract | Guards | Notes |
|---|---|---|---|
| `registerChannel(channelId, commitment)`, `completeChannel` | `ChannelLogic` | `onlyService` + `whenEnabled` | Permissionless commit-reveal; see `lifecycle.md` |
| `deriveChannelId`, `getChannel`, `getPeerEndpointManifest`, `getPeerEndpointRoster`, `pendingCommitments`, `channelCount` | `ChannelLogic` | None (read) | `getPeerEndpointRoster` is a derived view built on the fly from the cached peer manifest (nothing is stored in that shape); prefer `getPeerEndpointManifest` |
| `closeChannel` | `ChannelLogic` | Router `onlyOwner`; module `onlyService` + `whenEnabled` | ACTIVE/PAUSED → CLOSING, DRAINED → CLOSED, or purges a pending commitment through the reverse index |
| `sendMessage` | `MessagingLogic` | `nonReentrant` + `onlyService` + `whenEnabled` | Authorised by the source connector (`IClprConnector.authorizeOutboundMessage`); stamps `msg.sender` as the sender |
| `redactMessage` | `MessagingLogic` | Router `onlyOwner`; module `onlyService` + `whenEnabled` | DATA messages in the window `(ackedMessageId, nextMessageId)` only |
| `getMessage`, `getQueueDepth` | `MessagingLogic` | None (read) | `getQueueDepth` returns `{queueDepth, maxQueueDepth}` with depth = `nextMessageId − ackedMessageId − 1` |
| `submitBundle` | `BundleLogic` | `nonReentrant` + `onlyService` + `whenEnabled` | **Permissionless.** `msg.sender` is the bundle submitter and receives connector charges and slash proceeds. Endpoint registration does not gate it |
| `registerConnector`, `completeConnector` (payable), `topUpConnectorStake` (payable) | `ConnectorLogic` | `onlyService` + `whenEnabled` | — |
| `removeConnector` | `ConnectorLogic` | `nonReentrant` + `whenEnabled` | No `onlyService`; the caller must be the connector's `admin` |
| `getConnector`, `hasConnector`, `pendingConnectorCommitments`, `connectorCount`, `deriveConnectorId` (STATICCALL) | `ConnectorLogic` | None (read) | — |
| `setClprEnabled(bool)` | `AdminLogic` | Router `onlyOwner`; module `onlyService` + `whenInitialized` | Not gated by the kill switch, so the owner can always re-enable. Any call, `true` or `false`, reverts `ClprNotInitialized` until `initialize` has run |
| `initialize(...)` | `AdminLogic` | Router `onlyOwner`; module `onlyService` | One-time bootstrap: applies ledger + economic config while still disabled. A second call reverts `ClprAlreadyInitialized`. Does not enable the service |
| `updateLedgerConfiguration`, `updateEconomicConfiguration` | `AdminLogic` | Router `onlyOwner`; module `onlyService` + `whenEnabled` | Reconfigure a running service. A ledger update stamps `_config.nanosSinceEpoch` with `block.timestamp` in nanoseconds; each channel whose `lastConfigTimestamp` is older then enqueues a CONTROL message on its next send or bundle |
| `registerEndpoint` (payable) | `AdminLogic` | `onlyService` + `whenEnabled` | Permissionless. Creates a **PENDING** manifest entry for the caller, escrowing `msg.value ≥ minEndpointBond`; not advertised until admitted. There is no bond top-up |
| `addEndpoint`, `updateEndpointManifest` | `AdminLogic` | Router `onlyOwner`; module `onlyService` + `whenEnabled` | Admit a PENDING registration or direct-add. Capped by `throttles.maxLocalEndpoints` (`ClprEndpointManifestFull`) |
| `removeEndpoint` | `AdminLogic` | `onlyService` + `whenEnabled` | Registrant **or** owner, else `ClprEndpointUnauthorized`. Bond credited in full to `_pendingWithdrawals`; endpoint bonds are never slashed |
| `getEndpointManifest`, `getEndpointEntry`, `getLedgerConfiguration`, `getLedgerConfigurationHash`, `getChannelPeerConfigHash`, `getEconomicConfig`, `pendingWithdrawals`, `endpointCount` | `AdminLogic` | None (read) | `endpointCount` is the LIVE manifest size, excluding PENDING registrations |
| `collectPending` | `AdminLogic` | `nonReentrant` | Pull payment of the caller's `_pendingWithdrawals`. Not `onlyService` and not gated by the kill switch |
| `receive() payable {}` | router | None | Accepts ETH sent to the router, including `IClprConnector.payForExecution` payments |

## Outward-bound interfaces (the protocol calls these)

| Interface | Methods | Called from |
|---|---|---|
| `IClprVerifier` | `verifyConfig(configProof, channelId, endpointManifestProof)` → `(channelContext, chainId, serviceAddress, peerConfigNanos, throttles, initialTrustAnchor, initialTrustAnchorId, endpointManifest)` during `completeChannel`; `verifyBundle(proofBytes, trustAnchor, channelContext)` → `(metadata, messagePayloads, newTrustAnchor, newTrustAnchorId, newEndpointManifest)` during `submitBundle`. Both are `view`, so they run as STATICCALLs | `ChannelLogic._createChannel`, `BundleLib._validateAndPrepare` |
| `IClprApplication` | `onClprMessage` (gas-bounded; return value becomes the REPLY payload), `onClprResponse` (best-effort, gas `throttles.maxGasPerMessage`) | `BundleLib._processDataMessageDecoded`, `BundleLib._processReplyMessageDecoded` |
| `IClprConnector` | `authorizeOutboundMessage` (during `sendMessage`), `payForExecution` (pull payment for inbound DATA), `onInboundMessage` (best-effort, gas `economicConfig.connectorInboundGasStipend`) | `MessagingLogic._authorizeConnector`, `ConnectorLib.charge`, `BundleLib._notifyConnectorInbound` |

## Storage (`ClprServiceStorage.sol`)

**Hard rule:** order, names, and types here are part of the deployment ABI in
the storage sense. Reordering breaks every existing deployment. New fields
must be appended at the end. The base `ReentrancyGuardTransient` keeps its flag
in EIP-1153 transient storage and claims no sequential slot, so protocol fields
start at slot 0.

Listed in **slot order**, as `storage-layout.json` pins them:

| Slot | Field | Type | Purpose |
|---|---|---|---|
| 0 | `_authorizedService` | `address` | Router address, set in the constructor; checked by `onlyService` |
| 1 | `_messageQueues` | `mapping(bytes32 ⇒ mapping(uint64 ⇒ MessageValue))` | Per-channel outbound queue keyed by messageId. EVM verifiers prove the last message's `runningHashAfterProcessing` (`ClprEvmBundleVerifier._lastMessageRunningHashSlot`) |
| 2 | `_bundleDecodeHelper` (offset 0), `_clprEnabled` (20), `_isInitialized` (21) | `address`, `bool`, `bool` (packed) | Decode-helper contract for `try/catch` around protobuf decode; global kill switch (starts `false`); one-time bootstrap latch |
| 3 | `_channelCount` | `uint256` | Completed channels; checked against `economicConfig.maxChannels` |
| 4 | `_connectorCount` | `uint256` | Live connectors; checked against `economicConfig.maxConnectors`. `BundleLib.processBundle` subtracts connectors banned during a bundle by writing this slot directly |
| 5 | `_channelExists` | `mapping(bytes32 ⇒ bool)` | Set at `completeChannel` |
| 6 | `_pendingCommitments` | `mapping(bytes32 ⇒ bool)` | Channel commit phase; key `keccak256(channelId ‖ pubKey)` |
| 7 | `_connectorExists` | `mapping(bytes32 ⇒ bool)` | Key `keccak256(channelId ‖ connectorId)` |
| 8 | `_pendingConnectorCommitments` | `mapping(bytes32 ⇒ bool)` | Connector commit phase; key `keccak256(connectorId ‖ pubKey)` |
| 9 | `_connectorInflightCount` | `mapping(bytes32 ⇒ uint256)` | Key `keccak256(channelId ‖ connectorId)`; outbound DATA awaiting a REPLY; gates `removeConnector` |
| 10 | `_connectorQueueCounts` | `mapping(bytes32 ⇒ mapping(bytes32 ⇒ uint32))` | `[channelId][keccak256(connectorId)]`; per-connector queue quota |
| 11 | `_pendingWithdrawals` | `mapping(address ⇒ uint256)` | Pull-payment balances |
| 12 | `_channelIdToCommitment` | `mapping(bytes32 ⇒ bytes32)` | Reverse index `channelId → commitment`; set at `registerChannel`, deleted at `completeChannel` or `closeChannel` |
| 13, 14 | `_deprecatedPeerEndpointCount`, `_deprecatedPeerEndpointAccounts` | mappings | **Reserved.** Never read or written; they keep `_channels` at slot 15 |
| 15 | `_channels` | `mapping(bytes32 ⇒ Channel)` | Keyed by channelId. EVM verifiers and relay tooling derive this base slot (`ClprEvmBundleVerifier.CHANNELS_BASE_SLOT`) |
| 16 | `_connectors` | `mapping(bytes32 ⇒ Connector)` | Key `keccak256(channelId ‖ connectorId)` (channel-scoped!) |
| 17–21 | `_endpointManifest` | `EndpointManifestState` | Local endpoint registry: `version` (17), `commitment` (18), `entries`, `liveAccounts`, `liveCounter`. `ManifestLib` operates on it. EVM verifiers prove slot 18 (`ClprEvmBundleVerifier.ENDPOINT_MANIFEST_COMMITMENT_SLOT`) |
| 22 | `_peerEndpointManifests` | `mapping(bytes32 ⇒ ClprEndpointManifest)` | Cached peer manifest per channel; set at `completeChannel`, refreshed by BundleLib Step 1b; truncated to `throttles.maxPeerEndpoints` |
| 23–30 | `_config` | `LedgerConfiguration` | `protocolVersion`, local `chainId`, `serviceAddress`, `nanosSinceEpoch`, `throttles`, `trustAnchor`, `trustAnchorId` |
| 31–37 | `economicConfig` | `EconomicConfig` | Execution cost, margin, stake/bond minima, penalty params, queue quota, inbound gas stipend, channel/connector caps |
| 38 | `_owner` | `address` | `Ownable` owner (router only); read by `_getOwner()` |

> ⚠ Two distinct hashes for connector lookup coexist. The `Connector` record
> key (and the `_connectorInflightCount` key) is `keccak256(channelId‖connectorId)`.
> The inner key for `_connectorQueueCounts` is `keccak256(connectorId)` *only*
> (the outer mapping already keys by channelId). Mixing them up silently
> corrupts accounting.

## Key data structures (in `ClprTypes.sol`)

- **`Channel`** — the stored per-channel record in `_channels`, returned as-is
  by `getChannel`. Member slots, from `storage-layout.json`:

  | Slot | Members | Notes |
  |---|---|---|
  | +0 | `channelId` | |
  | +1 | `verifier` (offset 0), `status` (20), `nextMessageId` (21) | `nextMessageId` is the next outbound id; starts at 1 |
  | +2 | `ackedMessageId` (0), `receivedMessageId` (8), `nextExpectedReplyId` (16) | Highest outbound id the peer acked; highest inbound id processed; oldest outbound DATA id still owed a REPLY (cross-bundle response ordering) |
  | +3 | `peerConfigTimestamp` (0), `lastConfigTimestamp` (12) | `uint96` nanoseconds. Peer config timestamp: from `verifyConfig`, then from each accepted inbound CONTROL. Local config timestamp the channel is current with: completion time, then each CONTROL it enqueues |
  | +4, +5 | `sentRunningHash`, `receivedRunningHash` | Outbound and inbound SHA-256 chains |
  | +6, +7 | `ownershipCommitment`, `salt` | From the commit-reveal |
  | +8 … +12 | `chainId` (peer), `peerServiceAddress`, `peerThrottles` (2 slots), `trustAnchor` | Set from `IClprVerifier.verifyConfig` at `completeChannel`. `peerThrottles` is updated by inbound CONTROL (`BundleLib._processControlMessageDecoded`); `trustAnchor` is rotated by `verifyBundle` |
  | +13 | `lastDataMessageId` | Highest outbound DATA id; gates CLOSING → DRAINED |
  | +14, +15 | `trustAnchorId`, `channelContext` | `channelContext` is the opaque `ChannelContext{channelId, remoteServiceAddress}` from `verifyConfig`, passed to every `verifyBundle` |
  | +16 | `endpointManifestVersion` | Version of the cached peer manifest in `_peerEndpointManifests`; `0` = no manifest cached |

  `ClprEvmBundleVerifier._channelMetadataSlots` proves members +1, +2, +4, +5
  and +16 of a peer's `Channel`. Moving any of those fields breaks every EVM
  verifier that reads this layout. Status semantics are in `lifecycle.md`.
  **Public-key encoding:** 64-byte uncompressed secp256k1 (X‖Y, no 0x04
  prefix) — see `quirks.md` "EVM pubkey encoding is 64-byte uncompressed".
- **`Connector`** — `connectorId`, `connectorContract`, `admin`, `lockedStake`,
  `slashCount`. Operating funds for execution charges live as native balance on
  `connectorContract`; `lockedStake` is the slashable bond held in the router.
- **`MessageValue`** — protobuf `payload`, `runningHashAfterProcessing`, and
  `connectorIdForReply` (the connectorId of an outbound DATA message, so REPLY
  processing can decrement counters and slash source-side even after redaction;
  `bytes32(0)` for CONTROL/REPLY). Redaction replaces the payload with
  `ClprRedactedMessage { message_hash: sha256(original) }` and keeps the slot,
  its id and its `runningHashAfterProcessing`.
- **`QueueMetadata`** — `{nextMessageId, sentRunningHash, receivedMessageId,
  receivedRunningHash, state, endpointManifestVersion}`, the peer's view of the
  channel as returned by `verifyBundle`. `BundleLib` reads `nextMessageId`
  (one past the bundle's last message), `sentRunningHash` (the chain through
  that message), `receivedMessageId` (the peer's ack of our messages) and
  `state` (the peer's status). For an EVM peer,
  `ClprEvmBundleVerifier._buildQueueMetadata` decodes all six from the peer's
  proven `Channel` slots. `ClprTypes.ChannelStatus` values match the proto
  `ClprChannelStatus` enum; the spec does not define that enum
  (DRIFT-REVIEW S-1).
- **`Endpoint` / `EndpointManifestEntry` / `ClprEndpointManifest`** —
  `Endpoint {ipAddress, port, tlsCertificate, accountId}` is the discovery
  record advertised in a manifest. `EndpointManifestEntry {endpoint, bond,
  status}` is a local registration, `status` ∈ `EndpointStatus.{NONE, PENDING,
  LIVE}`. `ClprEndpointManifest {version, serviceAddress, endpoints[]}` is the
  published, provable set; `version ≥ 1`, with `0` as the "absent" sentinel.
  `EndpointManifestState` holds the local entries plus the ordered
  `liveAccounts` and the `commitment`. `ManifestUpdateEntry` is one addition in
  an `updateEndpointManifest` batch. `PeerEndpoint` is the derived view shape
  returned by `getPeerEndpointRoster`.
- **`LedgerConfiguration`** — the local config sent to peers in CONTROL
  messages. It carries no endpoints; the endpoint set lives in
  `_endpointManifest`.
- **`EconomicConfig`** — `messageExecutionCost` is stored but no contract in
  `src/` reads it; inbound execution is charged by measured gas (see
  `bundle-flow.md`).

## Library responsibilities

| Library | Responsibility | Takes storage refs? |
|---|---|---|
| `BundleLib` | `libraries/service/` — bundle processing pipeline (`bundle-flow.md`) | yes — heavy |
| `ConnectorLib` | `libraries/service/` — connector reveal, charge, slash, `_transferWithFallback` | yes |
| `ManifestLib` | `libraries/service/` — local endpoint manifest: register / admit / remove / batch update, version bump, commitment sync | yes (`EndpointManifestState`) |
| `EndpointValidation` | `libraries/service/` — validation of endpoint IP addresses and DER TLS certificates | no (pure) |
| `ClprProtobuf` + `ClprProtobufHelpers` | `libraries/codec/` — hand-rolled proto codec for DATA / REPLY / CONTROL / REDACTED, `ClprBundleContent`, and the endpoint manifest. Decoders revert `TruncatedInput` / `VarintOverflow` on malformed input and `ClprUnknownWireField` on unknown fields | no (pure) |
| `ClprConfigHash` | `libraries/codec/` — digests behind `getLedgerConfigurationHash` and `getChannelPeerConfigHash` | no (pure) |
| `BundleDecodeHelper` | `libraries/codec/` — a deployed **contract**, not a library: exposes `decodeData` / `decodeReply` / `decodeControl` as external calls so `BundleLib._dispatchMessages` can `try/catch` a decode | n/a |
| `ECDSA` | `libraries/crypto/` — EIP-191 `ecrecover` check against the `keccak256(pubKey)`-derived address, for channel and connector reveals | no |
| `ClprTypes` | `libraries/` — enums, structs, custom errors, and *file-scope events* `ChannelStatusChanged` and `MessageQueued` (declared at file scope so router and libs share one ABI selector) | no |

The proof libraries under `libraries/proof/` serve the verifiers, not the
service.

## Native-token (ETH) flows

- **In:** `registerEndpoint` (endpoint bond, once per registration),
  `completeConnector` / `topUpConnectorStake` (connector stake), and
  `payForExecution` (pull payment from the connector contract during inbound
  DATA, received by `receive()`).
- **Out:** charge and slash proceeds → bundle submitter, else the fallback
  recipient `_getOwner()`, else credited to the submitter's `_pendingWithdrawals`
  (`ConnectorLib._transferWithFallback`). `removeConnector` **pushes** the
  remaining stake to `recipient` and reverts `ClprTransferFailed` if the push
  fails. `removeEndpoint` and the removals in `updateEndpointManifest`
  **credit** the bond to `_pendingWithdrawals[registrant]` — never a push, so a
  rejecting contract cannot block its removal. `collectPending` pays out a
  `_pendingWithdrawals` balance.
- **Charge verification** is by router-balance delta in `ConnectorLib.charge`:
  after `payForExecution(amount)` the router must have gained exactly `amount`.
  If not, the charge fails and the connector is slashed.
- **`_pendingWithdrawals`** is the safety net: when both push transfers reject,
  the amount is credited to a pull balance claimable via `collectPending()`.
