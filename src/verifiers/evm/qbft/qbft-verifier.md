# QBFT Proof Verifier — Specification

**Status:** Implemented, revision 2026-06-16
**Scope:** Reference implementation of `IClprVerifier` for bundles originating from a Besu QBFT chain, using RLP-encoded block headers with QBFT committed seals plus Merkle-Patricia state and storage proofs.
**Anchors to:** `IClprVerifier` interface, CLPR §3.1, `hiero-verifier.md` (sibling implementation).

> **Header mode vs. contract mode.** This document specifies **header mode**, where the validator
> set lives in each block header's `extraData`. Besu QBFT can instead keep the set in an on-chain
> validator contract — **contract mode** — specified in [`qbft-contract-mode.md`](qbft-contract-mode.md).
> One channel keeps one mode for its whole life. `QBFTVerifier` inspects the stored trust anchor and
> config proof and routes contract-mode inputs to the embedded `QbftContractModeVerifier`; the two
> anchor encodings are currently distinguished by shape (length and first word). Keep any change to
> the header-mode anchor layout below disjoint from the contract-mode anchor
> (`abi.encode(uint8 mode=1, …)`, 192 bytes) so the router stays unambiguous.

## Overview

QBFTVerifier implements `IClprVerifier` for bundles whose source ledger is a Besu QBFT chain. Each call to `verifyBundle` authenticates:

- Zero or more **epoch block headers**, each advancing the trust-anchor validator to the next committee.
- The **current block header**, sealed by the (possibly updated) validator and carrying the state root.
- The **peer service account** in the state trie, by walking the Merkle-Patricia proof for the configured service contract against `header.stateRoot`.
- **Five fixed storage slots** of that account (plus an optional sixth for outbound message integrity), derived from the `channelId` stored in the trust anchor.

On success it returns queue metadata extracted from the proven slots, the message payloads decoded from the protobuf bundle content, and — when epoch headers were processed — an updated `newTrustAnchor` advancing the trust anchor to the latest epoch.

The verifier is **view** (reads no contract storage). All persistent trust is carried in the per-call `trustAnchor` bytes, which CLPRService stores per channel.

**Trust assumption: validator keys identify the chain.** A QBFT header is authenticated by its committed seals alone; the sealed hash carries no chain id, so nothing in a header ties it to one network. The verifier therefore trusts the validator keys, not a chain identity. If the same validator keys seal blocks on more than one network — a fork, or a test network cloned from production with the same contract addresses — a relay can present a header from the other network and the verifier cannot tell them apart. The anchor's `codeHash` and service address narrow this, but a clone shares both. Operators must not reuse validator keys across networks a channel could be pointed at. This applies to both header and contract mode.

## Construction

```solidity
constructor(uint8 _sealSignatures)
```

`_sealSignatures` is stored as the immutable `MIN_COMMITTED_SEALS`. It specifies how many distinct committed seals must appear in a block header's QBFT extraData. The value must be ≥ 1; the constructor reverts otherwise.

Deploy one instance per quorum configuration; share it across channels that have the same minimum-seal requirement.

## Trust anchor

```
abi.encode(
  address  validator,      // 32 bytes (padded)
  address  clprService,    // 32 bytes (padded)
  bytes32  codeHash,       // 32 bytes
  uint64   epochLength,    // 32 bytes (padded)
  uint64   epochNumber,    // 32 bytes (padded)
  bytes32  channelId    // 32 bytes
)                          // total: 192 bytes
```

| Field | Purpose |
| --- | --- |
| `validator` | The QBFT validator whose seal authenticates the current block. Updated on every epoch rotation. |
| `clprService` | The peer-side CLPR service contract. Used as the account-proof target. |
| `codeHash` | The peer service's `keccak256(code)`. Pinning this defends against a proof targeting a different contract at the same address. |
| `epochLength` | Number of blocks per QBFT epoch (fixed at channel establishment). |
| `epochNumber` | The epoch the trust anchor currently covers. Incremented on each rotation. |
| `channelId` | The local channel ID, seeded at `verifyConfig` time. Used to derive storage slot keys on the peer's chain and carried unchanged through every rotation. |

Reverts:
- `InvalidTrustAnchor()` — `trustAnchor.length != 192`.

## Payload shape

`proofBytes` is a single RLP list of **5** items (or **7** when the bundle carries an endpoint-manifest update — items 5 and 6 below):

| Index | Item | Notes |
| --- | --- | --- |
| 0 | Current block header | RLP list of 15–22 fields; field 3 = `stateRoot`, field 8 = `blockNumber`, field 12 = `extraData` (byte-string wrapping the inner QBFT extraData RLP). |
| 1 | Epoch block headers | RLP list of zero or more block headers. Each must fall on an epoch boundary (`blockNumber == (trustAnchorEpoch + i + 1) * epochLength`). May be empty (no rotation). |
| 2 | Account proof | RLP-encoded MPT proof for `clprService` against `header.stateRoot`. |
| 3 | Storage proof | RLP list of **5 or 6** entries, each a 2-tuple `[slotKey32, proofNodes]` (no value field: the proven value is read from the Merkle leaf) (five Channel slots +1/+2/+4/+5/+16; sixth = last-message running hash when the bundle carries messages). |
| 4 | Bundle content | Byte-string containing a protobuf-encoded `ClprBundleContent`. |
| 5 | Manifest storage proof | *(7-item shape only)* Single-entry storage proof of the peer service's endpoint-manifest commitment slot (18). |
| 6 | Manifest preimage | *(7-item shape only)* `ClprEndpointManifest` protobuf bytes; `keccak256` must equal the proven commitment. |

Reverts:
- `InvalidPayloadShape()` — top-level list ∉ {5, 7} items.
- `InvalidStorageProofShape()` — storage proof entries ∉ {5, 6} *(from ClprEvmBundleVerifier)*. Entry shape is validated while the list is indexed, so a malformed entry reverts `InvalidStorageEntry()` before the count is checked.
- `InvalidHeader()` — a header's field count is outside [15, 22], or an epoch header's block number does not equal the expected epoch boundary.

## verifyBundle

Signature:
```solidity
function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor)
  external view
  returns (
    ClprTypes.QueueMetadata memory metadata,
    bytes[] memory messagePayloads,
    bytes memory newTrustAnchor,
    bytes memory newTrustAnchorId
  )
```

Processing steps:

1. **Decode trust anchor** — `(validator, clprService, codeHash, epochLength, trustAnchorEpoch, channelId)` via `abi.decode`. Reverts `InvalidTrustAnchor()` if length ≠ 192.

2. **Decode top-level payload** — `RLP.decodeList(proofBytes)`, enforce exactly 5 items.

3. **Process epoch block headers** (payload[1]) — for each header in the list:
   - Require field count ≥ 15.
   - Require `blockNumber == (trustAnchorEpoch + i + 1) * epochLength`.
   - Verify the QBFT seal via `ClprQbftSeal.verify(MIN_COMMITTED_SEALS, header, validator)`.
   - Extract the next validator from the epoch header's `extraData` (field 12): decode as 5-item list `[vanity, validators[], vote, round, seals[]]`; require `validators.length == 1`; update `validator = validators[0]`.

4. **Verify the current block header** (payload[0]):
   - Require field count ∈ [15, 22].
   - Extract `stateRoot = header[3]`.
   - Verify the QBFT seal via `ClprQbftSeal.verify(MIN_COMMITTED_SEALS, header, validator)`.
   - Compute `currentEpoch = blockNumber / epochLength`; require `currentEpoch == trustAnchorEpoch + epochHeaders.length`. Reverts `EpochMismatch()`.

5. **Verify the account proof** (payload[2]):
   - `ClprEvmStateProof.verifyAccountFields(payload[2], stateRoot, clprService)` walks the MPT to the account leaf and decodes `(storageRoot, accountCodeHash)` in place.
   - Require `accountCodeHash == codeHash`. Reverts `CodeHashMismatch()`.

6. **Verify the storage proof** (payload[3]) — see [Storage layout](#storage-layout).

7. **Decode bundle content** (payload[4]):
   - `RLP.readBytes(payload[4])` yields the protobuf bytes.
   - Two-pass scan over field 2 (repeated LEN `ClprMessagePayload`): pass 1 counts, pass 2 collects. All other fields are skipped.

8. **Trust-anchor rotation** — if `epochHeaders.length > 0`:
   - `newTrustAnchor = abi.encode(validator, clprService, codeHash, epochLength, currentEpoch, channelId)`
   - `newTrustAnchorId = abi.encodePacked(currentEpoch)` (big-endian uint64)
   - Otherwise both are empty (no rotation).

9. Return `(metadata, messagePayloads, newTrustAnchor, newTrustAnchorId, abi.encodePacked(clprService))`.

Reverts and failure modes:

| Selector | Cause |
| --- | --- |
| `InvalidTrustAnchor()` | Trust anchor length ≠ 192. |
| `InvalidPayloadShape()` | Top-level list ∉ {5, 7} items. |
| `InvalidStorageProofShape()` | Storage proof entry count ∉ {5, 6}, checked after the entries are indexed (a malformed entry reverts `InvalidStorageEntry()` first). *(from ClprEvmBundleVerifier)* |
| `InvalidHeader()` | Header field count outside [15, 22], or epoch header block number wrong. |
| `EpochMismatch()` | Current block's epoch ≠ `trustAnchorEpoch + epochHeaders.length`. |
| `EmptyValidator()` | An epoch header's `validators[]` list is empty. |
| `MultiValidatorNotSupported()` | An epoch header's `validators[]` list has more than one entry. |
| `CodeHashMismatch()` | Proven account `codeHash` ≠ trust-anchor `codeHash`. |
| `InvalidExtraData()` | QBFT extraData inner list ≠ 5 items. *(from ClprQbftSeal)* |
| `WrongSealCount(got)` | Committed seals count < `MIN_COMMITTED_SEALS`. *(from ClprQbftSeal)* |
| `SealLengthMismatch(got)` | A committed seal is not 65 bytes. *(from ClprQbftSeal)* |
| `SealRecoverFailed()` | `ecrecover` returned `address(0)`. *(from ClprQbftSeal)* |
| `ValidatorSealNotFound(expected)` | None of the recovered sealers matches the expected validator. *(from ClprQbftSeal)* |
| `InvalidStorageProof()` | The storage proof item is not an RLP list filling its range. *(from ClprEvmStateProof)* |
| `InvalidStorageEntry()` | A storage entry is malformed: not a non-empty 2-item list `[slotKey, proofNodes]`, slot field not a scalar of at most 32 bytes, proof field not a list ending at the entry's end, or a leaf value that is not a byte-string envelope around a scalar filling it. Every entry is validated up front, so this fires regardless of entry order. *(from ClprEvmStateProof)* |
| `InvalidAccount()` | The account leaf is not a byte-string envelope around a 4-item list `[nonce, balance, storageRoot, codeHash]` of byte-string fields that fills it. *(from ClprEvmStateProof)* |
| `SlotNotProven(slot)` | No storage entry carries the expected slot key. *(from ClprEvmStateProof)* |
| `MPTEmptyProof()` | The proof list carries no nodes. *(from MerklePatriciaProof)* |
| `MPTInvalidNode()` | The proof container or a node has the wrong shape: not a list filling its range, a node envelope that is a list, a node that is neither a 2- nor a 17-item list, or a path item that is a list. (A hash-valid node that is an empty list reverts `RlpCursorOutOfBounds()` from the first item read instead.) *(from MerklePatriciaProof)* |
| `MPTInvalidHashRef()` | A node's `keccak256` differs from the hash its parent — or the root — committed to. *(from MerklePatriciaProof)* |
| `MPTInvalidPathPrefix()` | A leaf/extension path is empty, has a prefix nibble above 3, or an even-length path with a non-zero padding nibble. *(from MerklePatriciaProof)* |
| `MPTInlineNodeUnsupported()` | A child reference is not a 32-byte hash (an inline node, or a list). *(from MerklePatriciaProof)* |
| `MPTKeyMismatch()` / `MPTKeyAbsent()` | The account proof (strict walk) leaves the key's path / reaches an empty child: the service account is not in the trie under `stateRoot`. Storage walks are lenient — an absent slot reads as zero. *(from MerklePatriciaProof)* |
| `MPTProofEndedEarly()` | The proof ran out of nodes before the key was resolved. *(from MerklePatriciaProof)* |
| `RlpCursorOutOfBounds()` / `RlpCursorUnexpectedList()` / `RlpCursorScalarTooLong()` | An RLP item inside a proof or entry overruns its range; a list where a byte string was expected (the contract-mode validator-source item, see `qbft-contract-mode.md` §4); a scalar longer than 32 bytes where a `bytes32`/uint is expected (a storage leaf scalar, an account `storageRoot`/`codeHash`). *(from RlpCursor)* |
| `RLPInvalidEncoding()` | Malformed RLP in the payload/config/header decodes that still use the OZ library. *(from OZ RLP library)* |

## Storage layout

The storage proof proves five mandatory slots derived from the `channelId` stored in the trust anchor, plus an optional sixth for outbound message integrity.

**Slot derivation:**
```
cBase = keccak256(abi.encode(channelId, CHANNELS_BASE_SLOT))
// where CHANNELS_BASE_SLOT = 17 (_channels mapping on the peer chain)
```

| Entry # | Slot key | Struct field | Extracted values |
| --- | --- | --- | --- |
| 0 (mandatory) | `cBase + 1` | `Channel` slot+1 | `state = uint8(value >> 160)`, `nextMessageId = uint64(value >> 168)` |
| 1 (mandatory) | `cBase + 2` | `Channel` slot+2 | `receivedMessageId = uint64(value >> 64)` |
| 2 (mandatory) | `cBase + 4` | `Channel.sentRunningHash` | `sentRunningHash = value` |
| 3 (mandatory) | `cBase + 5` | `Channel.receivedRunningHash` | `receivedRunningHash = value` |
| 4 (mandatory) | `cBase + 16` | `Channel.endpointManifestVersion` | `endpointManifestVersion = uint64(value)` |
| 5 (optional)  | derived from `nextMessageId` | `MessageValue.runningHashAfterProcessing` | verified but not surfaced |

The optional 6th entry (present when the bundle carries outbound messages) binds the last message's running hash:
```
qBase   = keccak256(abi.encode(channelId, MESSAGE_QUEUES_BASE_SLOT))
msgBase = keccak256(abi.encode(uint64(nextMessageId - 1), qBase))
slot    = msgBase + 1   // MessageValue.runningHashAfterProcessing
```

`verifyProvenSlots` in `ClprEvmStateProof` accepts entries in any order — it matches each expected slot key against the entry's `slotKey` field. Relays SHOULD emit entries in the order the verifier derives its expected slots (the five Channel slots, then the message slot): the matcher keeps a rotating cursor, so ordered entries are found in one probe each, while a disordered layout still verifies but costs the sender O(N²) scanning gas.

> **Note.** Slot packing (`state` and `nextMessageId` packed into `Channel` slot+1 above the 20-byte `address verifier`) mirrors the Solidity `ClprTypes.Channel` struct storage layout. Any change to the struct order on the peer chain requires a corresponding update here.

## verifyConfig

Signature:
```solidity
function verifyConfig(bytes calldata configProofBytes, bytes32 channelId)
  external view
  returns (
    string memory chainId,
    bytes memory serviceAddress,
    uint96 peerConfigNanos,
    ClprTypes.Throttles memory throttles,
    bytes memory initialTrustAnchor,
    bytes memory initialTrustAnchorId,
    ClprTypes.Endpoint[] memory seedEndpoints
  )
```

`configProofBytes` is an RLP list of exactly **10** fields. The block header's QBFT seal is verified — `verifyConfig` is authenticated.

`channelId` is supplied by `ChannelLogic._createChannel` (which already holds it before calling `verifyConfig`) and embedded into the returned `initialTrustAnchor`. `ChannelLogic` independently validates it via `_deriveChannelId` immediately after this call returns.

**configProof field layout:**

| Index | Content | Usage |
| --- | --- | --- |
| 0 | Validator address (20 bytes) | Seal verification target; embedded in trust anchor via field 6. |
| 1 | Service address (bytes) | Returned as `serviceAddress`; embedded in trust anchor via field 6. |
| 2 | Code hash (bytes32) | Part of format; embedded in trust anchor via field 6. |
| 3 | Chain ID (bytes/string) | Returned as `chainId`. |
| 4 | Peer config timestamp (uint256) | Returned as `peerConfigNanos`. |
| 5 | Throttles (RLP list of 7 uint256) | Returned as `throttles`. |
| 6 | Trust anchor RLP `[validator, service, codeHash]` | Decoded and re-encoded with `epochLength`, `epochNumber`, `channelId` appended to form `initialTrustAnchor`. |
| 7 | Trust anchor ID (bytes) | Present in format; ignored — `initialTrustAnchorId` is derived as `abi.encodePacked(epochNumber)`. |
| 8 | Latest epoch block header (RLP) | QBFT seal verified against validator (field 0); `epochNumber = blockNumber / epochLength`. |
| 9 | Epoch length (uint256) | Stored in trust anchor. |

`initialTrustAnchorId` is returned as `abi.encodePacked(epochNumber)` (big-endian uint64).

`seedEndpoints` is always empty — the configProof format does not carry endpoints.

Reverts:
- `InvalidPayloadShape()` — `configProofBytes` is empty.
- `"configProof: wrong field count"` — top-level list ≠ 10 items.
- `"configProof: no header"` — header at field 8 has fewer than `MIN_BLOCK_HEADER_FIELDS` (15) fields.
- `"configProof: wrong throttle field count"` — throttles list at field 5 ≠ 7 items.
- `"trustAnchor: expected 3 fields"` — RLP trust anchor at field 6 ≠ 3 items.
- Seal verification errors from `ClprQbftSeal` (see error table above).

## Test fixture

A self-contained happy-path fixture lives at `test/verifiers/evm/qbft/fixtures/` (generated by `tools/qbft-proof-generator/`, gitignored):

| File | Content |
| --- | --- |
| `bundlePayload.hex` | Full RLP-encoded proof bundle captured from a single-validator Besu QBFT node, with the 5-entry (ACK-only) channel storage proof. |
| `trustAnchor.hex` | `RLP([validator20, service20, codeHash32])`. The test re-encodes this with synthetic `epochLength` and `epochNumber` appended to produce the 128-byte ABI form. |
| `configProof.hex` | RLP-encoded 10-field configProof for integration tests. |
| `serviceAddress.hex` | Expected service address for assertion in `test_verifyConfig_success`. |

The test loader (`_readHexFile`) reads via `vm.readFile`, strips trailing CRLF, and parses with `vm.parseBytes`. Foundry's `fs_permissions` (in `foundry.toml`) grants read access to `test/verifiers/evm/qbft/fixtures`.

The negative-path tests (`test_revertWhen_*`) build minimal synthetic payloads in-test (see `test/helpers/QbftSyntheticProofs.sol`); the happy paths run on synthetic proofs too, so the suite does not depend on the generated fixture. Fixture-dependent tests skip when the fixture is absent or its shape is stale (outer payload ∉ {5, 7} items, storage proof ∉ {5, 6} entries).

## File map

| Path | Role |
| --- | --- |
| `src/verifiers/evm/qbft/QBFTVerifier.sol` | The verifier contract. |
| `src/libraries/proof/evm/ClprEvmStateProof.sol` | Account-proof and storage-proof verification; `verifyAccountFields`, `verifyProvenSlots`. |
| `src/libraries/proof/qbft/ClprQbftSeal.sol` | QBFT committed-seal verification; `verify` checks ≥ N seals and finds the expected validator among the recovered signers. |
| `src/libraries/proof/evm/MerklePatriciaProof.sol` | MPT walker (`requireValueRange`, `valueRangeOrZero`), over `RlpCursor`. |
| `src/libraries/codec/ClprProtobufHelpers.sol` | Protobuf varint / length-delimited helpers used for bundle content decoding. |
| `lib/openzeppelin-contracts/contracts/utils/RLP.sol` | OZ RLP decode / encode. |
| `test/verifiers/evm/qbft/QBFTVerifier.t.sol` | Forge test suite. |
| `test/verifiers/evm/qbft/fixtures/` | Generated Besu QBFT proof fixture (gitignored). |
| `test/integration/IntegrationQBFT.t.sol` | End-to-end lifecycle test against the fixture (skips when fixture is stale). |
