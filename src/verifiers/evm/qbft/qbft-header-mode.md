# QBFT validators - Header mode

A QBFT chain in header mode lists its validator set in every block header. The Header-mode QBFT
verifier reads the validator set from `extraData` of the header. Nothing else is needed to know who
may seal a block.

The verifier supports:

- many validators, with a real quorum,
- set changes at **any block**, crossed by a chain of headers,
- **one member per change**, as Besu applies it: every accepted header may add or remove one
  member, and must be sealed by (almost) a quorum of the set the verifier already trusts.

One channel keeps one mode for its full life. The trust anchor starts with a mode byte; Header mode
is mode `0`.

## 1. How this mode works

Every block header carries the full validator list in `extraData`:

```
extraData = RLP([vanity(32), validators[], vote, round, committedSeals[]])
```

Two fields matter:

- `validators[]` — the set of **this** block. Besu uses it to seal it.
- `committedSeals[]` — the seals of **this** block, made by the set that was current before it.

```mermaid
flowchart LR
  A["block N-1<br/>validators[] = S_old<br/>seals by: S_old"] --> B["block N<br/>vote applied<br/>validators[] = S_old<br/>seals by: S_old"]
  B --> C["block N+1 (change block)<br/>validators[] = S_new<br/>seals by: S_new"]
```

A **rotation** is a vote that adds or removes a member. Besu applies at most **one** change per
block. So two neighbouring headers list sets that differ by at most one member.

The verifier does not check every block. It checks the headers the relay sends: the **hops** and
the **current block**. So the relay must send one hop for every change block: each accepted header
may move the trusted set by one member, and it must be sealed by the set that was trusted before it.

## 2. The rule for a header

For a header `H` with validator list `V_H` and seals `seals_H`, while the verifier trusts the set
`T` of size `n`, with quorum `q = ceil(2n / 3)`:

1. **One change at most.** `V_H` is `T`, or `T` plus one member, or `T` minus one member.
   Besu applies one vote per block, so two neighbouring headers never differ by more.
2. **The old set sealed it.** Count the distinct members of `T` among the signers of `H`:

   | Change | Signers of `T` required |
   |---|---|
   | none (`V_H == T`) | `q` |
   | one member removed | `q − 1`, and at least 1 |
   | one member added, and the new member signed | `q − 1`, and at least 1 |
   | one member added, and the new member did **not** sign | `q` |

3. **Own quorum.** At least `ceil(2·|V_H| / 3)` distinct members of `V_H` signed `H`.
   This is the QBFT finality rule, the same one Besu applies.

```mermaid
flowchart TB
  H["header H<br/>validators[] = V_H<br/>seals"] --> R1{"V_H differs from T<br/>by at most one member?"}
  R1 -->|no| X1["revert TooManySetChanges"]
  R1 -->|yes| R2{"distinct signers in T<br/>>= q, or q − 1 with one change<br/>(added member must sign)?"}
  R2 -->|no| X2["revert TrustLinkNotReached"]
  R2 -->|yes| R3{"distinct signers in V_H<br/>>= ceil(2|V_H|/3) ?"}
  R3 -->|no| X3["revert QuorumNotReached"]
  R3 -->|yes| OK["accept H<br/>T := V_H"]
```

When `V_H == T` the three checks collapse into the plain quorum check.

**Why rule 1 exists.** Rule 3 alone proves that *some* set finalized `H`. It does not prove that this
set is the real successor of `T`: an attacker can invent a set and seal a header with it. With rule
1 an accepted header can move the trusted set by one key only, and rule 2 requires that almost a
quorum of the keys the verifier already trusts vouched for it. An attacker who does not hold those
keys cannot move the set at all; one who holds a few cannot jump to an invented set in one step.

**Why `− 1`.** A change block is sealed around the change itself. When a member leaves, the seals
may miss exactly that member. When a member joins, the newcomer's seal may stand in for one old
seal. In both cases a full `q` of the old set is not always present, so one signer fewer keeps every
legitimate change block acceptable.

**Why the newcomer must sign to get the `− 1`.** With `q − 1` old signers the header is one vote
short of an old quorum. The newcomer's own seal is that vote: the header then carries a quorum of
the new list, and all of those signers but one are keys the verifier already trusts. Without the
newcomer's seal there is no reason to accept one vote fewer, so the full old quorum is required.

```mermaid
flowchart LR
  subgraph J["one member joins"]
    T1["T = {a, b}<br/>q = 2"] -->|"a signed (q − 1 = 1)<br/>c signed (the newcomer) ✓"| H1["H lists {a, b, c}<br/>sealed by a, c"]
  end
  subgraph L["one member leaves"]
    T2["T = {a, b, c, d}<br/>q = 3"] -->|"a, b signed (q − 1 = 2) ✓"| H2["H lists {a, b, c}<br/>sealed by a, b"]
  end
```

| n | q | q − 1 |
|---|---|---|
| 1 | 1 | 1 |
| 2 | 2 | 1 |
| 3 | 2 | 1 |
| 4 | 3 | 2 |
| 7 | 5 | 4 |
| 10 | 7 | 6 |
| 21 | 14 | 13 |

A set of one, two or three has no fault tolerance: one old key is enough to move it. QBFT itself
gives such sets no fault tolerance either.

## 3. Who builds what

The relay builds the **proof bytes** for each bundle. The relay also builds the **config proof** one
time, at channel setup. The verifier builds and stores the **trust anchor**.

```mermaid
sequenceDiagram
  participant R as Relay
  participant S as ClprService
  participant V as Verifier

  Note over R,V: Channel setup (once)
  R->>S: completeChannel(configProof)
  S->>V: verifyConfig(configProof)
  V-->>S: initialTrustAnchor + initialTrustAnchorId
  S->>S: store the anchor on the channel

  Note over R,V: Every bundle
  R->>S: submitBundle(proofBytes)
  S->>V: verifyBundle(proofBytes, storedAnchor)
  V-->>S: newTrustAnchor + newTrustAnchorId (rotation)
  S->>S: store the new anchor
```

**Relay rule:** track two things. First, the anchor **id** (`newTrustAnchorId`): a **block number**
(8 bytes, big-endian). Use it as a cut-off when you select change blocks for the next proof.
Second, the **member list at that block**: the anchor stores only a hash of it, and every bundle
must carry the full list. Read the list from `extraData.validators` of the anchor block header.

## 4. The trust anchor (the verifier remembers this)

The anchor is an `abi.encode` value. Word 0 is always the mode. The anchor stores **one hash of the
trusted set**, not the list. A list of tens of validators in storage would be too expensive. The
**relay sends the full list in every bundle**, and the verifier compares its hash with the anchor.

```mermaid
flowchart LR
   subgraph EP["the endpoint sends, in every bundle"]
      L["trusted member list (sort + deduplicated)"]
   end
   subgraph VF["the verifier"]
      A["trust anchor (storage)<br/>setCommitment = one bytes32"]
      C{"keccak256 of the<br/>sorted list == setCommitment?"}
   end
   L --> C
   A --> C
   C -->|yes| U["use the list as the trusted set"]
   C -->|no| R["revert WrongSetCommitment"]
```

`setCommitment = keccak256(abi.encode(sortedMembers))`. One flat hash. The seals are ECDSA, so the
verifier needs **every** member for the membership test and the set size for the quorum. With the
full list always present, one hash is cheaper than member proofs.

| Word | Field | Type | Meaning |
|------|-------|------|---------|
| 0 | mode | uint8 | 0 = Header |
| 1 | setCommitment | bytes32 | keccak256 of the sorted, deduped trusted set |
| 2 | codeHash | bytes32 | the CLPR service code hash. Pins the account |
| 3 | anchorBlockNumber | uint64 | the block whose header listed this set |

Encoded as `abi.encode(uint8, bytes32, bytes32, uint64)`, 128 bytes. The anchor has a fixed size,
for any set size.

## 5. The bundle proof bytes (the relay builds this)

The bundle proof is one RLP list. It has 7 fields.

```mermaid
flowchart TB
  P["bundle proof<br/>RLP list"] --> F0["0: current block header"]
  P --> F1["1: validator source"]
  P --> F2["2: service account proof"]
  P --> F3["3: channel storage proof"]
  P --> F4["4: bundle content (protobuf)"]
  P -. optional .-> F5["5: manifest storage proof"]
  P -. optional .-> F6["6: manifest preimage"]
```

| Field | Name | What it holds |
|-------|------|---------------|
| 0 | current block header | the block to verify. Holds the state root, the block number, and in `extraData` the validator list and the seals |
| 1 | validator source | the trusted member list, then the hops |
| 2 | service account proof | proves the CLPR service account under the block state root |
| 3 | channel storage proof | proves the channel slots under the service storage root |
| 4 | bundle content | the protobuf messages |
| 5 | manifest storage proof | optional |
| 6 | manifest preimage | optional |

### Field 1: the trusted set and the hops

Field 1 is an RLP list of 2 items.

| Item | Name | What it holds |
|------|------|---------------|
| 0 | trusted set | the full member list behind the anchor's `setCommitment` (sort + dedup, the hash must equal it). An RLP list of non-zero 20-byte address items, each the fixed 21-byte item Besu writes. **May be an empty list** when no rotation is crossed, see below |
| 1 | hops | a list of block headers. Empty when no rotation occurred |

A **hop** is one block header. Nothing else. The header's `extraData` holds both the new set
(`validators[]`) and the seals that prove it.

```mermaid
flowchart TB
  F1["field 1<br/>RLP list of 2"] --> TS["0: trusted set<br/>list of 20-byte addresses"]
  F1 --> HOPS["1: hops[]"]
  HOPS --> H1["header of block 141<br/>validators[] = set 2"]
  HOPS --> H2["header of block 305<br/>validators[] = set 3"]
```

**Skipping the trusted set.** When no rotation is crossed, the current header already lists the
trusted set in its own `extraData.validators`. The relay may then send item 0 as an **empty list**
(`0xc0`) and save the calldata. The verifier takes the current header's list instead, sorts it, and
checks its hash against the anchor exactly as it would check a submitted list. If the header lists a
different set, the hash does not match and the bundle reverts `WrongSetCommitment`. So the shortcut
is only valid with an empty hop list: a bundle with hops has a current header that lists the set
**after** the rotation, and that set never hashes to the anchor.

```mermaid
flowchart LR
  I0{"field 1 item 0"} -->|"list of addresses"| S["sort + hash the submitted list"]
  I0 -->|"empty list 0xc0"| H["sort + hash the current header's<br/>extraData.validators"]
  S --> C{"== anchor.setCommitment ?"}
  H --> C
  C -->|yes| T["trusted set"]
  C -->|no| X["revert WrongSetCommitment"]
```

An empty **byte string** (`0x80`) is not the shortcut: it is a malformed list and reverts
`InvalidTrustedSet`.

**Rules for the hops:**

1. Put the hops in ascending block order. No repeats.
2. Include only hops with a block number after the anchor id.
3. Each hop must pass the rule of §2 against the set trusted at that point.
4. Include a hop for **every** change block. A hop moves the trusted set by one member at most, so
   two changes need two hops. A header that lists the trusted set again is a valid hop too; it only
   advances the anchor block.
5. If no change occurred, send an empty hop list. This is the normal case. You may then also send
   the trusted set as an empty list (see above).

**How to detect a change.** Compare `extraData.validators` of two consecutive headers. When they
differ, the later block is a change block. `eth_getBlockByNumber` returns the header; Besu also
offers `qbft_getValidatorsByBlockNumber`.

**Which header to send for a change.** Send the header whose `validators[]` already lists the new
set: the change block `N` itself. Its seals come from the set around the change, so rule 2 is
satisfied by the previous set (`q − 1` of it, plus the newcomer when one joined), and rule 3 counts
the new list.

```mermaid
flowchart LR
  T["trusted set T"] -->|"rule 1: V_N = T ± one member<br/>rule 2: q − 1 of T sealed N"| N["change block N<br/>validators[] = V_N"]
  N -->|"rule 3: 2/3 of V_N sealed N"| T2["trusted set := V_N"]
```

## 6. The config proof bytes

The config proof is one RLP list of 6 fields. It creates the first trust anchor. It is passed to
`verifyConfig(configProofBytes, channelId, endpointManifestProofBytes)`.

```mermaid
flowchart TB
  CP["config proof<br/>RLP list of 6"] --> F0["0: service address"]
  CP --> F1["1: chain id"]
  CP --> F2["2: peer config nanos"]
  CP --> F3["3: throttles (list of 5 or 7)"]
  CP --> F4["4: trust anchor descriptor (byte string)"]
  CP --> F5["5: block header (list of 15-22)"]
```

### 6.1 Top-level fields

| Field | Name | RLP type | Size | Value |
|-------|------|----------|------|-------|
| 0 | service address | byte string | 20 bytes | the peer CLPR service address |
| 1 | chain id | byte string | any | UTF-8, for example `eip155:1` |
| 2 | peer config nanos | scalar | ≤ 12 bytes (uint96) | the config time |
| 3 | throttles | list | 5 or 7 scalars | see 6.2 |
| 4 | trust anchor descriptor | byte string | any | wraps the RLP list of 6.3 |
| 5 | block header | list | 15 to 22 items | see 6.4 |

Any other count reverts `InvalidProofPayloadShape`.

### 6.2 Field 3: throttles

| Item | Name | Type | Present |
|------|------|------|---------|
| 0 | maxMessagesPerBundle | uint32 | always |
| 1 | maxMessagePayloadBytes | uint64 | always |
| 2 | maxGasPerMessage | uint64 | always |
| 3 | maxQueueDepth | uint32 | always |
| 4 | maxSyncBytes | uint64 | always |
| 5 | maxLocalEndpoints | uint32 | 7-item list only; 0 otherwise |
| 6 | maxPeerEndpoints | uint32 | 7-item list only; 0 otherwise |

A 5-item list is the legacy shape. Any other count reverts `InvalidConfigThrottleFieldCount`.

### 6.3 Field 4: the trust anchor descriptor

Field 4 is a byte string. Its bytes are an RLP list of 2 items:

```
RLP([mode, codeHash])
```

| Item | Name | RLP type | Size | Value |
|------|------|----------|------|-------|
| 0 | mode | scalar | 1 byte | `0`. Any other value reverts `UnknownValidatorMode` |
| 1 | codeHash | byte string | 32 bytes | `keccak256` of the peer service code. Pinned in the anchor |

Any other item count reverts `InvalidTrustAnchorFields`.

### 6.4 Field 5: the block header

A Besu block header as the node returns it: an RLP list of 15 to 22 items. The verifier reads three
of them.

| Index | Name | Used for |
|-------|------|----------|
| 3 | stateRoot | not used at config time (no storage is proven here) |
| 8 | number | `anchorBlockNumber`, and the anchor id |
| 12 | extraData | byte string wrapping the QBFT list below |

`extraData` unwraps to an RLP list of 5 items:

| Item | Name | RLP type | Value |
|------|------|----------|-------|
| 0 | vanity | byte string, 32 bytes | ignored |
| 1 | validators | list of non-zero 20-byte addresses | **the initial trusted set** |
| 2 | vote | list | ignored |
| 3 | round | scalar | ignored |
| 4 | committedSeals | list of 65-byte strings | checked against item 1 |

```mermaid
flowchart LR
  H["header (field 5)"] --> X["extraData (index 12)"]
  X --> V["validators[]<br/>initial set"]
  X --> S["committedSeals[]"]
  S --> Q{"distinct signers in validators[]<br/>>= ceil(2N/3) ?"}
  V --> Q
  Q -->|yes| TA["anchor:<br/>setCommitment = hash(sorted validators[])<br/>anchorBlockNumber = header.number"]
  Q -->|no| X1["revert QuorumNotReached"]
```

The config header is trusted by the channel creator. The quorum check on it only proves the header
is self-consistent: the set it lists did seal it.

### 6.5 What comes out

| Output | Value |
|--------|-------|
| channelContext | `abi.encode(channelId, serviceAddress)` |
| chainId | field 1 as a string |
| serviceAddress | field 0 |
| peerConfigNanos | field 2 |
| throttles | field 3 decoded |
| initialTrustAnchor | 128 bytes, see §4: mode 0, hash of the sorted set, codeHash, header number |
| initialTrustAnchorId | header number, 8 bytes big-endian |
| endpointManifest | from `endpointManifestProofBytes`, see 6.6 |

### 6.6 The endpoint manifest proof (second argument)

Empty bytes mean "no manifest yet" and return the uninitialised manifest at version 0. Otherwise:

```
RLP([blockHeader, accountProof, manifestStorageProof, manifestPreimage])
```

| Item | Name | Value |
|------|------|-------|
| 0 | blockHeader | a header sealed by a quorum of the initial set (rule 3 of §2 only, with `V_H` = the set listed in field 5) |
| 1 | accountProof | the peer service account under `blockHeader.stateRoot` |
| 2 | manifestStorageProof | one entry: the manifest commitment slot |
| 3 | manifestPreimage | the `ClprEndpointManifest` protobuf; its `keccak256` must equal the proven slot |

## 7. How the verifier checks a bundle

```mermaid
flowchart TB
  A["decode anchor<br/>setCommitment, codeHash, anchorBlockNumber"] --> A2["open the commitment:<br/>sort + hash the submitted list<br/>(or the current header's list when item 0 is empty),<br/>must equal setCommitment"]
  A2 --> B["for each hop:<br/>block number must ascend past the anchor,<br/>one change at most (rule 1),<br/>q − 1 or q of the trusted set (rule 2),<br/>2/3 of the hop's own list (rule 3),<br/>trusted set := the hop's list"]
  B --> C["current block:<br/>the same rule against the final trusted set"]
  C --> D["read the set from the current header:<br/>validators[] in extraData"]
  D --> E["verify the service account<br/>pin the codeHash -> storage root"]
  E --> F["verify the channel slots,<br/>decode the bundle content"]
  F --> G["rotate: if validators[] differs from the anchor,<br/>store it, id = current block number"]
```

**Quorum** means: recover every seal, keep the signers that are in the set, and count the distinct
ones. The count must be at least `ceil(2N/3)`. This matches Besu.

**The change** is found by one merge pass over the two sorted lists: members only in the header's
list were added, members only in the trusted set were removed. More than one in total reverts
before any seal is recovered.

**Recover once, count twice.** Each seal is one `ecrecover`. Recover every seal once, then count the
recovered addresses against both sets, and note whether the added member is among them. Rules 2
and 3 must not pay for the seals twice. When the lists are equal, only one set is counted.

The current header's `validators[]` becomes the new trusted set whenever it differs from the anchor.
One bundle can cross many rotations, one hop for each change block.

## 8. What can go wrong

| Selector | Cause |
|---|---|
| `WrongSetCommitment(got, expected)` | the submitted list does not hash to the anchor; or item 0 was empty and the current header's list does not (a rotation was crossed without hops, or with hops but without the trusted set) |
| `TooManySetChanges(added, removed)` | rule 1 failed: the header's list differs from the trusted set by more than one member |
| `TrustLinkNotReached(got, required)` | rule 2 failed: too few members of the trusted set sealed the header |
| `QuorumNotReached(got, required)` | rule 3 failed on a hop or on the current block |
| `HandoffHeaderNotAscending(got, lastSeen)` | hops out of order, or a hop at or before the anchor block |
| `CurrentHeaderBehindWalk(got, lastSeen)` | the current block is not after the last hop |
| `EmptyValidatorSet()` | a header lists no validators |
| `InvalidHeader()` | a header's `validators[]` item is not a list of 20-byte addresses |
| `InvalidTrustedSet()` | bundle field 1 item 0 is not a list of 20-byte addresses (an empty byte string included) |
| `InvalidPayloadShape()` | bundle field 1 is not a list of 2 items, or a hop is not a header |

Errors from the seal parser, the service account proof and the channel proof are listed in
`qbft-verifier.md`.

## 9. A mode change on the chain is not supported

A chain can move between header mode and a validator contract at some block. Besu calls this a
transition. There is no on-chain proof of a transition. **A channel never changes its verifier.**
If the chain makes a transition:

1. Stop the bundles on the old channel.
2. Establish a new channel, with a config proof for the new mode.
3. Continue on the new channel.

**Relay rule:** one channel keeps one mode for its full life. Never send a mode that differs
from the anchor mode.
