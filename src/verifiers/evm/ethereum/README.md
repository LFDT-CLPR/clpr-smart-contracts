# EthMainnetVerifier

> **Source**: [EthMainnetVerifier.sol](./EthMainnetVerifier.sol)
> **Interface**: [IClprVerifier.sol](../../interfaces/IClprVerifier.sol)

---

## 1. The big picture

The CLPR protocol needs to **trustlessly verify state from a peer Ethereum chain** entirely on-chain. `EthMainnetVerifier` answers: *"prove to me that this bundle of cross-chain messages actually existed in the peer CLPR service contract's storage on Ethereum mainnet."*

It is a real **consensus-layer light client**: it builds a chain of cryptographic trust from a sync-committee BLS signature down to individual storage slots.

```mermaid
flowchart LR
    A["Trust anchor (window)\n{ current, next } aggregate +\ncommittee Merkle root, period"] --> B["Attested beacon\nblock header\n(bodyRoot, stateRoot)"]
    B --> C["SSZ branch\nexecution state_root\nin bodyRoot"]
    C --> E["Account trie (MPT)\nstorageRoot + codeHash"]
    E --> F["Storage trie (MPT)\n5 queue-metadata slots"]
    F --> G["Verified metadata\n+ message payloads"]
    B -. "rotation" .-> R["SSZ branch\nnext_sync_committee\nin stateRoot → new anchor"]
```

Each arrow is a proof the contract verifies on-chain. If any link breaks, the whole call reverts. Note there is **no EVM block header**: the execution `state_root` is proven *directly* against the beacon `bodyRoot` via SSZ.

> [!IMPORTANT]
> **All points are EIP-2537 *uncompressed*.** On-chain decompression is gas-infeasible (~22.8M for the 512 G1 pubkeys, ~49.5M for a single compressed G2 signature), so the relayer supplies uncompressed keys (the non-signers' per bundle, the full next committee at rotation) and signature; the contract only ever *compresses* (cheap) to rebuild the beacon SSZ committee root at rotation. The BLS aggregate verification is fully on-chain (EIP-2537) — see §7.

---

## 2. Differences with QBFTVerifier

Ethereum mainnet uses **Proof of Stake with sync-committee BLS signatures**, not QBFT committed seals, and it commits to its execution state through SSZ rather than an RLP block header.

```mermaid
flowchart TD
    subgraph QBFT["QBFTVerifier (Besu QBFT)"]
        direction TB
        Q1["EVM block header + extraData"] --> Q2["ECDSA committed seals"]
        Q2 --> Q3["ecrecover validator set"]
        Q3 --> Q4["≥ ⅔ validator threshold"]
    end
    subgraph ETH["EthMainnetVerifier (Ethereum mainnet)"]
        direction TB
        E1["Attested beacon header"] --> E2["Sync-committee BLS aggregate"]
        E2 --> E3["aggregateVerifyComplement (EIP-2537)"]
        E3 --> E4["SSZ branch → execution state_root"]
    end
```

The **shared** part is the bottom half: MPT account + storage proofs ([ClprEvmStateProof](../../libraries/proof/evm/ClprEvmStateProof.sol)) and the protobuf bundle-content decode. Only "how do we trust this state root?" differs.

---

## 3. Configuration & trust anchor

The **trust anchor** is a **flat packed 428-byte layout** (fixed offsets, no RLP) using the **window encoding** of [clpr-service-spec](https://github.com/hiero-hackers/CLPR-spec/blob/main/clpr-service-spec.md) §3.2: it holds a *set* of currently valid authorities — `{ current committee, next committee }` — and the verifier accepts a bundle signed by either. The 512 keys of each are **not stored**; the anchor commits to them with a keccak Merkle root ([ClprCommitteeMerkle](../../libraries/proof/beacon/ClprCommitteeMerkle.sol)):

```
gvr32 ‖ forkVersion4 ‖ channelId32 ‖ codeHash32 ‖ period8 ‖ [aggregate128 ‖ committeeRoot32] × 2
```

| Offset | Field | Bytes | Description |
|---|---|---|---|
| 0 | `genesisValidatorsRoot` | 32 | Chain-pinning root, folded into the BLS signing domain. |
| 32 | `forkVersion` | 4 | Current fork version, folded into the signing domain. Refreshed via a config update on a hard fork. |
| 36 | `channelId` | 32 | The CLPR channel this anchor authenticates. Seeded from `verifyConfig`'s `channelId`, carried through every advance, and used to derive the exact storage slots the bundle must prove. |
| 68 | `codeHash` | 32 | The `keccak256` hash of the expected contract code. |
| 100 | `period` | 8 | Sync-committee period of the **current** member, big-endian. The window covers `[period, period + 1]`. |
| 108 | `current.aggregatePubkey` | 128 | Precomputed aggregate (uncompressed EIP-2537 G1). Feeds the pairing directly at full participation. |
| 236 | `current.committeeMerkleRoot` | 32 | keccak Merkle root over the 512 uncompressed member pubkeys. Per bundle the relay supplies only the **non-signers'** keys (proof item 10), each authenticated against the *selected* member's root. |
| 268 | `next.aggregatePubkey` | 128 | Same shape as `current` — committee `i` sits at `108 + 160·i`, so selection is one offset multiply and an advance is one contiguous 160-byte copy. |
| 396 | `next.committeeMerkleRoot` | 32 | |

428 bytes means the service's per-bundle anchor SLOAD and per-advance SSTORE take 15 storage words, against ~4,110 for two committees stored as keys.

**Why the period is in the anchor.** `verifyBundle` is passed `(proofBytes, trustAnchor, channelContext)` — never `Channel.trustAnchorId`, where the period is also recorded. Nor can it be recovered from a committee: the BLS aggregate and the Merkle root are both one-way functions of the key set. Selection is a comparison, so the period has to travel inside the bytes.

### Config payload

`verifyConfig` takes an RLP list of **7 items**. Both committees are required — the anchor is a
width-2 window from the first bundle, and `next` cannot be derived on-chain:

| # | Item | Contents |
|---|---|---|
| 0 | `slot` | Beacon slot the config is taken at. `slot / 8192` becomes the window's start `period`. |
| 1 | `currentCommittee` | `[uncompressedPubkeys[512], uncompressedAgg128]` — the committee signing at `slot`. |
| 2 | `nextCommittee` | Same shape, for the following period. Must differ from `currentCommittee` (`ConfigWindowNotDistinct`); seeding one committee twice would let selection accept a signature from `period + 1` against a committee that never signed then. |
| 3 | `gvr` | Genesis validators root. |
| 4 | `forkVersion` | 4 bytes. |
| 5 | `ledgerConfiguration` | protobuf `ControlMessage`. |
| 6 | `codeHash` | Expected CLPR service code hash. |

Neither committee is verified against a beacon state root — both are trusted owner input at channel
setup. The optional endpoint-manifest proof is verified against `currentCommittee` and must attest a
header inside `period` (`ConfigManifestPeriodMismatch`).

**Why a window.** A single-authority anchor is *replaced* on rotation. Since the attested header may sit anywhere inside a period, the successor is installed early and every proof from the committee still signing on the beacon chain is rejected until the boundary — including anything already in flight. The endpoint would have to submit at the exact 27-hour boundary with nothing outstanding. With a window the outgoing committee stays valid until the chain leaves its period, so the advance is decoupled from the boundary. This mirrors Altair's [`LightClientStore`](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/), which has held both committees since the beginning.

---

## 4. Proof layout

The bundle proof is a **top-level RLP list of 11 items**:

| # | Item | Contents |
|---|---|---|
| 0 | `attestedHeader` | `[slot, proposerIndex, parentRoot, stateRoot, bodyRoot]` |
| 1 | `signatureSlot` | The slot the committee **signed at** — strictly after `attestedHeader.slot` and at most one period beyond it. Its period selects the window member, mirroring Altair's `update_signature_period`. It cannot be derived from the attested slot: the two sit in different periods for one slot per period. The bound is load-bearing — an unconstrained value is a free committee selector. |
| 2 | `syncAggregate` | `[bits(64 B), signature(256 B uncompressed G2)]` |
| 3 | `executionStateRoot` | 32-byte execution-layer state root (the SSZ leaf) |
| 4 | `executionBranch` | 9 SSZ sibling hashes (gindex 802) |
| 5 | `nextCommittee` | window-advance committee `[uncompressedPubkeys[512], uncompressedAgg128]` (128 B EIP-2537 keys), or an empty RLP **string** if absent. The contract derives the compressed form on-chain to rebuild the SSZ root. |
| 6 | `nextCommitteeBranch` | 6 SSZ siblings (gindex 87), or an empty RLP **list** if absent |
| 7 | `accountProof` | MPT account proof against `executionStateRoot` |
| 8 | `storageProof` | 4 × `[slotKey, proofNodes]` (ACK-only) or 5 (with outbound messages) against the account `storageRoot` |
| 9 | `bundleContent` | protobuf `ClprBundleContent` |
| 10 | `nonSignerProofs` | one 416-byte entry `uncompressedKey(128) ‖ 9 Merkle siblings (288)` per **clear** participation bit, in ascending index order; each is authenticated against the *selected* member's `committeeMerkleRoot`. Empty RLP list at full 512/512 participation. |

The advance pair (5 & 6) is **both-present or both-absent**.

---

## 5. Step-by-step verification flow

This is the core of [`verifyBundle`](./EthMainnetVerifier.sol):

```mermaid
flowchart TD
    START(["verifyBundle(proofBytes, trustAnchor)"]) --> A
    A["Decode trust anchor (flat 428 B)\ngvr, forkVersion, channelId, codeHash,\nperiod, { current, next } committees\n+ decode 11-item payload"] --> S2
    S2["Step 2 · beacon header\nhash_tree_root → beaconBlockRoot"] --> S2B
    S2B["Step 2b · window selection\np = period(signatureSlot)\np == anchorPeriod → current\np == anchorPeriod+1 → next\nelse SignaturePeriodOutOfWindow"] --> S3
    S3["Step 3 · BLS (EIP-2537)\nparticipants by bits ≥ ⅔\nnon-signer keys (item 10) Merkle-\nauthenticated vs the SELECTED\nmember's committeeMerkleRoot\ndomain = f(forkVersion, gvr)\nsigningRoot = sha256(root ∥ domain)\naggregateVerifyComplement(...)"] --> S4
    S4["Step 4 · execution state root\nSSZ verifyProof(stateRoot, branch,\n  bodyRoot, gindex 802)"] --> S5
    S5["Step 5 · account proof (MPT)\nverifyAccount(...) → storageRoot, codeHash\ncodeHash == EXPECTED_CODE_HASH?"] --> S6
    S6["Step 6 · storage proof (MPT)\nverifyProvenSlots(channelId slots)\n→ QueueMetadata"] --> S7
    S7["Step 7 · bundle content\nprotobuf field 2 → messagePayloads[]"] --> S8
    S8["Step 8 · window advance (optional)\nif nextCommittee present:\n  SSZ verifyProof(committeeRoot,\n    branch, stateRoot, gindex 87)\n  p == anchorPeriod → widen (no move)\n  p == anchorPeriod+1 → shift"] --> OUT
    OUT(["Returns: metadata · messagePayloads[] ·\nnewTrustAnchor · newTrustAnchorId"])

    style S3 fill:#2d1b69,color:#fff
    style S4 fill:#1b4332,color:#fff
    style S5 fill:#6b2d2d,color:#fff
    style S6 fill:#1b4332,color:#fff
    style S7 fill:#4a3728,color:#fff
    style S2B fill:#2d1b69,color:#fff
    style S8 fill:#4a3728,color:#fff
```

### Advancing the window

Let `p` be the signature slot's period. The `next_sync_committee` branch is proven against `attestedHeader.stateRoot`, so the committee it commits to is the successor of the *attested* period — while the committee that signed is chosen by the *signature* period. An advance therefore requires the two to be equal (`RotationPeriodStraddle` otherwise), which makes them one integer and rules out installing a window that never existed. Application bundles may straddle a boundary freely; only advances may not.

| Case | Effect | Returns |
|---|---|---|
| `p == anchorPeriod` | The proven committee is the one already stored as `next`. The window does not move. | **Empty** anchor. Returning bytes would satisfy `BundleLib`'s trust-anchor progress condition for free, so a zero-message no-op could be replayed as progress forever. A proven committee that *differs* reverts `WindowNextCommitteeMismatch` — two distinct state-proven successors to one period is a corrupted anchor or a chain fork, not a no-op. |
| `p == anchorPeriod + 1` | `current ← next`, `next ← proven`, `period ← p`. | The 428-byte successor anchor; `gvr`, `forkVersion`, `channelId` and `codeHash` are carried through unchanged. |

> **Endpoint note.** Because a widen returns an empty anchor, a **trust-only** widen bundle (zero
> messages, no acknowledgement progress) fails the CLPR Service's no-progress check — the endpoint
> must not submit one. A widen is only ever a side effect of a bundle that makes progress some other
> way. An advance that shifts the window does satisfy the trust-anchor progress condition on its own.

`newTrustAnchorId` is the window's **start period** as an 8-byte big-endian value — a compact, monotonic handle, not a hash of the anchor — and is empty when the window did not move. Note this is the period the chain has actually *reached*; the point-encoded predecessor reported `period + 1`, an identifier for a period that had not yet begun.

**Catch-up.** An endpoint that has missed N rotations submits N advances, each verified under the authority installed by its predecessor, so committee history cannot be skipped. Batching several advances into one bundle (permitted by §3.2) is not implemented.

---

## 6. Deep dive: key steps

### Step 3 — sync-committee BLS

The sync committee (512 validators, rotated every ~27 h) co-signs each beacon block. Verification reads the 64-byte `bits` vector, requires a **2/3 supermajority** of 512, collects the non-signers' keys from proof item 10 — each Merkle-authenticated against the selected window member's `committeeMerkleRoot` at its **committee index** (positional binding, so a relay cannot pass an arbitrary point as a "non-signer") — derives the signing domain, and verifies the aggregate signature via `aggregateVerifyComplement` (recovering the participant aggregate as `committeeAggregate − Σ(non-signers)` — cost scales with the non-signer count) over:

```
signingRoot = sha256( beaconBlockRoot ∥ domain )
domain      = 0x07000000 ∥ sha256( pad32(forkVersion) ∥ genesisValidatorsRoot )[0:28]
```

`computeSyncCommitteeDomain` and the SSZ helpers live in [ClprBeaconSsz](../../libraries/proof/beacon/ClprBeaconSsz.sol); the on-chain aggregation + pairing in [ClprBeaconBls](../../libraries/proof/beacon/ClprBeaconBls.sol) — see §7.

### Step 4 & 8 — SSZ Merkle branches

The execution `state_root` and `next_sync_committee` sit at fixed positions in SSZ binary trees. [`ClprBeaconSsz.verifyProof`](../../libraries/proof/beacon/ClprBeaconSsz.sol) walks the generalized index bit-by-bit (`sha256(left ∥ right)`):

| Leaf | Tree root | gindex | depth / index |
|---|---|---|---|
| `execution_payload.state_root` | `bodyRoot` | **802** | 9 / 290 |
| `next_sync_committee` | `stateRoot` | **87** | 6 / 23 |

The committee root is `sha256(merkleize(512 × sha256(pad64(pubkey48))) ∥ sha256(pad64(aggregate48)))` over the **compressed** 48-byte keys (the beacon-native encoding the proof commits to). The relayer ships only the **uncompressed** next committee, so `syncCommitteeRootFromUncompressed` derives each compressed key on-chain (`compressG1`, the cheap direction) and merkleizes — reconstructing that exact root. Matching the proven root authenticates the uncompressed keys in one pass (fail-closed: `compressG1` is injective, so a wrong key can't reproduce the committed root); no separate compressed committee or compress-and-compare bind is needed. The successor anchor then stores only the **keccak Merkle root** over those uncompressed keys ([ClprCommitteeMerkle.root](../../libraries/proof/beacon/ClprCommitteeMerkle.sol)) plus the new aggregate — not the keys themselves.

### Step 5 & 6 — EVM state proofs (MPT)

Shared with QBFTVerifier via [ClprEvmStateProof](../../libraries/proof/evm/ClprEvmStateProof.sol).

- **Account proof** — walks the state trie from `executionStateRoot` to `keccak256(EXPECTED_CONTRACT_ADDRESS)`, yielding `[nonce, balance, storageRoot, codeHash]`. `codeHash` is checked against the immutable.
- **Storage proof** — `verifyProvenSlots` proves each entry against the **caller-derived** slot for `channelId` (from the trust anchor), exactly like QBFTVerifier. The slots are never read from the proof, so the proven values are cryptographically bound to *this* channel's `Channel` struct — a relay cannot reorder them or substitute another channel's slot. The proof carries 4 entries (ACK-only) or 5 (with outbound messages):

| Slot index | Channel slot | Decoded field(s) |
|---|---|---|
| 0 | `+1` `verifier(20)\|status(1)\|nextMessageId(8)` | `state = slot>>160`, `nextMessageId = slot>>168` |
| 1 | `+2` `acked(8)\|received(8)\|nextExpectedReply(8)` | `receivedMessageId = slot>>64` |
| 2 | `+4` `sentRunningHash` | `sentRunningHash` |
| 3 | `+5` `receivedRunningHash` | `receivedRunningHash` |
| 4 | `_messageQueues[channelId][nextMessageId-1]` `runningHashAfterProcessing` | proven but not surfaced in metadata |

---

## 7. BLS verification

`_verifyBls` runs the real on-chain BLS12-381 check via [ClprBeaconBls](../../libraries/proof/beacon/ClprBeaconBls.sol) (EIP-2537 precompiles). All points arrive **uncompressed** (the relayer's wire format), so there is **no on-chain decompression**:

0. Select the window member: `period(signatureSlot)` equal to the anchor's `period` picks `current`, one beyond picks `next`, anything else reverts `SignaturePeriodOutOfWindow`. Steps 1–2 below read that member's `aggregatePubkey` and `committeeMerkleRoot` — the anchor holds two of each, so "the committee" always means the selected one.
1. Select the **non-participants** from `bits` (bit clear), require `3·participants ≥ 2·512` (`InsufficientParticipation` otherwise). Their keys arrive in proof item 10 (one 416-byte `key ‖ proof` entry per clear bit, ascending order) and each is Merkle-authenticated against the selected member's `committeeMerkleRoot` before use; with full participation the item is an empty list and no key material is needed.
2. **Recover the participant aggregate by complement**: the selected member's `aggregatePubkey` minus the non-participants, `aggregate + Σ nonParticipant·(r−1)`, in a single `BLS12_G1MSM` (0x0c) — `1 + |non-signers|` terms (≤ ⅓ of the committee at the supermajority), and no MSM at all when everyone signed.
3. **Hash-to-G2** the signing root per RFC 9380 (`expand_message_xmd` → 2× `MAP_FP2_TO_G2` (0x11) → `G2ADD` (0x0d)) under the ETH2 POP ciphersuite.
4. **Pairing**: `BLS12_PAIRING_CHECK` (0x0f) of `e(aggPubkey, H(signingRoot)) · e(−G1, sig) == 1`.

On-chain **compression** (the cheap, MODEXP-free direction, ~720 gas/key) is used only at rotation, to rebuild the beacon SSZ committee root from the uncompressed keys (§4 & 8). Gas (cost scales with the **non-signer** count, so high participation is cheapest): the aggregate verify is ~1.35M at the 342/512 supermajority and ~0.22M at full 512/512; see [GasUsage.t.sol](../../../test/verifiers/ethereum/GasUsage.t.sol) and the `baselines.yml` benchmarks.

---

## 8. Library dependency map

```mermaid
graph TD
    EMV["EthMainnetVerifier"] --> SSZ["ClprBeaconSsz"]
    EMV --> ESP["ClprEvmStateProof"]
    EMV --> PB["ClprProtobuf / Helpers"]
    EMV --> RLP["OpenZeppelin RLP + Memory"]
    EMV --> BLS["ClprBeaconBls"]
    EMV --> CM["ClprCommitteeMerkle"]

    ESP --> MPT["MerklePatriciaProof"]
    SSZ --> SHA["sha256 precompile"]
    SSZ --> CMP["ClprBls12381.compressG1"]
    BLS --> EIP["EIP-2537 precompiles\n(0x0c G1MSM / 0x0d G2ADD / 0x0f pairing / 0x11 map_fp2_to_g2)"]
```

| Library | Purpose | Shared with QBFT? |
|---|---|---|
| [ClprBeaconSsz](../../libraries/proof/beacon/ClprBeaconSsz.sol) | SSZ Merkle branches, header/committee `hash_tree_root`, signing domain | ETH-only |
| [ClprCommitteeMerkle](../../libraries/proof/beacon/ClprCommitteeMerkle.sol) | keccak Merkle commitment over the 512 committee keys: `root` at rotation, `verifyEntry` per non-signer per bundle | ETH-only |
| [ClprBeaconBls](../../libraries/proof/beacon/ClprBeaconBls.sol) | BLS12-381 aggregate verification (G1MSM aggregation + hash-to-G2 + pairing, EIP-2537) | ETH-only |
| [ClprEvmStateProof](../../libraries/proof/evm/ClprEvmStateProof.sol) | MPT account + storage proofs | Shared |
| [ClprProtobuf](../../libraries/codec/ClprProtobuf.sol) / [Helpers](../../libraries/codec/ClprProtobufHelpers.sol) | Bundle-content + ledger-config decode | Shared |

---

## 9. EthMainnetVerifier vs QBFTVerifier

| Aspect | QBFTVerifier | EthMainnetVerifier |
|---|---|---|
| Proof items | 4 | **11** |
| Block authentication | QBFT committed seals in `extraData` | Sync-committee BLS over the attested beacon header |
| Signature scheme | ECDSA secp256k1 (`ecrecover`) | BLS12-381 aggregate (EIP-2537, uncompressed points) |
| Execution state commitment | `stateRoot` field of the EVM block header | execution `state_root` proven **directly** via SSZ branch (no EVM header) |
| Trust anchor | validator address set | flat 428 B window: `gvr ‖ forkVersion ‖ channelId ‖ codeHash ‖ period ‖ [aggregate ‖ committeeRoot] × 2` |
| Peer contract identity | from proof | constructor immutables (`address`, `codeHash`) |
| Storage slots | fixed, caller-derived from `channelId` | fixed, caller-derived from `channelId` |
| Rotation | on validator-set change | SSZ `next_sync_committee` branch advances a `{ current, next }` window |
| Hash functions | keccak256 (MPT) | sha256 (SSZ) + keccak256 (MPT) |
