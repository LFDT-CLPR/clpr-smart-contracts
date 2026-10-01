# BitcoinVerifier: Bitcoin L1 → Hiero (prototype)

`BitcoinVerifier` is an `IClprVerifier` that runs on Hiero (Hedera's EVM) or any EVM. It verifies
CLPR messages that were **sent on Bitcoin L1**. It is a stateless proof-of-work (SPV) light client:
all state it needs lives in the channel's opaque trust anchor.

| File | What |
|---|---|
| `BitcoinVerifier.sol` | `verifyConfig` / `verifyBundle`, the trust anchor, message rules |
| `BitcoinLib.sol` | headers, compact targets, retarget, chainwork, Merkle branches, tx parsing |
| `test/verifiers/bitcoin/` | real-mainnet fixture tests, regtest-chain tests, gas |
| `test/integration/IntegrationBitcoin.t.sol` | the unmodified `ClprService` consuming this verifier |
| `test/e2e/relay/buildBitcoinProof.ts` | relay: builds proofs from Bitcoin Core RPC |
| `test/e2e/tests/verifiers/bitcoin-verifier.spec.ts` | real `bitcoind -regtest` (Docker) → anvil |

## Direction: one way only

**Bitcoin → Hiero works. Hiero → Bitcoin does not, and cannot today.** Bitcoin script cannot verify a
Hiero state proof, so nothing on Bitcoin can accept a CLPR bundle, a reply, or an acknowledgement.
BitVM2-style optimistic verification (a bridge committee with fraud proofs executed in Bitcoin
script) is the only credible route and is future work. It is also 1-of-n honest, not trustless.
So a Bitcoin channel is a **receive-only channel** from the Hiero side (see
[the spec change it needs](#required-spec-change-receive-only-peer-channels)).

## Design

Bitcoin has no smart contracts, so it has no CLPR Service and no queue state. Two Bitcoin
primitives replace them.

### Messages: OP_RETURN commitments

A CLPR message is a Bitcoin transaction whose **vout 0** is exactly this 55-byte script:

```
OP_RETURN PUSH53  "CLPR"(4) ‖ version(1)=0x01 ‖ channelTag(8) ‖ sha256(payload)(32) ‖ messageId(8, big-endian)
```

- `channelTag` is the first 8 bytes of the CLPR `channelId`. The verifier checks it against the
  channel context, so one channel cannot replay another channel's messages.
- The **payload** is a protobuf `ClprMessage` DATA (`connectorId`, `targetApplication`, `sender`,
  `messageData`). It is *not* on Bitcoin: the relay supplies the preimage in the bundle, and the
  verifier checks that its SHA-256 equals the committed hash.

### Queue order: a UTXO chain ("cursor")

- **Input 0** of every message tx MUST spend the previous message's **cursor output (vout 1)**.
  **vout 1** of the message tx is the new cursor.
- Bitcoin forbids double-spends, so the chain of cursor spends is linear. That gives a total order
  and exactly-once delivery with no on-chain queue. The trust anchor stores the current cursor
  outpoint and the last message id. Each delivered message must spend exactly that outpoint and
  carry `lastId + 1`. A replayed, skipped or reordered message fails the cursor check.
- Several messages can be chained inside one block (spending unconfirmed parents). Bitcoin Core's
  default mempool ancestor limit (25) caps a channel at about 25 messages per block.

### Channel setup: the genesis cursor tx (`verifyConfig`)

The sender publishes a **genesis tx** with the same layout: vout 0 is the commitment with
`messageId = 0` and an all-zero payload hash, and vout 1 is the first cursor. Its vout 1
`scriptPubKey` becomes the channel's **sender** (returned as the peer `serviceAddress` and bound
into the `ChannelContext`).

`configProof = abi.encode(ConfigProof{startHeight, headers, genesis: TxProof})`. The headers connect
to the **deployment checkpoint** (constructor), not to anything the channel operator supplies. The
genesis block must have ≥ k confirmations. Other return values:

- chain id: the CAIP-2 id from the constructor (`bip122:<genesis hash prefix>`)
- `peerConfigNanos`: the genesis block time
- endpoint manifest: version 0 (Bitcoin has no endpoints; manifest proofs are rejected)
- throttles: placeholders (see [receive-only](#required-spec-change-receive-only-peer-channels))

### Trust anchor

`Channel.trustAnchor = abi.encode(TrustAnchor)` (11 static words, 352 bytes):

| Field | Meaning |
|---|---|
| `checkpoint.blockHash / height` | deepest verified block with ≥ k confirmations |
| `checkpoint.chainWork` | cumulative work at the checkpoint (reported; there is no fork choice in v1) |
| `checkpoint.bits / time / periodStartTime` | state needed to validate the next header: nBits, the parent timestamp, and the timestamp of the first block of the current 2016-block period |
| `cursorTxid / cursorVout` | outpoint the next message must spend |
| `lastMessageId` | last delivered id (0 = none) |
| `runningHash` | `BundleLib` running hash after `lastMessageId` |
| `confirmations` | k, copied from the constructor at `verifyConfig` |

`trustAnchorId = checkpoint.blockHash ‖ lastMessageId`.

### Bundles (`verifyBundle`)

`proofBytes = abi.encode(BundleProof{startHeight, headers, messages: TxProof[]})`, where
`TxProof = {headerIndex, txIndex, merkleBranch, rawTx, payload}`.

1. **Header chain.** `headers` is a list of consecutive 80-byte headers. It either starts at
   `checkpoint.height + 1`, or starts **at or below** the checkpoint and contains the checkpoint
   header. For every header: `prevHash` links to the previous header. Headers at or below the
   checkpoint are bound by hash linkage only (their work was accepted earlier). Every header above
   the checkpoint also gets:
   - `hash256(header) ≤ target(nBits)` and `target ≤ powLimit`, using the SHA-256 precompile.
   - nBits: at a 2016 boundary it must equal Bitcoin Core's `CalculateNextWorkRequired`
     (timespan = parent time − period start time, clamped to ×4 / ÷4, capped at powLimit, compact
     re-encoding compared bit-exactly). Elsewhere it must be unchanged.
   - Regtest (`noRetargeting`, `allowMinDifficulty`): bits never retarget, and a block more than
     20 minutes after its parent may use the powLimit bits.
2. **Finality.** With `tip` the last header, `final = max(checkpoint.height, tip − k + 1)`. A block
   is final when it has **k confirmations** in Bitcoin's sense (the block itself counts as 1).
   Every message block must be ≤ `final`. The new checkpoint is the header at `final`, so the
   anchor only moves to blocks buried ≥ k deep, and it never moves backwards.
3. **Per message, in queue order:** the Merkle branch (double-SHA256) from the txid must reach
   the block's merkle root. The txid is computed over the **non-witness serialization**, and the
   BIP-144 marker, flag and witnesses are parsed and skipped. The coinbase is rejected, as are
   64-byte txs, which are ambiguous with Merkle interior nodes. Then the cursor, id and channel tag
   are checked, vout 1 must still pay to the sender script, and `sha256(payload)` must equal the
   commitment.
4. **Output.** The verifier returns payloads in `ClprTypes` form and synthesizes queue metadata the
   way `BundleLib` checks it:
   - `nextMessageId = lastId + 1`
   - `sentRunningHash = fold(sha256(h ‖ sha256(payload)))`, carried across bundles in the anchor
   - `receivedMessageId = 0` and `receivedRunningHash = 0`: Bitcoin never receives
   - `state = ACTIVE`
   - no manifest update

   A new anchor is returned only if the checkpoint moved or messages were delivered. Otherwise
   the service rejects the bundle with `NoProgress`.

`IntegrationBitcoin.t.sol` shows that the **unmodified** `ClprService` accepts this output: the app
receives the 3 messages, and the service's `receivedRunningHash` equals the anchor's.

### Not checked (by design, documented)

- **Median-time-past** (timestamp > median of the previous 11) and the **2-hour future** rule.
  Skipped: MTP needs 11 prior timestamps in the anchor or the proof, and the future rule needs a
  trusted clock. The main thing they defend against is timestamp manipulation of the retarget. That
  is bounded by the ×4 clamp and still costs full-difficulty work. Real mainnet data has
  non-monotonic timestamps (967679 < 967678, covered by a test), and those are accepted as Bitcoin
  accepts them.
- **Transaction validity** (scripts, signatures, amounts). This is the standard SPV assumption: a
  block with valid PoW is assumed valid.
- **Testnet3/4** difficulty rules (walk-back min-difficulty, BIP94). The constructor rejects
  `allowMinDifficulty` without `noRetargeting`.

## Trust assumptions

1. **The deployment checkpoint is on the canonical chain.** It roots every channel's config proof,
   like any light-client checkpoint. Deployers pick a block that is already deep.
2. **Standard SPV assumption: no reorg deeper than k.** The verifier sees only the chain the relay
   shows it. It does **not** compare against competing forks (out of scope for v1), so safety
   rests entirely on the cost of producing k blocks of valid PoW:
   - SPV does not check signatures, so a forger does not need the sender's key. A private fork
     can "spend" the cursor with a fake tx carrying any payload.
   - The forger does not need to outpace the honest chain either. They only need k valid blocks
     on top of the anchor checkpoint, submitted by a registered endpoint.
   - **Cost.** Data from mempool.space on 2026-10-01: difficulty ≈ 1.33 × 10¹⁴ (≈ 5.7 × 10²³
     hashes per block), network ≈ 982 EH/s, average reward over the last 144 blocks ≈ 3.15 BTC,
     BTC ≈ $83,900. That puts one block at ≈ $264k of hashing at break-even economics.

     | k | ≈ cost to forge | time for an attacker with 10% of hashrate |
     |---|---|---|
     | 6 | ≈ 19 BTC ≈ $1.6M | ≈ 10 h |
     | 12 | ≈ 38 BTC ≈ $3.2M | ≈ 20 h |

     Only 10% of the hashrate is needed because the fork never has to be the heaviest chain.
   - **Rule of thumb:** the value a single bundle can move on this channel must stay well below
     `k × block reward`.
   - **After a successful forgery the channel is also stuck.** The anchor sits on the private fork,
     so honest headers no longer connect.
   - **Mitigations (future):** a challenge window where a heavier competing header chain from the
     same checkpoint replaces the anchor (the chainwork is already tracked), multiple relays, and a
     per-channel k chosen by value.
3. **Relays are untrusted for safety.** Every byte is checked. A relay can only delay delivery.
   A relay also has no censorship discretion over content: it must supply the exact preimage, and
   invalid content is redacted deterministically (below).

## Design flaws found and the minimal fixes applied

1. **The anchor can advance past undelivered messages.** The checkpoint only moves forward. If a
   relay advanced it past a block holding the next cursor spend (by accident, or a griefing
   endpoint doing headers-only bundles), that message could never be proven against the header
   chain, and the queue would be stuck forever.
   - **Fix:** headers may start *below* the checkpoint. They are bound to it by hash linkage alone,
     so old blocks stay provable.
   - **Limit:** 80 bytes per block of lag. About 1,500 blocks (~10 days) fit in 128 KB of calldata.
     1,000 headers cost 6.4M gas (measured).
   - **Proper fix (future):** an MMR of verified header hashes in the anchor, for O(log n)
     historical proofs.
2. **The service seeds the running hash from its own state, which the verifier cannot see.** The
   verifier returns `sentRunningHash`, and `BundleLib` recomputes it from
   `channel.receivedRunningHash`.
   - **Fix:** the anchor carries `runningHash` and `lastMessageId` and advances them in the same
     atomic update the service applies.
3. **The UTXO chain alone does not enforce a single sender.** Whoever spends the cursor chooses the
   next cursor's script, so the cursor could be handed to anyone. The DATA payload's `sender`
   field is also free text on Bitcoin.
   - **Fix:** the genesis cursor script is the channel's sender. Every message's vout 1 must pay
     back to that script (`CursorNotHeldBySender`), and a payload whose `sender` field is not that
     script is redacted.
4. **A committed payload that the service would reject would halt the channel forever.** Examples:
   a REPLY or CONTROL type, a malformed DATA, an unknown wire field, or an oversized payload.
   `BundleLib` reverts the whole bundle on these, and the Bitcoin commitment can never be
   withdrawn.
   - **Fix:** the verifier checks deliverability itself. It requires a DATA message, `sender` equal
     to the channel script, a 20-byte target and ≤ `MAX_PAYLOAD_BYTES`, with the decode run under
     try/catch. Anything else is delivered as `ClprRedactedMessage{sha256(payload)}`, which the
     service answers with a REDACTED reply.
   - This is deterministic in the committed bytes. A wrong preimage still reverts
     (`PayloadHashMismatch`), so a relay cannot force redactions.
   - `MAX_PAYLOAD_BYTES` must be ≤ the local `maxMessagePayloadBytes` throttle.
5. **The config proof was operator-trusted.** Other verifiers accept the initial trust anchor from
   the config proof.
   - **Fix:** here the config headers must connect to the constructor checkpoint and carry valid
     PoW, so a channel operator cannot pick a fake checkpoint.
6. **"Depth k" was ambiguous.** It is defined as Bitcoin confirmations (`tip − h + 1 ≥ k`), so
   "6 headers" with the message in the first block is exactly 6 confirmations.

**Residual sender-side hazards (documented, not fixed):**

- A tx that spends the cursor but has a malformed commitment (wrong id, tag or format) permanently
  halts the channel. The same happens if the sender never publishes a payload preimage. Only the
  channel's own sender can cause either one, and the channel must then be closed and re-created.
  Sender tooling must validate before broadcasting.

## Limits

- **One sender per channel.** The sender is the genesis cursor script. More senders need more
  channels, or a multisig/taproot script shared by a group.
- **OP_RETURN.** The commitment is 55 bytes. That is inside Bitcoin Core's long-standing standard
  limit (`datacarriersize` 83 bytes, one OP_RETURN per tx) and so is relayed by every version.
  Core 30 relaxed both limits, but this design does not rely on that. Payloads live off-chain, so
  **data availability of the payload is the sender's responsibility.** A future variant could put
  the payload in the witness (inscription envelope) and prove it from the full serialization.
- **Throughput and cost.** One message per Bitcoin tx (~270 vB with a separate fee input), ~25 chained
  messages per channel per block, and latency of k blocks (~1 h at k = 6).
- **Reorgs deeper than k break safety** (see above). There is no fork handling in v1.
- **Header lag** of ~1,500 blocks per bundle (calldata), see flaw 1.
- **Networks:** mainnet and regtest. testnet3/testnet4/signet are not implemented (signet needs
  block-signature validation).

## Required spec change: receive-only peer channels

Hiero → Bitcoin is undeliverable, but today's CLPR Service treats every channel as bidirectional.
`IntegrationBitcoin.t.sol` demonstrates the gaps:

1. **Replies pile up.** Every inbound DATA makes `BundleLib` enqueue a REPLY for the peer.
   The peer can never ack it, so `ackedMessageId` stays 0 and `nextMessageId` grows by one per
   message. The storage is never reclaimed. The lazy CONTROL config-update enqueue (Step 10b)
   adds more.
2. **Outbound sends** are refused today only by accident: the verifier returns placeholder peer
   throttles with `maxSyncBytes = 1`, so `sendMessage` fails the peer-size check. That is not a
   protocol guarantee.
3. **Close never completes.** DRAINED → CLOSED needs every outbound message acked, which never
   happens.
4. **No response semantics.** Bitcoin-side senders get no REPLY. Applications must treat Bitcoin
   messages as fire-and-forget.

**Proposed spec change** (not implemented here; `ClprService` and `BundleLogic` are untouched):

- **New channel mode.** Add a `receiveOnly` flag, fixed at `completeChannel`. `verifyConfig`
  declares it, e.g. through a new return field or a `ClprThrottles` flag the peer config carries,
  since the verifier is the component that knows the peer cannot receive.
- **For a `receiveOnly` channel:**
  - (a) `sendMessage` reverts (`ClprChannelReceiveOnly`).
  - (b) inbound DATA dispatch still calls the application and connector, and still charges and
    slashes, but does **not** enqueue a REPLY. The result is emitted as an event
    (`MessageDispatched`) and the application's return data is dropped.
  - (c) CONTROL config updates are not enqueued.
  - (d) the outbound queue is always empty, so `_allOutboundAcked` is vacuously true, and close
    goes CLOSING → DRAINED → CLOSED locally. The peer-done requirement is waived, because the
    peer's reported state is synthesized.
  - (e) `receivedMessageId` from the peer is required to be 0 (anything else is a verifier bug).
- **Spec sections affected:**
  - §2.1.1: the channel lifecycle for `receiveOnly`.
  - §4.2 Step 5b: the close conditions.
  - §4.3: `sendMessage` guard.
  - §4.5: response ordering is vacuous.
  - `LedgerConfiguration` / `ChannelContext`: carry the flag.
- **Fee model.** No reply means connectors cannot learn success through `onClprResponse`, so
  source-side slashing (§4.6 outbound table) never applies.

## Gas and calldata (measured)

Foundry figures are `verifyBundle` execution only (a STATICCALL). The anvil figures are
`eth_estimateGas` and include the 21,000 base cost and calldata. In every case the 3 messages
are segwit txs.

| Scenario | Foundry execution gas | anvil `estimateGas` | calldata |
|---|---|---|---|
| 6 headers + 3 messages | 125,821 | 192,122 | 3.6–4.0 KB |
| 12 headers + 3 messages | 162,283 | 235,725 | 4.1–4.5 KB |
| 1,000 headers + 3 messages | 6.38M | not measured | 83 KB |

Hedera's per-transaction limits are **15M gas** and **128 KB calldata**. A normal bundle uses about
1.5% and 3.5% of them. Runtime bytecode is 13.5 KB, under the 24 KB limit.

## Running

```bash
forge test --match-path 'test/verifiers/bitcoin/*'                       # mainnet fixtures + regtest chains
forge test --match-path test/integration/IntegrationBitcoin.t.sol        # real ClprService
forge test --match-test test_gas_verifyBundle -vv --match-path 'test/verifiers/bitcoin/*'   # gas
npm run test:e2e:bitcoin-verifier   # bitcoind -regtest in Docker (bitcoin/bitcoin:28.1) + anvil
npx tsx test/verifiers/bitcoin/fixtures/fetch-mainnet.ts                 # re-fetch fixtures (optional)
```
