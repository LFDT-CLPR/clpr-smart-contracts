# Rootstock → Hiero

Status: live-verified on Rootstock mainnet headers (merged-mining proof of work and difficulty rule, 40 headers,
2026-10-01) and end to end on a real RSKj 9.0.4 regtest node. No mainnet storage proof: public RSK nodes serve none.

**Trust rests on merged-mining proof of work (Bitcoin hashrate that merge-mines RSK), not on a signer set.**

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `eip155:30` (mainnet, chain id 30); regtest `eip155:33` |
| Chain type | Bitcoin sidechain, merge-mined with Bitcoin; EVM-compatible (RSKj) |
| Finality source | `k` confirmations of merged-mining work at the RSK difficulty (`k = 12` in the tests) |
| Verifier | `RootstockVerifier` ([family README](../../src/verifiers/evm/rootstock/README.md)) |
| Trust tier | Proof of work, no reorg deeper than `k`; deployment checkpoint canonical |
| Typical bundle | Headers: 2,422,030 gas, 16,932 B for one 12-header window (live mainnet). Full bundle on regtest: 1,090,059 gas, 14,468 B |
| Rotation | None. Catch-up `extend`: 8,863,051 gas, 56,516 B for 40 mainnet headers (about 229,000 gas per header) |

## Deployment profile

| Parameter | Mainnet value | Where it was read |
|---|---|---|
| `chainId` | `eip155:30` | RSKj `Constants.MAINNET_CHAIN_ID` |
| `confirmations` | Deployment choice (12 in the tests) | — |
| `minDifficulty` | 7,000,000,000,000,000 | RSKj `Constants.mainnet()` |
| `difficultyDivisor` | 400 | RSKj `Constants` (RSKIP156, `papyrus200` = 2,392,700) |
| `durationLimit` | 14 | RSKj `MAINNET_DURATION_LIMIT` |
| `forkDetectionFrom` | 1,591,000 | RSKIP110 at `wasabi100` (`main.conf`) |
| `maxBtcTimestampDiff` | 300 | RSKIP179 (`iris300` = 3,614,800), `DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS` |
| `genesis` checkpoint | A deep mainnet block: hash, number, difficulty, timestamp | Any RSK node (`eth_getBlockByNumber`) |
| Service | The unmodified Solidity `ClprService` on RSK; its code hash is read from the Unitrie at `verifyConfig` | — |

## Relayer requirements

- Its own RSKj node: RSKj 9.x has no `eth_getProof`. Unitrie nodes come from the node's trie store (the fixture tool
  `UnitrieDump.java` reads a stopped node's RocksDB; production needs a live reader).
- Headers: `rsk_getRawBlockHeaderByNumber` on its own node, or rebuilt from `eth_getBlockByNumber` and checked against
  the block hash (public nodes). Coinbase and Merkle branch: `bitcoinMergedMiningCoinbaseTransaction`,
  `bitcoinMergedMiningMerkleProof` of each block.
- Wait for `k` confirmations (about 7 minutes at `k = 12` and the 33.8 s average of the fixture).
- About 65 headers fit in one transaction. If the channel's anchor is further behind, call `extend` first (about 54
  blocks per call at `k = 12`), then start the bundle from the last recorded checkpoint.

## Chain-specific trust and caveats

- The Bitcoin header's own difficulty is not used: the work is measured at the RSK difficulty. The verifier checks
  RSK's difficulty rule, so a fork cannot lower it faster than 1/400 per block or below 7 × 10^15.
- No fork choice: `k` valid headers above the anchor are enough.
- The PowPeg federation and the bridge are not involved.
- Only V0 headers; `reed810` (RSKIP351 header versions) and `cardamom1000` have no mainnet height on 2026-10-01.

## Live verification

- `test/e2e/fixtures/rootstock-live/mainnet.json`: 40 consecutive mainnet headers (9,286,608 to 9,286,647) from
  `https://public-node.rsk.co` (RSKj 9.0.3 VETIVER), captured 2026-10-01. Refresh: `npm run rootstock-live:refresh`.
- `test/e2e/fixtures/rootstock-live/regtest.json`: a real RSKj 9.0.4 regtest chain with a contract that holds a CLPR
  Channel record at the `ClprService` slots, and Unitrie proofs from the node's trie store. Refresh:
  `RSKJ_JAR=… npm run rootstock-live:refresh-regtest`.
- `test/e2e/fixtures/rootstock-live/compliance.json`: a real RSKj 9.0.4 regtest chain where one service's manifest
  commitment takes six values in six blocks, for the IClprVerifier compliance suite. Refresh:
  `RSKJ_JAR=… test/e2e/relay/rootstock/refresh-regtest.sh compliance`.
- Replay: `forge test --match-path 'test/verifiers/rootstock/*'` (23 tests),
  `test/verifiers/compliance/RootstockComplianceTest.t.sol` (21 cases) and `npm run test:e2e:rootstock-live`
  (6 tests on anvil, including `extend` as a transaction).

## Hiero → Rootstock

Not started. Rootstock runs Solidity, so the Hiero → EVM path (`HieroVerifier`) is the natural route, but
`TSSVerifier` checks hinTS BLS12-381 signatures with the EIP-2537 precompiles, and RSKj's precompiles (0x01 to 0x09
plus RSK-specific ones) do not include them. It would need an RSKIP adding BLS12-381 precompiles, or a BLS12-381
implementation in plain EVM code (none exists in this repository; its cost is not measured).
