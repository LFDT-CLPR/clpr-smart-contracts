# TON → Hiero

TON → Hiero · status: live-verified on TON mainnet and testnet (2026-10-01, fixture capture timestamps)

TON's masterchain validators sign every masterchain block; today both networks sign Simplex finalize
votes. `TonVerifier` follows the masterchain validator set key block by key block (ConfigParam 34),
checks that more than 2/3 of the weight signed a masterchain block, and proves a contract's data cell
through BoC Merkle proofs (masterchain state → shard block → shard state → account). Full design:
[family README](../../src/verifiers/evm/neartons/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `ton:mainnet` (global id −239), `ton:testnet` (global id −3) |
| Chain type | L1, masterchain + basechain shards |
| Finality source | Masterchain block signed by > 2/3 of the weight of the masterchain validators (ConfigParam 34, first `main` entries) of its previous key block |
| Verifier contract | `src/verifiers/evm/neartons/TonVerifier.sol` · [family README](../../src/verifiers/evm/neartons/README.md) |
| Trust tier | > 2/3 of each followed masterchain validator weight; deploy-time key-block checkpoint |
| Typical bundle | Mainnet: 1.90M gas, 15.8 KB with 69 cached signatures, after 4 cache transactions (about 12.44M gas each for 20). Testnet: 7.61M gas, 7.7 KB with 10 inline signatures |
| Rotation | One key block inside the bundle. Mainnet 5.88M gas, 32.6 KB (cached, plus 4 cache transactions for the key block); testnet 14.50M gas inline, or 8.57M gas after one 6.24M-gas cache transaction |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `chainId` | `ton:mainnet` / `ton:testnet` | `test/e2e/relay/buildTonLiveFixture.ts` (`TON_TARGETS`) |
| `checkpointKeyBlock` (tests) | mainnet 96,083,428; testnet 88,330,007 | `test/e2e/fixtures/ton-live/*.json` (`derived.anchorPrev`, first 4 bytes) |
| `checkpointSetHash` (tests) | mainnet `0xce924a84…d404` (100 masterchain validators); testnet `0xd17bd818…c2f2` (15) | `derived.anchorPrev`, last 32 bytes |
| Checkpoint source | A key block's ConfigParam 34 from a liteserver config proof, packed as `pubkey ‖ uint64 weight` | `buildTonLiveFixture.ts` |
| Signature mode | Simplex (mode 1) on both networks at capture; catchain (mode 0) also accepted | `derived.meta.mode` |
| `ClprEd25519SignatureCache` | Required on mainnet (68–69 signatures per block) | `ClprEd25519SignatureCache.sol` |
| Service data layout | `config_commitment:bits256 manifest_commitment:bits256 channels:(HashmapE 256 ^ChannelQueue)`; address `workchain:int8 ‖ account_id` | `TonVerifier.sol` header |

## Relayer requirements

- An ADNL liteserver from `ton.org/global.config.json` (testnet: `testnet-global.config.json`):
  `getMasterchainInfo`, `getBlockProof` (forward links with signature sets and config proofs),
  `getAccountStatePrunned`. HTTP gateways (toncenter, tonapi) cannot decode Simplex signature sets.
- Deliver every key block since the anchor, in order.
- Mainnet: record 68–69 signatures per signed block in the cache, 20 per transaction (4 per block).

## Chain-specific trust and caveats

- Shard blocks are trusted through the masterchain state that references them (`ShardDescr`).
- Only workchains 0 and −1 are accepted.
- The recorded mainnet key block did not change the validator set (only the anchor's seqno moved);
  the set-changing rotation is live-verified on testnet.
- No CLPR Service exists on TON; the fixtures prove the USDT jetton master (mainnet) and a basechain
  contract (testnet). The masterchain-service path is covered by the synthetic suite.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/ton-live/mainnet.json`, `testnet.json` |
| Captured | mainnet 2026-10-01T05:44:43Z (block 96,185,670), testnet 2026-10-01T05:44:33Z (block 88,333,049) |
| Refresh | `npm run neartons-live:refresh` (or `npx tsx test/e2e/relay/buildTonLiveFixture.ts --refresh`) |
| Replay | `forge build && npm run test:e2e:neartons-live`; forge: `forge test --match-path test/verifiers/evm/neartons/TonLive.t.sol -vv` |
| What was verified | Simplex-signed masterchain blocks (mainnet 69 of 100, testnet 10 of 15), a key-block rotation on each network, and basechain account proofs (masterchain state → shard block → shard state → account) |

## Hiero → TON direction

Not started on this branch. It needs a Hiero verifier as a TON contract.
