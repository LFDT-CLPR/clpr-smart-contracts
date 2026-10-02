# Bitcoin → Hiero

Status: in progress (prototype). Header, retarget and transaction rules are verified on real mainnet data (fixtures
fetched 2026-10-01); end-to-end message delivery is verified on a real `bitcoind -regtest` chain on anvil
(2026-10-01). Production needs the receive-only peer channel mode in the CLPR spec.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `bip122:000000000019d6689c085ae165831e93` (mainnet genesis hash prefix) |
| Chain type | L1, proof of work, no smart contracts |
| Finality source | `k` confirmations of valid proof of work (constructor parameter; tests use `k = 6`) |
| Verifier | `BitcoinVerifier` ([family README](../../src/verifiers/bitcoin/README.md)) |
| Trust tier | SPV: no reorg deeper than `k`; deployment checkpoint canonical. Forging 6 blocks cost about 19 BTC on 2026-10-01 |
| Typical bundle | 6 headers + 3 segwit messages: 192,050 gas (`eth_estimateGas`), 3,972 B calldata (real regtest) |
| Rotation | None (no validator set); the checkpoint advances with each bundle |

## Deployment profile

| Parameter | Mainnet | Regtest | Source |
|---|---|---|---|
| `powLimit` | `0xffff << 208` (bits `0x1d00ffff`) | Bitcoin Core regtest `powLimit` | `MAINNET_POW_LIMIT` in `BitcoinMainnet.t.sol`; Bitcoin Core `chainparams.cpp` |
| `noRetargeting` | false | true | Bitcoin Core `chainparams.cpp` |
| `allowMinDifficulty` | false | true | Bitcoin Core `chainparams.cpp` |
| `confirmations` (`k`) | Chosen by the value at risk; 6 in the tests | 6 in the e2e test | Deployment decision |
| `maxPayloadBytes` | At most the local `maxMessagePayloadBytes` throttle; 4096 in the mainnet tests | same | `BitcoinMainnet.t.sol` |
| `caip2ChainId` | `bip122:000000000019d6689c085ae165831e93` | regtest genesis prefix | BIP-122 |
| Deployment checkpoint | A deep mainnet block: hash, height, chainwork, bits, time, period start time | Read from `bitcoind` | Bitcoin Core `getblockheader`; any block explorer |
| Channel sender | vout 1 `scriptPubKey` of the channel's genesis cursor transaction | same | Genesis transaction |

## Relayer requirements

- Bitcoin Core RPC: `getblockcount`, `getblockhash`, `getblockheader`, `getblock`, `getrawtransaction`.
- The payload preimages, from the sender (they are not on Bitcoin).
- Wait for `k` confirmations (about 1 hour at `k = 6`).
- No rotation and no signature aggregation. A bundle can carry about 1,500 headers of lag in 128 KB.

## Chain-specific trust and caveats

- Same as the family: the verifier does not check transaction scripts or signatures, and does not compare competing
  forks. A forger needs `k` valid blocks on top of the anchor checkpoint, not the heaviest chain.
- One sender per channel (the genesis cursor script), about 25 chained messages per channel per block (Bitcoin
  Core's default ancestor limit), one 55-byte `OP_RETURN` per message.
- Median-time-past and the 2-hour future rule are not checked.

## Live verification

- Mainnet fixtures: `test/verifiers/bitcoin/fixtures/mainnet-{2016,32256,967680}.json` (headers around three retarget
  boundaries, including 967,680) and `mainnet-tx-{legacy,segwit}.json` (real transactions in block 967,680), fetched
  with `npx tsx test/verifiers/bitcoin/fixtures/fetch-mainnet.ts` from the Blockstream Esplora API.
- Replay: `forge test --match-path 'test/verifiers/bitcoin/*'` (20 mainnet tests: header hashes, three real
  retargets, bundles across real boundaries, non-monotonic timestamps, legacy and segwit txids and Merkle branches,
  tampering cases).
- End to end: `npm run test:e2e:bitcoin-verifier` runs `bitcoind -regtest` (Docker image `bitcoin/bitcoin:28.1`),
  creates a channel and 3 real messages, and verifies them on anvil. No CLPR messages have been sent on mainnet.

## Hiero → Bitcoin

Not possible today. Bitcoin script cannot verify a Hiero state proof, so nothing on Bitcoin can accept a CLPR bundle,
reply or acknowledgement. BitVM2-style optimistic verification (a committee with fraud proofs executed in Bitcoin
script) is the only credible route and is not started; it would be 1-of-n honest, not trustless. A Bitcoin channel is
therefore receive-only on the Hiero side, which needs the spec change described in the family README.
