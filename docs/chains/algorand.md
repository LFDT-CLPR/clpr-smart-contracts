# Algorand → Hiero · status: live-verified on mainnet, testnet (2026-10-01)

Algorand has no state root, so this verifier proves a log of a successful application call. The call must be
in a block attested by an Algorand state proof. The proofs are accumulated on Hedera over many
transactions. Design, trust model and gas are in the family README:
[`src/verifiers/evm/algorand/README.md`](../../src/verifiers/evm/algorand/README.md).

## Quick facts

| Item | Value |
|---|---|
| CAIP-2 | mainnet `algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k`; testnet `algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe` |
| Chain type | L1, pure proof-of-stake (go-algorand) |
| Finality source | State proofs: Falcon-1024 compact certificate per 256 rounds, chained through voters commitments |
| Verifier | `AlgorandStateProofVerifier` + `AlgorandStateProofAccumulator` (+ SHAKE256, SumHash512, Falcon engines) |
| Trust tier | State-proof threshold: forging needs 30% of the online weight of the top 1,024 accounts. Plus bootstrap message and CLPR application updater. |
| Typical bundle | 457,701 gas, 2,112 B (live mainnet transaction proof) |
| Rotation | Every 256 rounds (about 12 minutes): mainnet 62 transactions, 703.1M gas (max 11,792,178 gas and 7,012 B per transaction); testnet 16 transactions, 164.4M gas |

## Deployment profile

| Parameter | Mainnet | Testnet | Source |
|---|---|---|---|
| Genesis hash (anchor) | `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=` | `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=` | block field `gh`, `/v2/blocks/{round}` |
| Chain id | `algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k` | `algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe` | CAIP-2 Algorand namespace; checked by `caip2(genesisHash)` |
| Bootstrap message | a recent state-proof message, picked by the channel's governance | same | `/v2/stateproofs/{round}` |
| Service address | the CLPR application id, 8 bytes big-endian (no CLPR application deployed yet) | same | application creation transaction |
| Interval, strength target | 256 rounds, 256 | 256, 256 | `config/consensus.go` v34+ (compiled in) |
| Signature and participant tree depth | 10 (fixture) | 10 (fixture) | state proof `S.td`, `P.td` |
| Engines | `ClprShake256Engine`, 16 × `ClprSumHashTableChunk` + `ClprSumHash512Engine`, `ClprFalconDet1024Engine` | same | deployed once per Hedera network, shared |

## Relayer requirements

- **algod REST**: `/v2/status`, `/v2/stateproofs/{round}`, `/v2/blocks/{round}?format=msgpack`,
  `/v2/blocks/{round}/lightheader/proof`, `/v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`,
  `/v2/blocks/{round}/hash`. The public `https://{mainnet,testnet}-api.algonode.cloud` nodes were used.
- **Archive depth**: the public nodes keep about 1,000 rounds. Catching up older intervals needs an archival
  algod or an indexer for state-proof transactions.
- **Cadence**: every interval must be accumulated, about 122.6 per day on mainnet: one `submitReveals`
  transaction per reveal (about 60) plus `finalize`. The relayer rebuilds per-leaf SumHash512 paths from the
  batched proof (`individualPaths` in `buildAlgorandLiveProof.ts`).
- **Bundles**: one transaction per bundle. The CLPR application must be called at top level, with the
  `ClprQueue` ARC-28 log in that call.

## Chain-specific trust and caveats

- The state-proof threshold (30% of online weight) is lower than Algorand's agreement threshold. A state
  proof is Algorand's light-client guarantee, not full consensus finality.
- Algorand applications can be updatable. The CLPR application must be immutable, or its updater is trusted.
- Following mainnet costs about 86 billion gas per day. A SNARK of the state-proof verifier is the practical
  path to production.

## Live verification

| Network | Fixture | What was verified | Captured |
|---|---|---|---|
| mainnet | `test/e2e/fixtures/algorand-live/mainnet.json`, `vectors.json` | Interval 65,562,625–65,562,880 accumulated from the previous message: 61 reveals (Falcon-1024, three SumHash512 paths each), 151 coins. Then the application call at round 65,562,880 (tx 8, app 3705323992) proven through the light-header and transaction commitments; its log returned. | 2026-10-01 |
| testnet | `test/e2e/fixtures/algorand-live/testnet.json`, `testnet-vectors.json` | Interval 67,835,649–67,835,904: 15 reveals, 148 coins, then the application call at round 67,835,664 (tx 0, app 767308083) | 2026-10-01 |

```bash
forge test --match-path 'test/verifiers/*/algorand/*'      # includes the full mainnet accumulation
npm run test:e2e:algorand-live                              # anvil replay, mainnet and testnet
npm run algorand-live:refresh                               # re-capture mainnet
ALGORAND_NETWORK=testnet npm run algorand-live:refresh      # re-capture testnet
```

## Hiero → Algorand direction

Not started. It needs an AVM application that verifies Hiero block proofs and the CLPR Service as an
Algorand application. The AVM has elliptic-curve opcodes for BN254 and BLS12-381 (`ec_pairing_check`,
`ec_multi_scalar_mul`, AVM v10). The opcode budget per application call and the per-transaction argument size
limits decide whether a Hiero proof fits one transaction group. That is not measured here.
