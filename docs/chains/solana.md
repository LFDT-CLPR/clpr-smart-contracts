# Solana → Hiero

Status: in progress. The Alpenglow certificate path is verified on devnet's live genesis certificate (captured
2026-10-01). ATTESTED mode is tested with synthetic committees; the Solana-side CLPR program is designed, not built.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`; testnet `solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z`; devnet `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` (`getGenesisHash`) |
| Chain type | L1, Agave; TowerBFT on mainnet, Alpenglow on testnet and devnet |
| Finality source | ATTESTED: committee signs rooted slots only. ALPENGLOW: BLS finality certificate (FinalizeFast 80%, or Notarize + Finalize 60%) |
| Verifier | `SolanaVerifier` + `AlpenglowFinalityVerifier` ([family README](../../src/verifiers/solana/README.md)) |
| Trust tier | **K-of-N attestor committee (strict majority)** for the queue state, because Solana cannot prove transaction success or account state; in ALPENGLOW mode also for each epoch's validator set |
| Typical bundle | ATTESTED 13-of-19: 88,107 execution gas, 4,160 B proof (synthetic). ALPENGLOW on the live devnet certificate: 429,023 gas (`eth_estimateGas`), 7,812 B |
| Rotation | Committee 5 → 7: 74,285 execution gas, 3,296 B (synthetic). Epoch-set update once per epoch |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` (constructor) | CAIP-2 id of the cluster, above | `getGenesisHash` |
| `genesisCommitteeHash` (constructor) | `keccak256(abi.encode(nonce, K, members))` of the first committee; `2K > N` | Operator choice |
| `alpenglow` (constructor) | Address of the `AlpenglowFinalityVerifier` deployment, or zero for ATTESTED-only | Deployment |
| `mode` (config) | 1 ATTESTED today on mainnet; 2 ALPENGLOW where Alpenglow is active | Alpenglow feature `A1pengvuM6JEcyNuTnMqepBKhwHE3N6PmUrdATGawhJS` via `getMultipleAccounts` |
| `programId` | The Solana CLPR program id (32 bytes), equal to the channel's `remoteServiceAddress` | Not deployed yet |
| Initial `EpochSet` (mode 2) | Rank map of the current epoch: staked vote accounts with BLS keys, sorted by stake | `getVoteAccounts` and vote-account state at the epoch boundary |
| `shredVersion` | 7016 on devnet in the fixture | Fixture `shredVersion` |
| Alpenglow activation | Testnet slot 444,620,256; devnet slot 504,144,000; not on mainnet | Feature accounts |

## Relayer requirements

- Committee members: `getAccountInfo` on the queue PDA at a finalized slot, and the slot's `blockhash` (TowerBFT) or
  `block_id` (Alpenglow). Each member should run its own node.
- ALPENGLOW mode: **its own Agave node** that exports `block_final_cert` from replayed block footers (Geyser plugin or
  a small RPC patch) or a votor listener; public RPC exposes only `getAgGenesisCert`, and `getBlock` lacks `block_id`.
- A snapshot of each epoch's rank map at the boundary (432,000 slots per epoch), because RPC serves only current
  stakes; committee signatures over each new `EpochSet`.
- Committee rotations when operators change.

## Chain-specific trust and caveats

- Mainnet stake concentration on 2026-10-01 (683 staked vote accounts): 1/3 of stake is 18 validators, 60% is 61,
  2/3 is 80, 80% is 146.
- Planned on Solana: bonded committee members and fraud proofs against the program's own queue records (designed, not
  built).
- Mainnet-scale certificates fit at 700 validators with about 8% offline (1,161,881 gas, 42 KB, synthetic) but not in
  the worst case (206 KB).

## Live verification

- Fixture: `test/e2e/fixtures/solana-live/devnet-genesis.json` and `.proof.hex` (captured 2026-10-01T04:05Z from
  `api.devnet.solana.com`, epoch 1171).
- Refresh: `npm run solana-live:refresh`. Replay: `forge test --match-path 'test/verifiers/solana/*'` and
  `npm run test:e2e:solana-live` (6 tests).
- Verified: devnet's Alpenglow genesis certificate at slot 504,148,999 (11 of 17 bitmap ranks, 19-entry set, 8
  non-signers proven, 97.6% of stake) with `verifyFinality` (352,196 gas, 5,572 B), and a full ALPENGLOW-mode
  `verifyBundle` anchored by it (429,023 gas, 7,812 B). Negative cases: wrong shred version, block id, payload kind,
  bitmap bit, set entry, dropped non-signer, set root and epoch.

## Hiero → Solana

Not built; designed. The Solana CLPR program would verify Hiero state proofs and run the CLPR Service logic.

- **What must be verified:** a hinTS aggregate signature (BLS12-381, KZG openings) and a WRAPS proof (Nova IVC with a
  Groth16 decider on BN254, Poseidon over the hinTS key), then a state-proof path to the CLPR Service queue.
- **Costs** (Agave `program-runtime/src/execution_budget.rs`, 1.4M CU per transaction):

  | Operation | CU |
  |---|---|
  | alt_bn128 pairing | 36,364 for the first pair + 12,121 per extra pair |
  | alt_bn128 G1 mul / add | 3,840 / 334 |
  | G2 decompress | 13,610 |
  | Poseidon | 61n² + 542 |
  | BLS12-381 pairing | 25,445 + 13,023 per extra pair |
  | BLS12-381 G1 / G2 mul | 4,627 / 8,255 |
  | BLS12-381 G1 / G2 decompress | 2,100 / 3,050 |

  The WRAPS Groth16 decider is about 4 BN254 pairings (about 73k CU) plus a few MSMs; groth16-solana reports 78-109k CU
  for plain Groth16. hinTS needs about 5 BLS12-381 pairing checks plus MSMs, plus hash-to-G2: SIMD-0388 has no
  map-to-curve syscall, so SSWU runs in BPF, which is the one unmeasured cost and the main risk.
- **Recommended path:** a single Groth16 proof of "hinTS + WRAPS + state path ⇒ (ledgerId, blockRoot, queueRoot)", so
  Solana verifies one Groth16 (about 100k CU) plus one Merkle path. Verifying hinTS and WRAPS directly is the fallback.
- **Blocker:** every Hiero → X direction needs a Hiero proof source (WRAPS and the block node ProofService), which is
  not available yet.
- **Solana-side constraints:** queue PDAs replace EVM storage, fees are lamports, connector escrows are PDAs, and a hot
  queue PDA is limited to 12M CU of writes per block, so heavy channels should shard per-sender message PDAs.
