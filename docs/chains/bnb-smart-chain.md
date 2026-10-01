# BNB Smart Chain → Hiero

Status: live-verified on BSC mainnet and BSC testnet Chapel (2026-10-01).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `56` / `eip155:56`; Chapel testnet `97` / `eip155:97` |
| Chain type | L1, Parlia proof of staked authority with BEP-126 fast finality |
| Finality source | BLS vote attestation of at least 2/3 of the validator set, `target = source + 1` |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)) |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted |
| Typical bundle | Mainnet: 1,953,408 gas (`eth_estimateGas`), 23,684 B calldata. Chapel: 1,772,152 gas, 18,724 B |
| Rotation | Mainnet: +412,079 execution gas and +5,376 B per rotation (2,439,616 gas, 29,060 B with one rotation). Chapel: 2,177,714 gas, 21,732 B with one rotation |

## Deployment profile

| Parameter | Mainnet | Chapel | Source |
|---|---|---|---|
| `chainId` | 56 | 97 | `eth_chainId`; `NETWORKS` in `test/e2e/relay/buildBscLiveProof.ts` |
| `epochLength` | 1000 | 1000 | `EPOCH_LENGTH` in the capture script (Maxwell, BEP-524); fixture `epochLength` |
| Validators at capture | 21 | 9 | Epoch block `extraData`; vectors `validators` |
| `turnLength` | 8 | 8 | Epoch block `extraData` (BEP-341) |
| Bootstrap epoch block (fixture) | 125,020,000 | 134,166,000 | Vectors `anchorEpoch` |
| `activeFrom` | `E + checkLen + 1` of the previous set; set per bootstrap | same | `verifyConfig` input, see family README |
| ClprService code hash | Code hash of the deployed ClprService; the fixtures pin WBNB's code hash | same | `eth_getProof` `codeHash` |
| Live probe account | WBNB `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB `0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd` | `NETWORKS` in the capture script |

## Relayer requirements

- RPC methods: `eth_chainId`, `eth_getBlockByNumber` (epoch blocks, the blocks that carry finalizing attestations,
  the state block), `eth_getProof` (ClprService account and channel slots).
- Rotation cadence: one epoch every 1000 blocks; in the fixtures 450 s apart. On mainnet the set changes in almost
  every epoch (BEP-131), so the relayer must submit at least one bundle per epoch or carry the missed rotations.
- Catch-up: about 19 rotations fit in 128 KB at mainnet sizes (about 2.4 hours). Longer gaps need `eth_getProof` at
  historical blocks, so a node with state history. Public RPCs serve `eth_getProof` only for recent blocks.
- No signature aggregator: the attestation is in the next block header.

## Chain-specific trust and caveats

- Same as the family baseline. BSC's 21-validator mainnet set changes nearly every epoch, which makes rotation
  cost a standing part of the relay budget.
- No ClprService is deployed on BSC yet; the live storage proofs are exclusion proofs on WBNB.

## Live verification

- Fixtures: `test/e2e/fixtures/bsc-live/mainnet.json`, `chapel.json` (captured 2026-10-01T02:36Z) and the
  `*-vectors.json` files built from them.
- Refresh: `npm run bsc-live:refresh`, then `npx tsx test/e2e/relay/buildBscLiveProof.ts --vectors`.
- Replay: `forge test --match-contract BscParliaLive -vv` and `npm run test:e2e:bsc-live`.
- Verified: `verifyConfig` from a real epoch block; one real epoch rotation (mainnet: a real set change) finalized
  by the outgoing set; a finalized state block (mainnet 20 of 21 votes, Chapel 9 of 9); the account proof and the
  channel-slot exclusion proofs; negative cases (tampered signature, dropped voter bit, wrong set, tampered storage
  node, other chain id).

## Hiero → BNB Smart Chain

Not built on this branch. BSC runs the EVM, so the direction would use the reference Hiero verifier deployed on BSC.
It is blocked on the same Hiero proof source as Hiero → Ethereum.
