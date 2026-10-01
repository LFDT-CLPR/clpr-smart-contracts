# Monad → Hiero

Status: certificates live-verified; full bundle needs own node. Quorum certificates live-verified on Monad mainnet
and testnet (2026-10-01); page proofs verified against Monad's C++ vectors and synthetic data only.

> **Limitation.** Full live bundles (certificate + storage proof against a real ClprService queue) are **not**
> verified. No public Monad RPC serves `eth_getProof` or consensus headers (29 public endpoints checked on
> 2026-10-01). A relayer needs its own Monad node: x86-64 Linux on bare metal with about 2.5 TB of NVMe.
>
> - **Verified on live data:** the quorum certificate (BLS aggregate, signer bitmap, stake supermajority) for
>   mainnet epoch 2190 (196 validators) and testnet epoch 1343 (199 validators), on-chain on anvil.
> - **Verified only against vectors or synthetic data:** the MIP-8 page proofs (BLAKE3 page commitment against
>   Monad's C++ reference vectors; MPT path, account proof, consensus headers and rotation against the synthetic
>   196-validator fixture).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `143` / `eip155:143`; testnet `10143` / `eip155:10143` |
| Chain type | L1, MonadBFT consensus with asynchronous (delayed) execution, EVM |
| Finality source | QC of ≥ ⌊2·total/3⌋ + 1 of the epoch's stake on block B with round = B.qc.round + 1, committing B's parent P; state root from P's delayed result (block `P.seq_num − 3`) |
| Verifier | `MonadVerifier` + `MonadValsetRotation` ([family README](../../src/verifiers/evm/monad/README.md)) |
| Trust tier | Fewer than 1/3 of each epoch's stake Byzantine; bootstrap validator set trusted |
| Typical bundle | Synthetic, 196 validators: 1.43M execution gas, 37.1 KB calldata, 1.89M tx gas. Live QC check (mainnet): about 0.98M gas, 32 KB |
| Rotation | Synthetic, 196 validators: warm 4 transactions (about 35M gas total, each ≤ 10.2M gas and ≤ 85 KB); cold 8 transactions (each ≤ 12.2M gas and ≤ 72 KB) |

## Deployment profile

| Parameter | Mainnet | Testnet | Source |
|---|---|---|---|
| `chainId` (config string) | `143` | `10143` | `eth_chainId`; fixture `chainId` |
| Bootstrap epoch (fixture) | 2190 | 1343 | forkpoint `high_certificate.Qc.info.epoch` in `capture.json` |
| Validators at capture | 196 | 199 | `validators/<net>/validators.toml`, epoch section |
| Bootstrap validator set | `valsetBlob` (G1 key 128 B ‖ stake 32 B, ascending compressed secp key order) | same | `validators.toml`, cross-checked against staking precompile storage |
| Key registry (optional) | keys of the bootstrap set | same | staking `val_execution(id).keys` |
| ClprService address and code hash | Not deployed on Monad yet | same | — |
| Epoch length | 50,000 blocks (about 5.5 h) | 50,000 blocks | forkpoint `validator_sets` rounds; Monad docs |
| Protocol constants | `EXECUTION_DELAY = 3`, `MAX_VALIDATORS = 200`, MIP-8 paged storage (mainnet since 2026-09-02) | MIP-8 since 2026-08-12 | `MonadVerifier.sol`; family README "Protocol facts" |

## Relayer requirements

- **Own Monad full node** (required). x86-64 with AVX2, Linux with io_uring (Ubuntu 24.04), 16 cores at 4.5 GHz or
  more, 32 GB of RAM or more, bare metal, a dedicated 2 TB NVMe for TrieDB plus 500 GB. A Mac cannot run it.
- **Consensus headers** P, B and B's child (for the QC on B) from the node's `ledger/headers/`. No RPC serves them.
- **Storage proofs**: a proof tool on `category/mpt` reading `/dev/triedb` that emits the ClprService account path
  and MIP-8 page leaves in the `channelPages` format. It does not exist yet; `eth_getProof` is not implemented in
  `monad-rpc`.
- Standard RPC: `eth_getBlockByNumber`, `eth_chainId`.
- Rotation cadence: one epoch every 50,000 blocks. The rotation must start inside epoch E's delay period, so the
  relayer must watch every epoch boundary.
- No signature aggregator: the QC on B is in B's child header.

## Chain-specific trust and caveats

- Same as the family baseline (Monad is the only chain in the family).
- The verifier proves paged (MIP-8) storage only; it cannot prove state from before MIP-8 activation.
- No ClprService is deployed on Monad, so even with an own node a live bundle needs a deployment first.

## Live verification

- Fixture: `test/e2e/fixtures/monad-live/capture.json` (mainnet captured 2026-10-01T03:34Z, testnet 03:35Z):
  forkpoint QC, validator sets, staking-precompile storage at a pinned block, Ethereum header.
- Refresh: `npm run monad-live:refresh`.
- Replay: `forge build && npm run test:e2e:monad-live`.
- Verified on live data: the QC signature and stake supermajority on-chain through `verifyQuorumCertificate`
  (mainnet 116 signers of 196, testnet 136 of 199), with negative cases (tampered vote, cleared signer bit, wrong
  stakes, swapped keys, mismatched uncompressed signature); off-chain, the staking storage decodes to the next
  epoch's published set, and the Ethereum header hashes to the block hash.
- Not verified on live data: consensus headers P/B, the commit rule, account and page proofs, a full bundle and a
  rotation. These run on the synthetic fixture (`test/verifiers/evm/monad/fixtures/synthetic`) and the C++ page
  vectors.

## Hiero → Monad

Not built on this branch. Monad runs the EVM, so the direction would use the reference Hiero verifier deployed on
Monad (EIP-2537 is available). It is blocked on the same Hiero proof source as Hiero → Ethereum.
