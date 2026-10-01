# MultiversX → Hiero

MultiversX → Hiero · status: in progress (consensus half live-verified on MultiversX mainnet, 2026-10-01; storage proofs and validator-set rotation blocked on public endpoints)

MultiversX shards are notarised by the metachain, and since Andromeda every header gets an equivalent
proof: an aggregated BLS signature of more than 2/3 of the 400 eligible validators of its shard.
`MvxMetachainVerifier` checks a header and its proof on Hedera against an eligible list pinned at
deployment. It is not yet an `IClprVerifier`. Full design and blockers:
[family README](../../src/verifiers/icpmvx/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `mvx:1` (`erd_chain_id` `1`) |
| Chain type | L1, 3 shards + metachain, Secure Proof of Stake; 400 eligible validators per shard and in the metachain; 600 ms rounds; epochs of 144,000 rounds |
| Finality source | Header equivalent proof: aggregated BLS (BLS12-381, keys in G2, signatures in G1, herumi non-IETF mode) of ≥ n·2/3 + 1 eligible validators over BLAKE2b-256(header) |
| Verifier contract | `src/verifiers/icpmvx/MvxMetachainVerifier.sol` (consensus only) · [family README](../../src/verifiers/icpmvx/README.md) |
| Trust tier | > 2/3 of the pinned eligible list; the list itself is taken from `api.multiversx.com` (not proven) |
| Typical bundle | No bundle path. Metachain header proof: 3,394,220 gas, 104,036 B per transaction |
| Rotation | Not implemented: needs proofs the public endpoints do not serve |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `epoch` | 2249 (fixture) | `test/e2e/fixtures/mvx-live/mainnet.json` (`meta.epoch`) |
| `n` | 400 | `gateway.multiversx.com/network/config` (`erd_meta_consensus_group_size`, `erd_shard_consensus_group_size`) |
| `keysHash` (metachain) | `0x205f29508be32fe4e09a5e5fcfcb3e51bdfd698cc5af9de064faf571b99a899b` | keccak256 of the uncompressed list in `meta.keys`, order from `api.multiversx.com/blocks/<hash>` (`validators`) |
| `keysHash` (shard 0) | `0xab40d777a657650ce03c73a9dc32d23df2635e77f1c4c7975a408c3c95349b7b` | `shard0.keys` |
| BLS scheme | herumi bls-go-binary v1.37.0 without `BLS_ETH`: mcl original map to G1 from SHA-512, G2 generator mapToG2(1) | mx-chain-crypto-go `signing/mcl`, herumi/bls `86c167d` `bls_c_impl.hpp`, herumi/mcl `map_impl.hpp` |
| Threshold | `n·2/3 + 1` (267 of 400) | mx-chain-core-go `core/common.go:GetPBFTThreshold` |

## Relayer requirements

- Header bytes: gateway `/internal/<shard>/raw/block/by-nonce/<nonce>` (base64 protobuf;
  BLAKE2b-256 of it is the header hash).
- Proof and ordered eligible list: `api.multiversx.com/blocks/<hash>` (`proof.aggregatedSignature`,
  `proof.pubKeysBitmap`, `validators`).
- Decompress mcl-format keys (96 B) and signatures (48 B) to EIP-2537 form (`test/e2e/relay/mvx.ts`).
- For CLPR storage: an own observing node with the proof routes enabled
  (`/proof/root-hash/:roothash/address/:address/key/:key`); the public gateways return 404.

## Chain-specific trust and caveats

- The eligible list is pinned per deployment and not proven from the previous epoch; that is a weaker
  tier than the family's ICP verifier.
- Andromeda sets the consensus group to the whole eligible list, so the bitmap is over 400 keys in
  nodes-coordinator order (sorted by `IndexInList`, then key).
- State roots come in later headers' `executionResults` (`MetaBlockV3`); no storage path is built.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/mvx-live/mainnet.json` |
| Captured | 2026-10-01T08:53:43Z; metachain header nonce 34,295,162 (round 35,126,424, epoch 2249), shard-0 header nonce 34,324,116 |
| Refresh | `npm run mvx-live:refresh` |
| Replay | `forge build && npm run test:e2e:mvx-live`; Foundry: `forge test --match-path test/verifiers/icpmvx/MvxLive.t.sol -vv` |
| What was verified | BLAKE2b-256(raw header) = header hash; the metachain proof (281 of 400 signers) and the shard-0 proof (277 of 400); the leader's single signature over the previous random seed; rejections of a tampered header, another eligible list, a bitmap below threshold, a missing signer, a wrong epoch and a bad bitmap |

## Hiero → MultiversX direction

Not started on this branch. It needs a Hiero verifier as a MultiversX (WASM) smart contract.
