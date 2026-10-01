# Ontology → Hiero

Ontology → Hiero · status: blocked (no EVM state proofs; not covered by the signer-replay verifier)

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Ontology EVM `58` / `eip155:58` (mainnet), `5851` / `eip155:5851` (Polaris testnet), read with `eth_chainId` |
| Chain type | L1, Ontology node (ontio/ontology) with VBFT consensus and an EVM layer |
| Finality source | VBFT: a header is signed by its bookkeepers (`Bookkeepers` + `SigData` in the header) |
| Verifier | None |
| Trust tier | n/a |
| Typical bundle | n/a |
| Rotation | n/a |

## Deployment profile

None. What was checked (ontio/ontology commit `1d2d81e`, live mainnet height 20,877,486 on 2026-10-01):

| Item | Finding | Source |
|---|---|---|
| Header | `Version, PrevBlockHash, TransactionsRoot, BlockRoot, Timestamp, Height, ConsensusData, ConsensusPayload, NextBookkeeper, Bookkeepers, SigData`; hash = SHA-256(SHA-256(unsigned header)) | `core/types/header.go` |
| Signatures | Bookkeeper keys are 33-byte compressed keys (`02…`), the default Ontology key type (ECDSA P-256) | Live header at height 20,877,000 |
| State commitment | No world-state trie root in the header; `StateMerkleRoot` is a running hash of per-block write sets | `core/store/ledgerstore/state_store.go` |
| EVM storage proofs | `eth_getProof` returns "eth_getProof is not supported" | `http/ethrpc/eth/api.go` |

## Relayer requirements

n/a.

## Chain-specific trust and caveats

Ontology does not fit the signer-replay family: its headers are not Ethereum headers and are signed with P-256
multisignatures, and there is no Merkle-Patricia state to prove the ClprService queue against. A verifier would need
a different design, for example one built on Ontology's native cross-chain contract
(`smartcontract/service/native/cross_chain`) and VBFT bookkeeper signatures (P-256). That path, its P-256 cost on
Hedera and its data source were not investigated further on this branch.

## Live verification

None. The public endpoints `dappnode1.ont.io:20339` (mainnet) and `polaris1.ont.io:20339` (testnet) answered
`eth_chainId`; the REST API (`:20334`) returned blocks.

## Hiero → Ontology

Not built.
