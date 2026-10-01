# Citrea

Citrea → Hiero · status: blocked (no verifier built; design notes only)

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:4114` (`eth_chainId` on `rpc.mainnet.citrea.xyz`, 2026-10-01) |
| Chain type | Bitcoin zk rollup (Chainway); EVM execution, state committed by ZK proofs written to Bitcoin |
| Finality source | Batch proofs inscribed on Bitcoin (taproot witness), which a Bitcoin light client would have to read |
| Verifier | none. Family README: [L1-settled rollup verifiers](../../src/verifiers/evm/zkrollup/README.md) ("Limits and known gaps") |
| Trust tier | would be: Bitcoin proof of work + Citrea's ZK proofs; not available |
| Typical bundle / rotation | not applicable |

## Deployment profile

None. Citrea does not settle on Ethereum, so the family's `L1RollupStateRoot` profile does not apply.

## Relayer requirements

Not applicable until a verifier exists.

## Chain-specific trust and caveats

Why the repository's Bitcoin proof-of-work verifier cannot carry Citrea's proofs (checked against chainwayxyz/citrea at
commit f11527f9, 2026-09-11):

- Citrea writes its data and proofs into the **witness** of taproot reveal transactions, as `Complete` bodies or as
  `Aggregate` + `Chunk` transactions for large proofs (`crates/bitcoin-da/src/helpers/parsers.rs`). Citrea's own DA
  verifier checks them through **wtxids** and the coinbase witness commitment (`crates/bitcoin-da/src/verifier.rs`).
  The repository's `BitcoinVerifier` proves transactions by txid Merkle branch, which does not commit to witness data.
- The proof body is **brotli-compressed** (quality 11, `crates/primitives/src/compression.rs`); a verifier would have
  to decompress it on-chain before reading the proof's public output.
- The proof itself is a RISC Zero or SP1 receipt (the repository has `guests/risc0/batch-proof` and
  `guests/sp1/batch-proof-bitcoin`); the EVM side
  would need the matching Groth16 wrapper verifier and the guest's journal layout.
- The L2 state is a Jellyfish Merkle Tree (Sovereign SDK `sov-state`), not an MPT, so a storage-proof verifier would
  also be new.

Brotli decompression of a multi-kilobyte proof inside one Hedera transaction (15M gas) is not practical, and chunk
reassembly across several Bitcoin transactions multiplies the SPV work. A workable design would need Citrea to publish
an uncompressed, single-transaction proof commitment (or an Ethereum-side verifier contract) first.

## Live verification

None.

## Hiero → Citrea direction

Not covered. Citrea runs the EVM, so a Hiero verifier deployed on Citrea would work like on other EVM chains; it does
not depend on the blocked direction above.
