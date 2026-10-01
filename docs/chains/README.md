# Chain pages

One page per chain researched on this branch: the five "hard" chains of DefiLlama ranks 51-100.
The summary with the comparison table is in [../hard-chains-51-100.md](../hard-chains-51-100.md).

| Chain | Class | Verifier | Status | Page |
|---|---|---|---|---|
| Osmosis | (a) existing family | `CosmWasmVerifier` (CometBFT family) | family-covered; proof path checked live (2026-10-01); no CLPR Service until a governance or allow-listed code upload | [osmosis.md](osmosis.md) |
| STRATO | (b) new verifier | `StratoVerifier` (sketch: Blockstanbul seals + receipt MPT proof) | in progress; mainnet blocked until receipts are committed at block 1,000,000 | [strato.md](strato.md) |
| Fantom Opera | (c) blocked | none | blocked: no `eth_getProof` (Carmen backend) and no public LLR vote export | [fantom-opera.md](fantom-opera.md) |
| Vite | (c) blocked | none | blocked: no reachable RPC, single-producer blocks, no state root | [vite.md](vite.md) |
| AFX L1 | (c) blocked | none | blocked: no node source, no RPC, no signed state commitment | [afx.md](afx.md) |
