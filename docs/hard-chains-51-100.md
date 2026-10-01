# Hard chains, ranks 51-100 (2026-10-01)

Five chains from DefiLlama ranks 51-100 were marked "hard". Each was checked against its current
source code and public endpoints for: finality source and signature scheme, validator-set rotation,
state commitment and public storage proofs, and fit on Hedera (15M gas, 128 KB calldata, EIP-2537,
BN254 and BLAKE2F available, no P-256). Estimates are marked as such; nothing here was measured on
an EVM.

| Chain | Finality | Signatures | State proofs (public) | Class | Blocker / next step |
|---|---|---|---|---|---|
| [Osmosis](chains/osmosis.md) | CometBFT commit, > 2/3 power; 69 validators, 18 clear 2/3 | Ed25519 | yes: ICS-23 IAVL + simple Merkle; recomputed to `app_hash` live | **(a)** `CosmWasmVerifier`, store `wasm`, key `0x03‖contract‖key`, chain id `osmosis-1` | Queue home: code upload is `AnyOfAddresses` (54) or governance; ~26 set changes/h means ~630 rotation bundles/day without skipping verification |
| [STRATO](chains/strato.md) | Blockstanbul PBFT seals, `3·w > 2·W`; 17 validators | secp256k1 over `keccak(blockHash ‖ 0x02)` | no storage proofs; receipt MPT proofs over REST (testnet now; mainnet from block 1,000,000) | **(b)** new `StratoVerifier`: header codec + seals + receipt proof; est. 200–350k gas | Mainnet receipts start at block 1,000,000 (~24 days); CLPR Service must be a SolidVM contract emitting events |
| [Fantom Opera](chains/fantom-opera.md) | Lachesis DAG; LLR block votes in signed events | secp256k1 (64 B, no `v`) | no: `eth_getProof` panics in the Carmen backend | **(c)** | Needs a client with `GetProof` and LLR vote export; 4 validators (2 clear 2/3) |
| [Vite](chains/vite.md) | none (confirmation count) | Ed25519-BLAKE2b, one producer per block | no state root, no proof RPC | **(c)** | No reachable RPC; producer set not provable; at best attestor-trusted |
| [AFX L1](chains/afx.md) | unknown ("Mysticeti" per press) | unknown | none | **(c)** | No source, spec, RPC or signed state; bridge drained and API stale |

## Findings that affect other work

- **Sonic (chain 146)** has no finality certificate in `0xsoniclabs/sonic` main (`c593e51`): LLR is
  off for all Sonic rule sets and there is no BLS committee code. Native verification is not
  possible today; Sonic is buildable only as attestor ("signer") + its working `eth_getProof`
  (MPT, checked live). This matters for the planned "BLS committees (Sonic, Flow, Conflux)" batch.
- **Osmosis** fits `CosmWasmVerifier` with no contract change; a live fixture belongs on the
  CometBFT family branch next to ZIGChain. Its churn makes CometBFT skipping verification the most
  useful improvement to that family.
- **STRATO** is the only (b): finality and receipts are already checked offline with
  `script/hard51/strato_header_check.py`.

## Reproduce

- `python3 script/hard51/osmosis_wasm_proof_check.py osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9`
- `python3 script/hard51/strato_header_check.py https://noderpc.strato.nexus/strato-api/eth/v1.2/block/last/1`

Both use only the Python standard library and public endpoints.
