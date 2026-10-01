# Conflux → Hiero

Conflux → Hiero · status: in progress — finality half live-verified on Conflux mainnet (2026-10-01); storage proofs blocked

Conflux's PoS chain finalizes the PoW pivot chain. `ConfluxPosLightClient` checks the PoS
committee's aggregated BLS signature on a ledger info, follows committee rotations, and authenticates
the finalized pivot block header, returning its deferred state root (the eSpace state root). It
stops there: no public RPC serves Conflux state-trie proofs. Full design:
[family README](../../src/verifiers/evm/blscommittees/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | eSpace 1030 / `eip155:1030`; core space 1029 |
| Chain type | L1: PoW tree-graph with a PoS finality layer (Diem-derived); eSpace is the EVM space |
| Finality source | PoS ledger info with pivot decision; BLS12-381 min-pk aggregate, signed power ≥ `quorum_voting_power` |
| Contract | `src/verifiers/evm/blscommittees/ConfluxPosLightClient.sol` · [family README](../../src/verifiers/evm/blscommittees/README.md) |
| Trust tier | > 2/3 of PoS voting power per epoch; deploy-time committee checkpoint |
| Typical proof | 446,398 gas / 4,356 B (finality + pivot header; no storage proof) |
| Rotation | 1,000,171 gas / 10,180 B per PoS epoch (25 validators) |

## Deployment profile

| Parameter | Mainnet value (fixture) | Read from |
|---|---|---|
| `bootstrapEpoch` | `46113` | `test/e2e/fixtures/conflux-live/vectors.json` (`bootstrap.epoch`) |
| `bootstrapCommitteeHash` | `0x2809678f64963979cd4a6b779c51d311767ca58c87f9ab327d3cd8601e53167e` | `vectors.json` (`bootstrap.hash`), built from `pos_getLedgerInfoByEpoch(46112)` → `nextEpochState` + `nextEpochValidators` |
| Committee size / total / quorum | 24 validators, 300, 201 (epoch 46113); 25, 300, 201 (epoch 46114) | `vectors.json` (`bootstrap`, `next`) |
| BLS DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` | `ConfluxPosLightClient.DST` |
| Signing seed | `0xcd510d1a…df1b62` = SHA3-256("DIEM::LedgerInfo") | `ClprConfluxPos.LEDGER_INFO_SEED`; checked in `buildConfluxLiveProof.ts` |

Use a recent epoch for a real deployment: the bootstrap committee hash of epoch `E` is computed
from the last ledger info of epoch `E − 1` (`buildConfluxLiveProof.ts:committeeFrom`).

## Relayer requirements

- Core-space RPC: `pos_getStatus`, `pos_getLedgerInfoByEpoch`, `pos_getLedgerInfoByBlockNumber`,
  `cfx_getBlockByHash`. eSpace RPC: `eth_getBlockByNumber` (for the eSpace base fee in the header
  RLP and the stateRoot cross-check). Public: `https://main.confluxrpc.com`, `https://evm.confluxrpc.com`.
- Header RLP: `cfx_getBlockByHash` shows the gas limit as 90% of the header value (multiply by
  10/9); `custom` items are appended raw inside the list; the miner is a base32 `cfx:` address.
- Signer bitmap: committee in address order; bit `i` = byte `i/8`, LSB first.
- Rotations: one per PoS epoch (about 1 h in the fixture). Advance the anchor at least every ~12
  epochs so a catch-up fits 128 KB.
- Storage proofs: need an own conflux-rust node and a Conflux state-trie proof format; not available
  from public RPCs.

## Chain-specific trust and caveats

- Pivot blocks with blame ≠ 0 are rejected (their state-root field is a blame-vector commitment).
- The deferred state root is the state after epoch `height − 5`.
- `pos_getLedgerInfoByEpoch` is a "debug rpc" in conflux-rust; public endpoints serve it today.

## Live verification

- Fixture: `test/e2e/fixtures/conflux-live/` (captured 2026-10-01T08:13:32Z; epochs 46113 → 46114;
  pivot block 158,034,960, hash `0xdf4cb961…9445813`; deferred state root `0x2caf7673…c599d44`,
  equal to the eSpace `stateRoot` at that height).
- Refresh: `npm run conflux-live:refresh`. Replay: `npm run test:e2e:conflux-live`.
- Verified: a real rotation (24 of 24 signers, committee grew to 25), a ledger info with 25 of 25
  signers, the pivot header hash, and the state root cross-check. Foundry negatives in
  `test/verifiers/evm/blscommittees/ConfluxPosLightClient.t.sol`.

## Hiero → Conflux direction

Not started. eSpace runs EVM contracts, so the Hiero-side verifiers deployed on other EVM chains
are the starting point; this needs an eSpace deployment of the ClprService and a check of eSpace
precompile support (BLS12-381, BN254).
