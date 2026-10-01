# Tezos → Hiero

Tezos → Hiero · status: live-verified on Tezos mainnet (2026-10-01, level 15,181,989; finality and context proofs — no Tezos CLPR Service is deployed yet)

Tezos finalizes with Tenderbake: bakers attest a block's payload, and a quorum of attestations on
the payload of level L makes block L−1 final. `TezosVerifier` is a Tenderbake light client on
Hedera. From a trusted Tezos state it reads the attested cycle's slot rights, verifies tz1, tz2,
tz3 and tz4 attestations, re-draws the signers' slots, and proves the CLPR Service's big_map entries
with Irmin Merkle proofs into the Tezos context. Full design:
[family README](../../src/verifiers/evm/tezos/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `tezos:NetXdQprcVkpaWU` (chain id bytes `0x7a06a770`) |
| Chain type | L1, Tenderbake BFT, 6 s blocks, protocol 025 PsUshuai |
| Finality source | Attestations owning ≥ 4,667 of 7,000 committee slots on the payload of level L (block L−1 final) |
| Verifier contract | `src/verifiers/evm/tezos/TezosVerifier.sol` · [family README](../../src/verifiers/evm/tezos/README.md) |
| Trust tier | < 1/3 of a cycle's committee slots Byzantine; deploy-time checkpoint; pinned CLPR contract and big_map |
| Typical bundle | One transaction: 11,402,659 gas, 79,492 B. Cached: 7,002,485 gas, 98,372 B after 4 cache transactions (8.89M, 8.88M, 3.12M, 6.87M gas) |
| Rotation | A bundle whose state is in a later cycle (every ≤ 2 cycles, 24 h each): 11,398,689 gas, 79,364 B inline |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `chainId` | `0x7a06a770` | `GET /chains/main/blocks/head` → `chain_id` |
| `protocolLevel` | 25 | block header `proto` |
| `eraFirstLevel` / `eraFirstCycle` / `blocksPerCycle` | 15,168,289 / 1369 / 14,400 | `metadata.level_info` (cycle 1369 starts at 15,168,289), `context/constants` |
| `committeeSize` / `threshold` | 7,000 / 4,667 | `consensus_committee_size`, `consensus_threshold_size` |
| `consensus_rights_delay` | 2 (rights fixed 2 cycles ahead) | `context/constants` |
| Checkpoint (tests) | level 15,181,967, root `0xfc27f2e1…7ffb`; previous-cycle anchor level 15,167,539 | `test/e2e/fixtures/tezos-live/mainnet.json` |
| `serviceAddress` / `bigMapId` | the CLPR Michelson contract (22-byte id `0x01 ‖ hash ‖ 0x00`) and its big_map | origination; `verifyConfig` proves the contract's storage is `Int <id>` |
| `Ed25519Verifier`, `TezosSignatureCache`, `TezosContextVerifier` | shared deployments | `src/verifiers/evm/sei/Ed25519Verifier.sol`, `src/verifiers/evm/tezos/` |

## Relayer requirements

- Tezos RPC: `/chains/main/blocks/<L+1>` (attestations for L), `/blocks/<L>` (payload round and
  payload operations), `/blocks/<L-1>/header/raw`, `/blocks/<L-2>` (timestamp, fitness, operation
  count and context for the commit preimage), and `context/merkle_tree_v2/<path>` at the anchor block
  (sampler and seed of L's cycle) and at block L−2 (CLPR big_map entries). Reference:
  `test/e2e/relay/buildTezosLiveFixture.ts`.
- `merkle_tree_v2` is needed. At capture only `https://rpc.tzbeta.net` served it (rpc.tzkt.io: 403;
  mainnet.smartpy.io: empty). An own node is the reliable source; it must keep the anchor block's
  context (up to two cycles, 28,800 blocks).
- Off-chain work: uncompressed BLS keys (G1) and the aggregate signature (G2), secp256k1/P-256 `y`
  coordinates, and the slot owners of each attester (to pick a signer set).
- Cadence: one bundle at least every two cycles (about 48 h) keeps the anchor fresh; bundles may be
  submitted every block.

## Chain-specific trust and caveats

- No CLPR Service exists on Tezos. The storage profile (one `big_map bytes bytes`; `"q" ‖ channelId`,
  `"m"`, `"c"`) is a design; the live tests prove a tzBTC ledger entry and the tzBTC contract storage.
- Key mix at capture: 196 delegates (75 tz1, 7 tz2, 31 tz3, 83 tz4). P-256 has no precompile on
  Hedera; tz3 signatures are verified in Solidity (about 275k gas each).
- The verifier refuses anchors that schedule "all bakers attest" (activated when half of the bakers
  use tz4 keys) and does not support SWRR lotteries; both would need a new verifier.
- Forbidden (denounced) delegates are not excluded; safe under the 1/3 assumption.

## Live verification

- Fixture: `test/e2e/fixtures/tezos-live/capture.json` (RPC data) and `mainnet.json` (proofs).
- Refresh: `npm run tezos-live:refresh` (set `TEZOS_RPC` to use another node).
- Replay: `forge build && npm run test:e2e:tezos-live`, and `forge test --match-contract TezosLiveTest`.
- Verified on 2026-10-01: the quorum of level 15,181,989 (47 tz1, 4 tz2, 25 tz3 attestations and a
  65-member tz4 aggregate, 6,942 of 7,000 slots), from a same-cycle anchor and from a cycle-1368
  anchor, the commit of the state after level 15,181,987, a tzBTC big_map entry and the tzBTC
  storage under it; negative cases with a tampered signature, a dropped aggregate and a wrong anchor.

## Hiero → Tezos direction

Not built. Michelson has BLS12-381 types and a `PAIRING_CHECK` instruction but no BN254 operations,
so Hiero's BN254 proofs cannot be checked natively in a Michelson contract. Options are a Michelson
BN254 implementation (gas-bound), a Groth16 wrapper over BLS12-381, or routing through Etherlink,
whose EVM has the BN254 precompiles.
