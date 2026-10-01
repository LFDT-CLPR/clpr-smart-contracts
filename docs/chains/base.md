# Base → Hiero · status: family-covered (same contracts live-verified on Base Sepolia, anvil, 2026-09-30)

Base is an OP Stack L2 that settles on Ethereum through dispute games. Its bundles are verified on Hiero by
`OpStackVerifier` (FINALIZED) or `OpStackProposedVerifier` (PROPOSED). Family README:
[src/verifiers/evm/opstack/README.md](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:8453` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee over L1, then Base `AggregateVerifier` 0.2.0, TEE and ZK provers (type 621) at that L1 state |
| Verifier | `OpStackVerifier` / `OpStackProposedVerifier` ([source](../../src/verifiers/evm/opstack/OpStackVerifierBase.sol)), 17,884 B runtime, with `EthL1StateVerifier` 11,593 B |
| Trust tier | FINALIZED: sync committee + Base proof system (TEE/ZK) + upgrade key; PROPOSED adds the proposer |
| Typical bundle | 3,910,935 gas, 46,084 B (Base Sepolia PROPOSED, full bundle) |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure) |

## Deployment profile

| Value | Base | Read from |
|---|---|---|
| `rootFormat` | `OUTPUT_ROOT` | Game root claim format |
| `l2ChainId` | 8453 | Chain id |
| Settlement | Base `AggregateVerifier` 0.2.0, TEE and ZK provers (type 621); ASR 3.7.0, `DISPUTE_GAME_FINALITY_DELAY_SECONDS` 0 | ASR `respectedGameType`, DGF `gameImpls`, probed on L1 on 2026-10-01 |
| `layout` (ASR/DGF/game state) | 1, 2, 3, 5, 6, 0, 4, 103, 0, 0, 8, 16 (family table) | Sourcify storage layouts |
| `gameWasRespectedSlot`, offset | 0, 18 | Sourcify layout of the game implementation |
| `anchorStateRegistry`, `anchorStateRegistryImplCodeHash`, `gameImplementation`, `disputeGameFinalityDelaySeconds` | not recorded in this repo | Read at deployment from the OptimismPortal → ASR → DGF `gameImpls[type]`; the live builder checks them |
| L1 constructor values | `l1GenesisTime` 1606824023, `l1SecondsPerSlot` 12; `EthL1StateVerifier(802, 9, 87, 6, 8192)` | Ethereum mainnet beacon config |

## Relayer requirements

- **Ethereum beacon API**: `light_client/finality_update`, `light_client/bootstrap/{root}`,
  `light_client/updates` (rotation), `beacon/genesis`, `config/spec`.
- **Ethereum execution RPC** (within the non-archive window of about 128 blocks): `eth_getProof` of the
  ASR, its implementation, the DGF and the game; `eth_getCode` of the game; `eth_call` DGF `gameCount` and
  `gameAtIndex`; `eth_getStorageAt` ASR.
- **L2 RPC**: `eth_getBlockByNumber` of the game's L2 block, and `eth_getProof` of the `ClprService` at
  that block. FINALIZED needs a proof at a block past the finality delay; with delay 0 this is game resolution time, so an archive L2 node or a staged proof is needed if the block has left the RPC window.
- **Cadence**: one L1 sync-committee rotation per period (8,192 L1 slots, about 27 h).

## Chain-specific trust and caveats

- FINALIZED trusts the sync committee, Base's fault-proof contracts and their upgrade key, and the TEE and ZK provers behind `AggregateVerifier`.
- Same layout as Base Sepolia (verified live). The finality delay is 0, so a resolved `DEFENDER_WINS` game is final at once.
- Base Sepolia's games took about 5 days to become final in the capture; Base mainnet timing was not measured here.
- `AnchorStateRegistry.paused()` is not proven (family README, section 4).

## Live verification

No Base mainnet capture. Base Sepolia (`eip155:84532`, ASR `0x2fF5cC82dBf333Ea30D8ee462178ab1707315355` 3.7.0, OptimismPortal `0x49f53e41452C74589E85cA1677426Ba426459e85`) is live-verified: `test/e2e/fixtures/base-sepolia-live/capture.json` (captured 2026-09-30, Sepolia slot 11255476, 493/512), replay `forge build && npm run test:e2e:opstack-live`, refresh `npm run opstack-live:refresh`. PROPOSED full `verifyBundle` 3,910,935 gas, 46,084 B; FINALIZED `verifyL2StateRoot` GAME 2,765,246 gas, ANCHOR 2,473,604 gas. One game's L2 proofs are staged under `pending/` for a full FINALIZED bundle.

## Hiero → Base direction

Not built. It would deploy the Hiero verifier contracts on Base; whether its EVM provides the EIP-2537
precompiles the Hiero verifier needs was not checked in this work.
