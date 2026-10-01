# Soneium → Hiero · status: family-covered

Soneium is an OP Stack L2 that settles on Ethereum through dispute games. Its bundles are verified on Hiero by
`OpStackVerifier` (FINALIZED) or `OpStackProposedVerifier` (PROPOSED). Family README:
[src/verifiers/evm/opstack/README.md](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:1868` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee over L1, then `SuperPermissionedDisputeGame` 1.1.0 (type 5) at that L1 state |
| Verifier | `OpStackVerifier` / `OpStackProposedVerifier` ([source](../../src/verifiers/evm/opstack/OpStackVerifierBase.sol)), 17,884 B runtime, with `EthL1StateVerifier` 11,593 B |
| Trust tier | FINALIZED (weaker): sync committee + permissioned proposer and challenger + upgrade key |
| Typical bundle | not measured for this chain; Base Sepolia PROPOSED full bundle: 3,910,935 gas, 46,084 B |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure) |

## Deployment profile

| Value | Soneium | Read from |
|---|---|---|
| `rootFormat` | `SUPER_ROOT_V1` | Game root claim format |
| `l2ChainId` | 1868 | Chain id |
| Settlement | `SuperPermissionedDisputeGame` 1.1.0 (type 5); ASR 3.x | ASR `respectedGameType`, DGF `gameImpls`, probed on L1 on 2026-10-01 |
| `layout` (ASR/DGF/game state) | 1, 2, 3, 5, 6, 0, 4, 103, 0, 0, 8, 16 (family table) | Sourcify storage layouts |
| `gameWasRespectedSlot`, offset | 0, 17 | Sourcify layout of the game implementation |
| `anchorStateRegistry`, `anchorStateRegistryImplCodeHash`, `gameImplementation`, `disputeGameFinalityDelaySeconds` | not recorded in this repo | Read at deployment from the OptimismPortal → ASR → DGF `gameImpls[type]`; the live builder checks them |
| L1 constructor values | `l1GenesisTime` 1606824023, `l1SecondsPerSlot` 12; `EthL1StateVerifier(802, 9, 87, 6, 8192)` | Ethereum mainnet beacon config |

## Relayer requirements

- **Ethereum beacon API**: `light_client/finality_update`, `light_client/bootstrap/{root}`,
  `light_client/updates` (rotation), `beacon/genesis`, `config/spec`.
- **Ethereum execution RPC** (within the non-archive window of about 128 blocks): `eth_getProof` of the
  ASR, its implementation, the DGF and the game; `eth_getCode` of the game; `eth_call` DGF `gameCount` and
  `gameAtIndex`; `eth_getStorageAt` ASR.
- **L2 RPC**: `eth_getBlockByNumber` of the game's L2 block, and `eth_getProof` of the `ClprService` at
  that block. FINALIZED needs a proof at a block older than the finality window: an archive L2 node or a staged proof.
- **Cadence**: one L1 sync-committee rotation per period (8,192 L1 slots, about 27 h).

## Chain-specific trust and caveats

- **Weaker tier.** Permissioned proposer and challenger, plus the sync committee and the upgrade key.
- Super-root games with permissioned roles; the entry for chain 1868 must equal the output root.
- `AnchorStateRegistry.paused()` is not proven (family README, section 4).

## Live verification

None for Soneium. The profile was probed on Ethereum mainnet on 2026-10-01. To add a capture, add the chain to `OPSTACK_LIVE_CHAINS` in `test/e2e/relay/buildOpStackLiveProof.ts` and run the builder with `--chain`.

## Hiero → Soneium direction

Not built. It would deploy the Hiero verifier contracts on Soneium; whether its EVM provides the EIP-2537
precompiles the Hiero verifier needs was not checked in this work.
