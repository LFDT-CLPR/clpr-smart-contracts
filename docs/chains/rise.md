# RISE → Hiero

RISE → Hiero · status: live-verified on Ethereum mainnet to the RISE state root (2026-10-01)

RISE (chain 4153) is an OP Stack L2 that settles on Ethereum through OP Succinct Lite dispute games.
`OpStackVerifier` (FINALIZED) and `OpStackProposedVerifier` (PROPOSED) prove, from a header the
Ethereum sync committee signs, that RISE's AnchorStateRegistry accepts an output root, then walk
the RISE state down to the ClprService queue slots. Full design:
[OP Stack verifiers README](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 4153 / `eip155:4153` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee → AnchorStateRegistry 3.5.0 → OPSuccinctFaultDisputeGame (game type 42) |
| Verifier contract | `OpStackVerifier` / `OpStackProposedVerifier` with [`RiseProfile`](../../src/verifiers/evm/opstack/profiles/RiseProfile.sol) · [family README](../../src/verifiers/evm/opstack/README.md) |
| Trust tier | Weaker: permissioned challenger set with a 1-day window, upgrade keys with no delay (below) |
| Typical bundle | FINALIZED `verifyL2StateRoot`, GAME mode: 2,596,353 gas, 28,868 B (anvil `eth_estimateGas`, 510/512 signers). No full bundle captured yet |
| Rotation | Adds the next sync committee: 66,902 B and about 4.84M gas (EthMainnetVerifier README, real Fulu rotation); not measured on this fixture |

## Deployment profile

Constructor: `new OpStackVerifier(l1StateVerifier, 1606824023, 12, RiseProfile.profile())`.

| Parameter | Value | Read from |
|---|---|---|
| `rootFormat` | `OUTPUT_ROOT` | game `rootClaim` = output root of the L2 header (builder cross-check) |
| `l2ChainId` | 4153 | chain id |
| `anchorStateRegistry` | `0x551A672d703966D83C3EC3ea0e844f43c3373c91` | OptimismPortal `0xad92…db4C` (5.1.1) `anchorStateRegistry()`, checked at every capture |
| `anchorStateRegistryImplCodeHash` | code hash of implementation `0xeb69…cf2e` (3.5.0, X Layer's bytecode) | `eth_getProof` at the captured L1 block |
| `disputeGameFinalityDelaySeconds` | 302,400 (3.5 days) | ASR implementation immutable |
| `gameImplementation` | `0xBf60dBc272833cD25f0426983c3175C32C8E5A7a` (OPSuccinctFaultDisputeGame, `version()` 1.0.0) | DGF `0x6A41…1aA3` (1.3.0) `gameImpls(42)` |
| `gameArgsHash` | 0 (DGF 1.3.0 has no game args) | DGF |
| `layout` | `OP_SUCCINCT_LITE_LAYOUT`: ASR slots 1, 2, 3, 5, 6; DGF games slot 103; game state slot 0, wasRespected slot 9 | Sourcify layouts, checked against live storage |
| L1 beacon layout | `EthL1StateVerifier(802, 9, 87, 6, 8192)` (Electra/Fulu) | family README §6 |

## Relayer requirements

- L1: a beacon API (`finality_update`, bootstrap) and an execution RPC serving `eth_getProof` for
  the ASR, its implementation, the DGF and the game at the signed block (the public
  `ethereum-rpc.publicnode.com` works inside its ~128-block state window).
- L2: `eth_getBlockByNumber` for the claimed block, and `eth_getProof` of the ClprService there.
  `rpc.risechain.com` serves `eth_getProof` for recent blocks only. A full FINALIZED bundle needs
  the proof of a block 3.5 days old: stage it while recent (`--stage-next`, as for X Layer) or run
  an archive node.
- Rotations follow the Ethereum sync committee: one rotation per 8,192 slots (about 27 h).

## Chain-specific trust and caveats

- FINALIZED trusts, besides the sync committee: the permissioned challenger set (AccessManager
  `0xF90a…2d17`, `challengers[address(0)]` is false). An unchallenged game resolves without a proof
  after the 1-day window, so a wrong root is accepted unless a listed challenger acts.
- SP1 (verifier gateway `0x3B60…185e`) decides challenged games.
- A 3-of-5 Safe `0x9196…002c` owns the ProxyAdmin, the DGF and the AccessManager, with no timelock.
  Through the upgrade-and-restore path (family README §3) it can make both tiers accept any root.
- Proposals fall back to permissionless after 14 days without one.
- PROPOSED also trusts the proposer outright.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/rise-live/capture.json`; Foundry `test/verifiers/evm/opstack/fixtures/rise-live.json` |
| Captured | 2026-10-01T05:40:45Z, Ethereum slot 15,334,068 (510/512) |
| Refresh | `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain rise --refresh` |
| Replay | `forge test --match-contract OpStackRiseLive`; `npm run test:e2e:opstack-live:sweep51` |
| Verified | FINALIZED ANCHOR mode (anchor game `0xb64d…881d`) and GAME mode (final game `0xCE2f…BA11`) to the RISE state root; the newest game `0x923b…3589` accepted by PROPOSED and rejected by FINALIZED; the resolved game inside the delay rejected by FINALIZED; other game args, game implementation, ASR implementation and fork version rejected |

## Hiero → RISE direction

Not started on this branch. RISE is EVM, so a Hiero verifier deployed on RISE is the expected path.
