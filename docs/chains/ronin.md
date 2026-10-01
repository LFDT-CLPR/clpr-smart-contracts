# Ronin → Hiero

Ronin → Hiero · status: live-verified on Ethereum mainnet to the Ronin state root (2026-10-01)

Ronin (chain 2020) is an OP Stack L2 that settles on Ethereum through permissioned dispute games.
`OpStackVerifier` / `OpStackProposedVerifier` prove, from a header the Ethereum sync committee
signs, that Ronin's AnchorStateRegistry accepts an output root, then walk the Ronin state to the
ClprService queue slots. Full design: [OP Stack verifiers README](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 2020 / `eip155:2020` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee → AnchorStateRegistry 3.9.0 → PermissionedDisputeGame 2.4.0 (game type 1) |
| Verifier contract | `OpStackVerifier` / `OpStackProposedVerifier` with [`RoninProfile`](../../src/verifiers/evm/opstack/profiles/RoninProfile.sol) · [family README](../../src/verifiers/evm/opstack/README.md) |
| Trust tier | Weaker: one permissioned proposer and one permissioned challenger; upgrade keys with no delay |
| Typical bundle | FINALIZED `verifyL2StateRoot`, GAME mode: 2,701,785 gas, 28,740 B (anvil `eth_estimateGas`, 501/512 signers). No full bundle: no public `eth_getProof` |
| Rotation | Adds the next sync committee: 66,902 B and about 4.84M gas (EthMainnetVerifier README, real Fulu rotation); not measured on this fixture |

## Deployment profile

Constructor: `new OpStackVerifier(l1StateVerifier, 1606824023, 12, RoninProfile.profile())`.

| Parameter | Value | Read from |
|---|---|---|
| `rootFormat` | `OUTPUT_ROOT` | builder cross-check against L2 headers |
| `l2ChainId` | 2020 | chain id; also in `gameArgs[1]` |
| `anchorStateRegistry` | `0x0B95fF1d1B113bac3E29Ac0BBF2089126C9aE81A` | OptimismPortal `0x652C…6D77` (5.6.1) `anchorStateRegistry()` |
| `anchorStateRegistryImplCodeHash` | code hash of implementation `0x8f40…b281` (3.9.0) | `eth_getProof` at the captured L1 block |
| `disputeGameFinalityDelaySeconds` | 302,400 (3.5 days) | ASR implementation immutable |
| `gameImplementation` | `0xe1dFFCBE4e22B813F26d2106D943C102e7cAb87e` (PermissionedDisputeGame 2.4.0) | DGF `0x45dA…843a` (1.6.1) `gameImpls(1)` |
| `gameArgsHash` | `0x935142cfa45769773f43a67571713dc18b13d04ab29892197b8225c879f17796` (164 B: prestate, VM, ASR, WETH, chain id, proposer, challenger) | `keccak256(DGF.gameArgs(1))` |
| `layout` | `PERMISSIONED_DISPUTE_GAME_V2_LAYOUT`: ASR slots 1, 2, 3, 5, 6; DGF games 103; game state slot 0, wasRespected slot 10 | Sourcify layouts, checked against live storage |

## Relayer requirements

- L1: as for every profile of the family (beacon API; `eth_getProof` at the signed block).
- L2: `api.roninchain.com` does not whitelist `eth_getProof` and `ronin.drpc.org` failed on
  2026-10-01. Full bundles need an own Ronin node (or archive RPC) that serves `eth_getProof` for
  blocks at least 3.5 days old.
- Rotations follow the Ethereum sync committee (about every 27 h).

## Chain-specific trust and caveats

- One proposer (EOA `0xd379…d620`) and one challenger (a 4-of-11 Safe `0x4a49…a746`), fixed by
  `gameArgs[1]`. A wrong root that the challenger does not dispute within the game clock is
  finalized: FINALIZED trusts that the proposer is honest or the challenger is honest and live.
- A 5-of-6 Safe `0xE9Ad…5607` owns the ProxyAdmin and the DGF and is the guardian, with no timelock.
- A new prestate, proposer or challenger changes `gameArgs[1]` and fails closed with `GameArgsMismatch`.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/ronin-live/capture.json`; Foundry `test/verifiers/evm/opstack/fixtures/ronin-live.json` |
| Captured | 2026-10-01T05:44:49Z, Ethereum slot 15,334,116 (501/512) |
| Refresh | `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain ronin --refresh` |
| Replay | `forge test --match-contract OpStackRoninLive`; `npm run test:e2e:opstack-live:sweep51` |
| Verified | FINALIZED ANCHOR and GAME mode on the anchor game `0x3aC5…1202` (the newest final game) to the Ronin state root; the newest game accepted by PROPOSED and rejected by FINALIZED; game-args, implementation, ASR-implementation and fork-version negatives |

## Hiero → Ronin direction

Not started on this branch. Ronin is EVM, so a Hiero verifier deployed on Ronin is the expected path.
