# BOB → Hiero

BOB → Hiero · status: live-verified on Ethereum mainnet, full FINALIZED bundle (2026-10-01)

BOB (chain 60808) is an OP Stack L2 that settles on Ethereum through permissioned dispute games
with a 12-hour clock. `OpStackVerifier` / `OpStackProposedVerifier` prove, from a header the
Ethereum sync committee signs, that BOB's AnchorStateRegistry accepts an output root, then walk
the BOB state to the ClprService queue slots. Full design:
[OP Stack verifiers README](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 60808 / `eip155:60808` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet |
| Finality source | Ethereum sync committee → AnchorStateRegistry 3.9.0 (12 h delay) → PermissionedDisputeGame 2.4.0 (game type 1) |
| Verifier contract | `OpStackVerifier` / `OpStackProposedVerifier` with [`BobProfile`](../../src/verifiers/evm/opstack/profiles/BobProfile.sol) · [family README](../../src/verifiers/evm/opstack/README.md) |
| Trust tier | Weaker: one permissioned proposer; a 4-of-6 Safe is challenger, upgrader and guardian, no timelock |
| Typical bundle | FINALIZED `verifyBundle`: 3,647,899 gas, 38,180 B (anvil `eth_estimateGas`, 508/512 signers) |
| Rotation | Adds the next sync committee: 66,902 B and about 4.84M gas (EthMainnetVerifier README, real Fulu rotation), about 8.5M gas and 105 KB in total; not measured on this fixture |

## Deployment profile

Constructor: `new OpStackVerifier(l1StateVerifier, 1606824023, 12, BobProfile.profile())`.

| Parameter | Value | Read from |
|---|---|---|
| `rootFormat` | `OUTPUT_ROOT` | builder cross-check against L2 headers |
| `l2ChainId` | 60808 | chain id; also in `gameArgs[1]` |
| `anchorStateRegistry` | `0xC9AC21AcD8696B64270716528bF83630Ea7a293c` | OptimismPortal `0x8AdE…5a3E` (5.6.1) `anchorStateRegistry()` |
| `anchorStateRegistryImplCodeHash` | `0x95cd0287fff0b9dbac513c35e8d5a5b6f3f17ff95f54dc9a0f2666855b981c18` (implementation `0x5020…5c09`, 3.9.0) | `eth_getProof` at the captured L1 block |
| `disputeGameFinalityDelaySeconds` | 43,200 (12 h) | ASR implementation immutable |
| `gameImplementation` | `0x642d1cc835a81c738313EBe85ED61979a44897bF` (PermissionedDisputeGame 2.4.0; not on Sourcify, slots checked against a live game's getters) | DGF `0x9612…1079` (1.6.1) `gameImpls(1)` |
| `gameArgsHash` | `0x6168acf76bd054257f945dbc8f45fbedd29be6ac0f023379377445378ba17da9` (164 B) | `keccak256(DGF.gameArgs(1))` |
| `layout` | `RoninProfile.layout()` (`PERMISSIONED_DISPUTE_GAME_V2_LAYOUT`) | as for Ronin |

## Relayer requirements

- L1: as for every profile of the family.
- L2: `rpc.gobob.xyz` serves `eth_getProof` days back, so a relayer can build full FINALIZED
  bundles from public data (the delay is 12 h plus the 12 h clock).
- Rotations follow the Ethereum sync committee (about every 27 h).

## Chain-specific trust and caveats

- One proposer, EOA `0x7cB1…8C69`, fixed by `gameArgs[1]`.
- A 4-of-6 Safe `0xC914…764E` is the challenger, owns the ProxyAdmin and the DGF, and is the
  guardian, with no timelock. FINALIZED trusts that the proposer is honest or that this Safe
  challenges within 12 h; the Safe can also make both tiers accept any root through the
  upgrade-and-restore path (family README §3).
- The factory also registers a Kailua game (type 1337, `0xD37b…742b`). Only type 1 is respected,
  so those games are rejected (`GameTypeNotRespected`).
- Latency: about a day from an L2 block to FINALIZED delivery (12 h clock, 12 h delay).

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/bob-live/capture.json` (+ `pending/`); Foundry `test/verifiers/evm/opstack/fixtures/bob-live.json` |
| Captured | 2026-10-01T05:47:10Z, Ethereum slot 15,334,129 (508/512) |
| Refresh | `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain bob --refresh` |
| Replay | `forge test --match-contract OpStackBobLive`; `npm run test:e2e:opstack-live:sweep51` |
| Verified | Full FINALIZED `verifyBundle` on the anchor game `0x5459…7744` down to BOB storage (L2ToL1MessagePasser as ClprService stand-in, channel slots absent); full PROPOSED `verifyBundle` on the newest game `0x0D0B…e6bF`; ANCHOR and GAME mode to the state root; negatives as for the family |

## Hiero → BOB direction

Not started on this branch. BOB is EVM, so a Hiero verifier deployed on BOB is the expected path.
