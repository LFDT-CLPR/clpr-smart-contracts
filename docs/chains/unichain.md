# Unichain → Hiero

Unichain → Hiero · status: live-verified on Ethereum mainnet to the Unichain state root (2026-10-01)

Unichain (chain 130) is an OP Stack L2 on the Superchain. It settles on Ethereum through
permissionless `SuperFaultDisputeGame`s whose root claims are interop super roots.
`OpStackVerifier` / `OpStackProposedVerifier` prove, from a header the Ethereum sync committee
signs, that Unichain's AnchorStateRegistry accepts a super root, that the super root's entry for
chain 130 is Unichain's output root, and then walk the Unichain state to the ClprService queue
slots. Full design: [OP Stack verifiers README](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 130 / `eip155:130` |
| Chain type | L2, OP Stack (Superchain), settles on Ethereum mainnet |
| Finality source | Ethereum sync committee → AnchorStateRegistry 3.9.0 → SuperFaultDisputeGame 0.8.0 (game type 9, super root v1) |
| Verifier contract | `OpStackVerifier` / `OpStackProposedVerifier` with [`UnichainProfile`](../../src/verifiers/evm/opstack/profiles/UnichainProfile.sol) · [family README](../../src/verifiers/evm/opstack/README.md) |
| Trust tier | Permissionless fault proofs (Cannon); Superchain guardian and upgrade Safe |
| Typical bundle | FINALIZED `verifyL2StateRoot`, ANCHOR mode: 1,754,014 gas, 21,700 B; PROPOSED newest game: 2,647,377 gas, 26,724 B (anvil `eth_estimateGas`, 507/512 signers). No full bundle captured |
| Rotation | Adds the next sync committee: 66,902 B and about 4.84M gas (EthMainnetVerifier README, real Fulu rotation); not measured on this fixture |

## Deployment profile

Constructor: `new OpStackVerifier(l1StateVerifier, 1606824023, 12, UnichainProfile.profile())`.

| Parameter | Value | Read from |
|---|---|---|
| `rootFormat` | `SUPER_ROOT_V1` | each game's `extraData` is the preimage `0x01 ‖ timestamp ‖ (130 ‖ outputRoot)`; its keccak256 is the `rootClaim` |
| `l2ChainId` | 130 | the super root's entry |
| `anchorStateRegistry` | `0x27Cf508E4E3Aa8d30b3226aC3b5Ea0e8bcaCAFF9` | OptimismPortal `0x0bd4…A7a2` (5.8.0) `anchorStateRegistry()` |
| `anchorStateRegistryImplCodeHash` | `0x3f54fcc2d17726f6c927da08dec4dbfbecc43a013fd309344ecd2cace85ae36d` (implementation `0x8f40…b281`, 3.9.0) | `eth_getProof` at the captured L1 block |
| `disputeGameFinalityDelaySeconds` | 302,400 (3.5 days) | ASR implementation immutable |
| `gameImplementation` | `0x19AF533Cc2A2A55786DCB8672aA5717e64213208` (SuperFaultDisputeGame 0.8.0) | DGF `0x2F12…dFe4` (1.6.1) `gameImpls(9)` |
| `gameArgsHash` | `0xa8b484d71cba05e23a78f585f0b52d044f4d77d9011e16a8fd69cec591b67e32` (124 B: prestate, VM, ASR, WETH, chain id 0) | `keccak256(DGF.gameArgs(9))` |
| `layout` | `UnichainProfile.layout()`: ASR slots 1, 2, 3, 5, 6; DGF games 103; game state slot 0, wasRespected slot 9 | Sourcify layouts, checked against live storage |

## Relayer requirements

- L1: as for every profile of the family.
- L2: games claim an L2 **timestamp**; blocks are 1 s apart, so the relayer maps the timestamp to
  a block number and checks the header's timestamp.
- `mainnet.unichain.org` refuses `eth_getProof` ("distance to target block exceeds maximum proof
  window") and `unichain-rpc.publicnode.com` serves it at the head only. A full bundle needs an own
  node, or staging the proof of the block a future game will claim. `--stage-next` does not yet map
  super-root timestamps to blocks.
- Rotations follow the Ethereum sync committee (about every 27 h).

## Chain-specific trust and caveats

- Fault proofs are permissionless (Cannon), with 3.5-day clocks and a 3.5-day finality delay.
- The Superchain guardian `0x09f7…dAf2` can pause, blacklist and retire games and change the
  respected type. Pause is not proven (family README §2); the others make verification fail closed.
- A 2-of-2 Safe `0x5a0A…3d2A` (Optimism Foundation and Security Council) owns the ProxyAdmin and the DGF.
- The ASR has no anchor game since its re-initialisation; ANCHOR mode proves the starting anchor
  root, a super root at L2 timestamp 1,788,848,651 (2026-09-08).
- The factory holds type-9 games only since 2026-09-24. At the capture no type-9 game was final
  yet (the first finalize 3.5 days after their resolution, from 2026-10-02), so FINALIZED GAME mode
  is not exercised; a refresh after that date covers it.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/unichain-live/capture.json`; Foundry `test/verifiers/evm/opstack/fixtures/unichain-live.json` |
| Captured | 2026-10-01T07:37:22Z, Ethereum slot 15,334,666 (507/512) |
| Refresh | `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain unichain --refresh` |
| Replay | `forge test --match-contract OpStackUnichainLive`; `npm run test:e2e:opstack-live:sweep51` |
| Verified | FINALIZED ANCHOR mode (starting anchor super root) to the Unichain state root; the newest game `0x3BBB…EB67` accepted by PROPOSED and rejected by FINALIZED; the resolved game `0x49B6…9106` rejected by FINALIZED inside the delay and accepted by PROPOSED; negatives as for the family |

## Hiero → Unichain direction

Not started on this branch. Unichain is EVM, so a Hiero verifier deployed on Unichain is the expected path.
