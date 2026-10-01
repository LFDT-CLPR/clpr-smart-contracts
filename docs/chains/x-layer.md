# X Layer → Hiero · status: live-verified on mainnet data to the L2 state root (anvil, 2026-10-01)

X Layer is an OP Stack L2 that settles on Ethereum through OP Succinct Lite dispute games. Its bundles are
verified on Hiero by `OpStackVerifier` (FINALIZED) or `OpStackProposedVerifier` (PROPOSED) with the pinned
`XLayerProfile`. Family README: [src/verifiers/evm/opstack/README.md](../../src/verifiers/evm/opstack/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:196` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet (OP Stack fault proofs) and Polygon AggLayer (bridge only) |
| Finality source | Ethereum sync committee over L1, then `OPSuccinctFaultDisputeGame` 2.0.0 (type 42) through ASR 3.5.0 and DGF 1.3.0 |
| Verifier | `OpStackVerifier` / `OpStackProposedVerifier` ([source](../../src/verifiers/evm/opstack/OpStackVerifierBase.sol)) with [`XLayerProfile`](../../src/verifiers/evm/opstack/profiles/XLayerProfile.sol), 17,884 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | Weaker: sync committee + one permissioned proposer + one permissioned challenger + SP1 + upgrade keys with no or a 1-hour delay |
| L1 half (`verifyL2StateRoot`) | FINALIZED GAME 2,577,100 gas, 26,948 B; ANCHOR 2,177,016 gas, 22,148 B; PROPOSED newest game 2,532,538 gas, 26,756 B (510/512) |
| Typical full bundle | Not yet measured: needs a staged L2 proof (see below) |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure) |

## Deployment profile

`new OpStackVerifier(l1StateVerifier, 1606824023, 12, XLayerProfile.profile())`. Values read from Sourcify
storage layouts and live mainnet storage on 2026-10-01; the live builder re-checks them.

| Value | X Layer | Read from |
|---|---|---|
| `rootFormat` | `OUTPUT_ROOT` | Game root claim is the v0 output root |
| `l2ChainId` | 196 | `XLayerProfile.L2_CHAIN_ID` |
| OptimismPortal | `0x64057ad1DdAc804d0D26A7275b193D9DACa19993` (5.2.0) | L1 |
| `anchorStateRegistry` | `0x000590BB65ab1864a7AD46d6B957cC9a4F2C149d` (implementation `0xeb69cc681e8d4a557b30dffbad85affd47a2cf2e`, 3.5.0) | Portal → ASR |
| `anchorStateRegistryImplCodeHash` | `0x1194081c631cd5141ef68135c5aaaa59b92a7c2df303a713c3cf81c6bab69348` | `keccak256` of the implementation's runtime code |
| `disputeGameFinalityDelaySeconds` | 302,400 (3.5 days) | ASR implementation immutable |
| DisputeGameFactory | `0x9D4c8FAEadDdDeeE1Ed0c92dAbAD815c2484f675` (1.3.0) | ASR slot 1 |
| `gameImplementation` | `0x8841FA06099FEdfE7DB6962926C6A281e9E1e607` (`OPSuccinctFaultDisputeGame` 2.0.0), game type 42 | DGF `gameImpls[42]` |
| `layout` | 1, 2, 3, 5, 6, 0, 4, 103, 0, 0, 8, 16; `gameWasRespected` 9, 0 | Sourcify layouts of ASR 3.5.0, DGF 1.3.0, the game |

The same values are in `XLAYER_MAINNET_PROFILE` (`test/e2e/relay/opstack.ts`). Both the Foundry and the
vitest tests deploy from the pinned profile, not from captured values.

## Relayer requirements

- **Ethereum beacon API** and **execution RPC** as for every OP Stack chain (family README, section 3);
  the capture used `ethereum-beacon-api.publicnode.com`, `lodestar-mainnet.chainsafe.io` and
  `ethereum-rpc.publicnode.com`.
- **X Layer RPC with `eth_getProof`.** `rpc.xlayer.tech`, `xlayerrpc.okx.com` and thirdweb answer "rpc
  method is not whitelisted"; Ankr and BlockPI need keys; `xlayer.drpc.org` (reth) serves `eth_getProof` at
  `"latest"` only ("distance to target block exceeds maximum proof window" for any older block).
- **Staging.** `npm run opstack-live:stage:xlayer` reads the proposer's cadence from L1 (one game per 3,600
  L2 blocks), waits for the block the next game will claim, and keeps the `"latest"` proof whose root is
  that block's `stateRoot`. Without an archive node or a staged proof, a full FINALIZED bundle cannot be
  built from public data.
- **Cadence.** Games about every hour; one L1 sync-committee rotation per period (about 27 h).

## Chain-specific trust and caveats

- **Two links to Ethereum.** Only the OP Stack fault-proof path holds provable state. The AggLayer side
  (RollupManager `0x5132…7aB2` rollup 3, `AggchainECDSAMultisig` `0x2B0e…0507`, 1-of-1 signer) stores exit
  and pessimistic roots only. Assets move through the AggLayer bridge, so the OP Stack games secure no L1
  funds and their bonds are nominal (1e10 wei).
- **One proposer, one challenger.** AccessManager `0x98BA…c17B` allows proposer `0xE439…394F` and
  challenger `0x736E…2FF6`; the permissionless fallback timeout is about 1,000 years. An unchallenged game
  resolves `DEFENDER_WINS` after 3,600 s without a proof.
- **SP1.** A challenged game needs an SP1 proof through SP1VerifierGateway `0x397A…a9B`, whose owner can add
  routes.
- **Upgrade keys.** ASR, SystemConfig and portal proxies: ProxyAdmin `0x313c…fee6`, owned by a 2-of-3 Safe
  `0xC290…D45A` with no timelock. DGF: TimelockController `0xFa3A…52d6`, 1-hour minimum delay. EOA
  `0x6eE7…C6aA` is guardian, SystemConfig owner, AccessManager owner and a Safe signer.
- **Shared factory.** The DGF also hosts game type 1961 for another L2; those games are rejected
  (`GameTypeNotRespected`, tested live).
- **Latency.** About 3.6 days from L2 block to FINALIZED delivery; about 30 min for PROPOSED.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/xlayer-live/capture.json` (Ethereum mainnet, captured 2026-10-01, attested slot 15333656, 510/512); Foundry export `test/verifiers/evm/opstack/fixtures/xlayer-live.json` |
| Replay | `forge build && npm run test:e2e:opstack-live:xlayer` (13 passed, 2 skipped); `forge test --match-contract OpStackXLayerLive` (6 passed, 2 skipped) |
| Refresh | `npm run opstack-live:stage:xlayer`, then `npm run opstack-live:refresh:xlayer` |

Verified on real mainnet data: FINALIZED in ANCHOR and GAME mode up to the X Layer state root (L1 state,
ASR, DGF, game, output root, L2 `state_root`); FINALIZED rejects a resolved game still inside the delay
(`GameNotFinalized`) and the newest game (`GameNotResolved`), PROPOSED accepts both; rejection of the other
game type (1961), wrong preimages, forged game code, an unpinned ASR or game implementation, and the
Electra fork version. The skipped cases are the full bundles, which need a staged L2 proof (none staged
yet). Not yet run on Hedera.

## Hiero → X Layer direction

Not built. It would deploy the Hiero verifier contracts on X Layer; whether X Layer's EVM provides the
EIP-2537 precompiles was not checked in this work.
