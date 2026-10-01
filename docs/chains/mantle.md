# Mantle → Hiero · status: live-verified on mainnet data, FINALIZED and PROPOSED full bundles (anvil, 2026-10-01)

Mantle settles on Ethereum through `OPSuccinctL2OutputOracle`: each output carries an SP1 validity proof.
Its bundles are verified on Hiero by `OpOutputOracleVerifier` (FINALIZED) or
`OpOutputOracleProposedVerifier` (PROPOSED). Family README: [src/verifiers/evm/opstack/oracle/README.md](../../src/verifiers/evm/opstack/oracle/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:5000` |
| Chain type | L2, OP-derived, settles on Ethereum mainnet through `OPSuccinctL2OutputOracle` 2.0.1 |
| Finality source | Ethereum sync committee over L1; output posted with an SP1 proof and, for FINALIZED, older than `finalizationPeriodSeconds` (43,200 s at capture) |
| Verifier | `OpOutputOracleVerifier` / `OpOutputOracleProposedVerifier` ([source](../../src/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol)), 15,947 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | FINALIZED: SP1 (OP Succinct), its vkeys and owner, and the challenger's veto window. PROPOSED: the same proof inside the 12 h window. |
| Typical bundle | FINALIZED 3,640,599 gas, 37,732 B; PROPOSED 3,672,351 gas, 38,020 B (510/512) |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure); Mantle + rotation about 8.5M gas and 105 KB (estimate) |

## Deployment profile

| Value | Mantle | Read from |
|---|---|---|
| `oracle` | `0x31d543e7BE1dA6eFDc2206Ef7822879045B9f481` (`OPSuccinctL2OutputOracle` 2.0.1) | Portal `0xc54c…A8Fb` 1.7.0 `L2_ORACLE()` (immutable) |
| `oracleImplCodeHash` | `0xefcc10a3c3e18892f239c9e297e3db584a584d7da894f4c230b489378c57570f` (implementation `0x4059…6f50`) | EIP-1967 slot, implementation code |
| `outputsSlot` | 3 | Sourcify layout |
| `periodSource`, period | STORAGE, slot 8 (43,200 s at capture; the challenger can set ≥ 1 h, or ≥ 7 d in optimistic mode) | `finalizationPeriodSeconds()` |
| Optimistic flag | slot 16, offset 0 (`false` at capture) | `optimisticMode()` |
| `accountFormat` | `(4, 2, 3)` | Ethereum account leaf |
| Challenger, SP1 verifier | `0x2F44…daC9`, `0x3B60…185e` | Oracle storage |

## Relayer requirements

- Ethereum beacon API and execution RPC (non-archive window): committee data, `eth_getProof` of the
  oracle and implementation, `eth_call` `nextOutputIndex`, `getL2Output`, `finalizationPeriodSeconds`,
  `optimisticMode`.
- Mantle RPC: `eth_getBlockByNumber` and `eth_getProof` at the output's block. `rpc.mantle.xyz` serves
  archive proofs, so a full FINALIZED bundle works from public data. The message-passer root is the
  header's `withdrawalsRoot` (Isthmus).
- Outputs every ≥ 1,800 L2 blocks (about 1 h); one L1 rotation per period (about 27 h).

## Chain-specific trust and caveats

- The finalization period is read from storage at the proven state; if the challenger shortens it,
  FINALIZED follows, as Mantle's portal does.
- Optimistic mode stalls both tiers while set, but outputs posted during an earlier optimistic window stay
  in the array; monitor `OptimisticModeToggled` if that matters to the Channel.
- Upgrade keys of the portal and oracle, and the SP1 vkey owner, are trusted.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/opadapters-live/capture.json` (mainnet slot 15,333,427, 510/512, 2026-10-01) |
| Replay | `forge build && npm run test:e2e:opadapters-live`; Foundry `forge test --match-path 'test/verifiers/evm/opstack/oracle/*'` |
| Refresh | `npm run opadapters-live:refresh` |

Verified: FINALIZED full `verifyBundle` on output #22306 (past 12 h); PROPOSED full `verifyBundle` on
the newest output #22318, which FINALIZED rejects with `OutputNotFinalized`. The storage step proves
exclusion on the message passer (no ClprService on Mantle). Not yet run on Hedera.

## Hiero → Mantle direction

Not built. Whether Mantle's EVM provides the EIP-2537 precompiles the Hiero verifier needs was not checked.
