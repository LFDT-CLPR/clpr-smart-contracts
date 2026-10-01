# Blast → Hiero · status: live-verified on mainnet data, PROPOSED full bundle (anvil, 2026-10-01)

Blast settles on Ethereum through an `L2OutputOracle` with a permissioned proposer and no fault proofs.
Its bundles are verified on Hiero by `OpOutputOracleVerifier` (FINALIZED) or
`OpOutputOracleProposedVerifier` (PROPOSED). Family README: [src/verifiers/evm/opstack/oracle/README.md](../../src/verifiers/evm/opstack/oracle/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:81457` |
| Chain type | L2, OP-derived (blast-geth), settles on Ethereum mainnet through `L2OutputOracle` 1.6.0 |
| Finality source | Ethereum sync committee over L1; output posted in `l2Outputs` and, for FINALIZED, older than 604,800 s (7 days) |
| Verifier | `OpOutputOracleVerifier` / `OpOutputOracleProposedVerifier` ([source](../../src/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol)), 15,947 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | FINALIZED: the proposer unless the challenger deletes within 7 days. PROPOSED: the proposer alone. |
| Typical bundle | PROPOSED 3,048,294 gas, 30,884 B calldata (510/512) |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure) |

## Deployment profile

`new OpOutputOracleVerifier(l1StateVerifier, 1606824023, 12, profile, accountFormat)`; values read from
Sourcify and live L1 storage on 2026-10-01.

| Value | Blast | Read from |
|---|---|---|
| `oracle` | `0x826D1B0D4111Ad9146Eb8941D7Ca2B6a44215c76` (`L2OutputOracle` 1.6.0) | Portal `0x0Ec6…6Cb` 1.10.0 `l2Oracle()` |
| `oracleImplCodeHash` | `0xf0b82e9f910d7f9ec66bc721e163d6cb875a539e6e2161a8bdd286a488c9dc9a` (implementation `0x1c90…16eb`) | EIP-1967 slot, implementation code |
| `outputsSlot` | 3 | Sourcify layout |
| `periodSource`, period | IMMUTABLE, 604,800 s | `FINALIZATION_PERIOD_SECONDS` immutable |
| Optimistic flag | none | — |
| `accountFormat` | `(7, 5, 6)`: `[nonce, flags, fixed, shares, remainder, storageRoot, codeHash]` | blast-geth `types.StateAccount` |
| Proposer, challenger | `0x082b…A821`, `0x4f72…8B05` | Oracle storage |

## Relayer requirements

- Ethereum beacon API and execution RPC (non-archive window): `finality_update` and committee data;
  `eth_getProof` of the oracle and its implementation; `eth_call` `nextOutputIndex`, `getL2Output`.
- Blast RPC: `eth_getBlockByNumber` and `eth_getProof` of the `ClprService` **and** of the
  `L2ToL1MessagePasser` `0x4200…0016` at the output's block, because Blast headers carry an empty
  `withdrawalsRoot` (pre-Isthmus).
- `rpc.blast.io` serves `eth_getProof` only 10,000 blocks (about 5.5 h) back, so FINALIZED (7 days)
  needs an archive node or a proof staged when the output is new.
- Outputs every 1,800 L2 blocks (about 1 h); one L1 rotation per period (about 27 h).

## Chain-specific trust and caveats

- No fault proofs: outputs are not proven. Security is the challenger's 7-day deletion window, the same
  model Blast's own withdrawals use.
- 7-field L2 account leaf (yield shares); a 4-field format is rejected (tested).
- Upgrade keys of the portal and oracle are trusted; an oracle upgrade fails closed (`OracleImplMismatch`).

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/opadapters-live/capture.json` (mainnet slot 15,333,427, 510/512, 2026-10-01); staged `pending/blast-22780.json` |
| Replay | `forge build && npm run test:e2e:opadapters-live`; Foundry `forge test --match-path 'test/verifiers/evm/opstack/oracle/*'` |
| Refresh | `npm run opadapters-live:refresh` |

Verified: PROPOSED full `verifyBundle` on output #22780 through the 7-field account leaf; FINALIZED
rejects the newest output with `OutputNotFinalized`; the FINALIZED L1 half on output #22612 (7 days old)
through `verifyOutput`. A full FINALIZED bundle runs automatically after a refresh 7 or more days after
the staged output. The storage step proves exclusion on the message passer (no ClprService on Blast). Not
yet run on Hedera.

## Hiero → Blast direction

Not built. Whether Blast's EVM provides the EIP-2537 precompiles the Hiero verifier needs was not checked.
