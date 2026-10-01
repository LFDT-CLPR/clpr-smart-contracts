# Katana → Hiero · status: live-verified on mainnet data, FINALIZED full bundle (anvil, 2026-10-01)

Katana settles through the Polygon AggLayer: its `AggchainFEP` contract on Ethereum keeps an output array
that the AgglayerManager appends to after verifying the pessimistic proof. Its bundles are verified on Hiero
by `OpOutputOracleVerifier` (FINALIZED and PROPOSED behave the same). Family README: [src/verifiers/evm/opstack/oracle/README.md](../../src/verifiers/evm/opstack/oracle/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:747474` |
| Chain type | L2, OP Stack, settles on Ethereum mainnet through Polygon AggLayer `AggchainFEP` 3.0.0 (rollup 20) |
| Finality source | Ethereum sync committee over L1; output appended to `l2Outputs` (period 0, final when appended) |
| Verifier | `OpOutputOracleVerifier` ([source](../../src/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol)), 15,947 B runtime; `EthL1StateVerifier` 11,593 B |
| Trust tier | AggLayer pessimistic proof wrapping the OP Succinct FEP proof, the 1-of-1 aggchain signer, AggLayer governance |
| Typical bundle | FINALIZED 2,634,859 gas, 22,756 B calldata (510/512) |
| Rotation | L1 sync-committee rotation: 66,902 B, about 4.84M gas (Ethereum figure) |

## Deployment profile

| Value | Katana | Read from |
|---|---|---|
| `oracle` | `0x100d3ca4f97776A40A7D93dB4AbF0FEA34230666` (`AggchainFEP` 3.0.0) | AgglayerManager `0x5132…7aB2` `rollupIDToRollupDataV2(20).rollupContract` |
| `oracleImplCodeHash` | `0x1bf6addd3946244bb16ed6f289e604c8ec8bcdc7617a3aee929c6134d300b342` (implementation `0x9532…c660`) | EIP-1967 slot, implementation code |
| `outputsSlot` | 116 | Sourcify layout |
| `periodSource`, period | IMMUTABLE, 0 | No delete function |
| Optimistic flag | slot 124, offset 0 (`false` at capture; `optimisticModeManager` packed at offset 1) | `optimisticMode()` |
| `accountFormat` | `(4, 2, 3)` | Ethereum account leaf |

## Relayer requirements

- Ethereum beacon API and execution RPC (non-archive window): committee data, `eth_getProof` of the
  `AggchainFEP` and its implementation, `eth_call` getters for the outputs and the optimistic flag.
- Katana RPC: `eth_getBlockByNumber` and `eth_getProof` at the output's block. `katana.drpc.org` was used;
  `rpc.katana.network` serves recent blocks only. The message-passer root is the header's
  `withdrawalsRoot` (Isthmus).
- One output per AggLayer certificate, about 1 h (outputs #10338 → #10438 took 102.5 h); one L1 rotation
  per period (about 27 h).

## Chain-specific trust and caveats

- No deletion and period 0: PROPOSED and FINALIZED accept the same outputs.
- The pessimistic proof wraps the FEP (OP Succinct) proof under the AggLayerGateway default vkeys
  (`useDefaultVkeys = true`). The 1-of-1 aggchain signer (the trusted sequencer) must also sign.
- In optimistic mode Katana accepts sequencer-signed outputs with no state-transition proof; both tiers
  stall while the flag is set, but earlier optimistic outputs stay in the array.
- An upgraded AgglayerManager could append any output; AggLayer governance is trusted.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/opadapters-live/capture.json` (mainnet slot 15,333,427, 510/512, 2026-10-01) |
| Replay | `forge build && npm run test:e2e:opadapters-live`; Foundry `forge test --match-path 'test/verifiers/evm/opstack/oracle/*'` |
| Refresh | `npm run opadapters-live:refresh` |

Verified: FINALIZED full `verifyBundle` on the newest output #10438. The storage step proves exclusion on
the message passer (no ClprService on Katana). Not yet run on Hedera.

## Hiero → Katana direction

Not built. Whether Katana's EVM provides the EIP-2537 precompiles the Hiero verifier needs was not checked.
