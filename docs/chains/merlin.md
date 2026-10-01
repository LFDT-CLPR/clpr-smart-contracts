# Merlin Chain

Merlin Chain → Hiero · status: blocked for trustless verification (weak tier only; not built)

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:4200` (`eth_chainId` on `rpc.merlinchain.io`, 2026-10-01) |
| Chain type | Bitcoin-branded L2 built on Polygon CDK (zkEVM node) |
| Finality source | No public settlement chain was found (see below) |
| Verifier | none. Family README: [L1-settled rollup verifiers](../../src/verifiers/evm/zkrollup/README.md) ("Limits and known gaps") |
| Trust tier | only possible tier: trust Merlin's sequencer, or t-of-n attestors that sign Merlin state roots |
| Typical bundle / rotation | not applicable |

## Deployment profile

None.

## Relayer requirements

Not applicable until a verifier exists.

## Chain-specific trust and caveats

Checked on 2026-10-01:

- `rpc.merlinchain.io` answers the Polygon CDK methods `zkevm_batchNumber`, `zkevm_virtualBatchNumber` and
  `zkevm_verifiedBatchNumber` (verified batch `0x4907e9` at the time), and `zkevm_getBatchByNumber` returns each batch's
  `stateRoot` with the `sendSequencesTxHash` and `verifyBatchTxHash` of its settlement transactions.
- Those settlement transactions (for example `0x7c61…4ada` and `0xd3ee…fab9`) are not on Ethereum mainnet
  (`eth_getTransactionByHash` returns null on a public mainnet RPC) and not on Bitcoin (mempool.space finds neither the
  hash nor its byte-reversed form). The chain the CDK node settles to is not a public chain this verifier could read.

So there is no contract or chain that holds Merlin's verified state roots under a consensus we can check. A Merlin
channel can only trust Merlin itself: a verifier that accepts state roots signed by Merlin's sequencer key, or by a
t-of-n set of independent attestors that each run a Merlin node (as in the Canton verifier). That tier is
weaker than every other chain in this family and was not built.

## Live verification

None.

## Hiero → Merlin direction

Not covered. Merlin runs the EVM, so a Hiero verifier deployed on Merlin would work like on other EVM chains.
