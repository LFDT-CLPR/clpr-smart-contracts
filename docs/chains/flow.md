# Flow → Hiero

Flow → Hiero · status: blocked (Flow EVM storage cannot be proven from public data)

Flow's consensus committee signs quorum certificates with BLS, so block finality is checkable in
principle. The ClprService would live in Flow EVM, and its storage cannot be proven: Flow EVM
blocks carry no state root, and no public API returns register proofs. No Flow code is on this
branch. See the [family README](../../src/verifiers/evm/blscommittees/README.md), "Limits and known gaps".

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Flow EVM 747 / `eip155:747` |
| Chain type | L1 (Flow), EVM environment inside Cadence/FVM |
| Finality source | HotStuff quorum certificates (BLS min-sig: signatures in G1, keys in G2) and execution seals |
| Contract | None |
| Trust tier | — |
| Typical bundle / rotation | — |

## Deployment profile

None.

## Relayer requirements

What was checked on 2026-10-01 against `https://mainnet.evm.nodes.onflow.org`:
- `eth_getBlockByNumber("latest")` → `stateRoot` = `0x0000…0000`.
- `eth_getProof` → "endpoint is not supported: eth_getProof".

## Chain-specific trust and caveats

What a Flow verifier would need:
- A source of storage proofs: Flow EVM state is stored as atree slabs in registers of the Flow
  execution state trie. Proving one EVM slot means a register proof against a sealed state
  commitment plus slab decoding. No public access-node API serves register proofs.
- Quorum certificates: votes sign `view (8 bytes, big-endian) ‖ blockID`
  (flow-go `consensus/hotstuff/verification/common.go:MakeVoteMessage`) and hash to G1 with a
  KMAC128-based `expand_message_xof` (onflow/crypto `bls.go:NewExpandMsgXOFKMAC128`), which would
  need a Keccak sponge in Solidity. Staking keys are G2 and would be passed uncompressed.

## Live verification

None.

## Hiero → Flow direction

Not started. Flow EVM is EVM-compatible, so the Hiero-side verifiers used on other EVM chains are
the starting point.
