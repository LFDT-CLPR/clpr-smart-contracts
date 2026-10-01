# Etherlink → Hiero

Etherlink → Hiero · status: in progress — the Tezos L1 half (cemented PVM state hash) is live-verified on mainnet (2026-10-01); EVM storage proofs under it are blocked (no public proof source)

Etherlink is an EVM chain run as a Tezos smart rollup (WASM PVM). Its state is committed on Tezos
L1 by smart-rollup commitments; a commitment becomes final ("cemented") when the refutation window
passes without a successful challenge. `EtherlinkCementedState` uses the Tezos light client of the
[family](../../src/verifiers/evm/tezos/README.md) to prove the rollup's last cemented commitment and
return its PVM state hash. The second half — an EVM storage slot under that hash — is not built.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `eip155:42793` (Etherlink mainnet); rollup `sr1Ghq66tYK9y3r8CC1Tf8i8m5nxh8nTvZEf` (`0x74f8952e7a287d78e8dceec67547bd00a278abbf`) on `tezos:NetXdQprcVkpaWU` |
| Chain type | L2, Tezos smart rollup (WASM PVM, Etherlink kernel), optimistic with a refutation game |
| Finality source | Tezos L1 finality (Tenderbake) + cementation: 201,600 L1 blocks (`smart_rollup_challenge_window_in_blocks`, 14 days at 6 s) after a commitment is published |
| Verifier contract | `src/verifiers/evm/tezos/EtherlinkCementedState.sol` (L1 half) · [family README](../../src/verifiers/evm/tezos/README.md) |
| Trust tier | Tezos L1 quorum (as for Tezos) + at least one honest, active refuter during the 14-day window. Staking is permissionless (no whitelist under the rollup at capture) |
| Typical proof (L1 half) | 11,536,116 gas, 78,276 B calldata (inline signatures), live mainnet |
| Rotation | As for Tezos (the Tezos anchor) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| Tezos light-client profile | as on the [Tezos page](./tezos.md) | |
| `rollup` | `0x74f8952e7a287d78e8dceec67547bd00a278abbf` | `sr1Ghq66tYK9y3r8CC1Tf8i8m5nxh8nTvZEf` (base58check payload) |
| LCC path | `smart_rollup/index/<rollup hex>/data/last_cemented_commitment` | octez `storage.ml` (carbonated map under `data/`) |
| Commitment path | `smart_rollup/index/<rollup hex>/commitments/<hash hex>/data` = `0x00 ‖ compressed_state ‖ inbox_level ‖ predecessor ‖ ticks` | `sc_rollup_commitment_repr.ml` |
| Commitment hash | BLAKE2b-256 of the 76 bytes after the version byte | checked on chain |

## Relayer requirements

- The Tezos relayer data (see the [Tezos page](./tezos.md)) plus two `merkle_tree_v2` proofs at block
  L−2: the LCC and its commitment.
- For the missing half: an Etherlink smart-rollup node (bootstrapped from a public snapshot) kept at
  the LCC's state, and a tool that produces a binary-Irmin proof of
  `durable/evm/eth_accounts/<addr>/storage/<slot>` under the PVM state. The rollup node uses such
  proofs for refutation and outbox messages but exposes no RPC for arbitrary keys.

## Chain-specific trust and caveats

- **Blocked: EVM storage proofs.** No public endpoint returns a durable-storage proof against the PVM
  state hash, and `eth_getProof` is not supported by the Etherlink EVM node
  (`node.mainnet.etherlink.com`: "Method not supported"). The Etherlink block `stateRoot` is not a
  Merkle-Patricia root, so the EVM-family verifiers do not apply.
- **14-day delay.** Only cemented state is final from L1; a bundle reflects Etherlink state about two
  weeks old. Faster paths would trust the Etherlink sequencer.
- **Outbox alternative.** Outbox messages have a proof RPC on the rollup node and are verifiable against a
  cemented commitment, but only the bridge system contracts emit them (fast withdrawals can carry a
  payload to a Tezos contract, behind a kernel feature flag). Not used here.

## Live verification

- Fixture: `test/e2e/fixtures/tezos-live/mainnet.json` (`derived.etherlink`).
- Replay: `forge test --match-contract TezosLiveTest --match-test etherlink` and
  `npm run test:e2e:tezos-live`.
- Verified on 2026-10-01: from the Tezos quorum of level 15,181,989, the last cemented commitment
  `0x2b701220…5997` (inbox level 14,980,267) and its PVM state hash `0x4ad74460…5ddd`, with the
  commitment hash recomputed on chain.

## Hiero → Etherlink direction

Etherlink's EVM has the BN254 precompiles (`ecAdd` at `0x06` and the pairing at `0x08` answer on
`node.mainnet.etherlink.com`), so the existing Solidity Hiero verifiers and ClprService can be
deployed there; not done in this branch.
