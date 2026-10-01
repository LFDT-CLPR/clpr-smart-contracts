# Sei → Hiero

Status: family-covered. Sei's production verifier today is `SeiCometBftVerifier`; `CometBftVerifier`
serves Sei by profile but has no live Sei fixture.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | not recorded in this branch's fixtures |
| Chain type | L1, Cosmos SDK + sei-tendermint (CometBFT fork), EVM in IAVL store `evm` |
| Finality source | CometBFT commit: > 2/3 of voting power, Ed25519 |
| Verifier | `SeiCometBftVerifier` ([Sei README](../../src/verifiers/evm/sei/README.md)); by profile also `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | not measured on live Sei data |
| Rotation | not measured on live Sei data |

## Deployment profile

For `CometBftVerifier`:

| Parameter | Value | Source |
|---|---|---|
| `chainId` | the Sei chain id, read from `/status` at deployment | — |
| `storeKey` | `evm` | sei-chain `x/evm/types/keys.go` |
| `evmStateKeyPrefix` | `0x03` | sei-chain `x/evm/types/keys.go` `StateKeyPrefix` |
| `keyScheme` | `ED25519` | sei-tendermint |
| `ed25519Verifier` | the deployed `Ed25519Verifier` | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | a recent header's set hash and height | `/commit?height=…` |

`SeiCometBftVerifier` keeps its own anchor format, `abi.encode(chainId, validators[])` (the full
validator list), so the existing Sei relay stays compatible. Both contracts share the protobuf
decoders in `CometBftProofCodec`.

## Relayer requirements

- RPC methods: `/commit`, `/validators`, `abci_query /store/evm/key?prove=true` at `H-1`.
- To move to `CometBftVerifier`, the relay must emit the compact 40-byte anchor
  (`validatorSetHash ‖ height`) and send raw `SimpleValidator` leaves in calldata.

## Chain-specific trust and caveats

- The full-list anchor of `SeiCometBftVerifier` costs one cold SLOAD per 32 B on every bundle and one
  SSTORE per 32 B on every rotation (family README §5). `CometBftVerifier`'s anchor is two slots.
- Storage key prefix is `0x03`, not Ethermint's `0x02`.

## Live verification

- No live Sei fixture on this branch. `SeiCometBftVerifier` is covered by its own tests
  (`test/e2e/tests/sei-verifier.spec.ts`, `test/verifiers/compliance/SeiComplianceTest.t.sol`, 28
  tests). No test runs `CometBftVerifier` with a `0x03` profile; the synthetic suite
  (`test/verifiers/evm/cometbft/CometBftVerifier.t.sol`) uses `0x02` and checks that Sei's `0x03`
  keys are rejected by it.
- Next step: record a Sei mainnet bundle with `buildCometBftLiveFixture.ts` and a `0x03` profile.

## Hiero → Sei

Not built. Sei runs an EVM, so the direction would deploy a Hiero verifier contract on Sei. It
waits on the Hiero proof source, like every Hiero → chain direction.
