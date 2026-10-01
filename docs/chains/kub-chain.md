# KUB Chain → Hiero

KUB Chain → Hiero · status: live-verified on KUB mainnet and testnet (2026-10-01)

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `96` / `eip155:96`; testnet `25925` / `eip155:25925` |
| Chain type | L1, Bitkub's go-ethereum fork (kub-chain/bkc v2.4.0); Clique engine in PoS mode since the Chaophraya fork |
| Finality source | None; seal by a span-scheduled validator or the Bitkub super node |
| Verifier | `SignerReplayVerifier` with `SignerReplayProfiles.kub` ([family README](../../src/verifiers/evm/signer/README.md)) |
| Trust tier | Majority of a small signer set: mainnet 6-7 signers (4 needed), testnet 5 (3 needed), each including the super node |
| Typical bundle | Mainnet: 942,986 gas, 10,628 B calldata (6-header run) |
| Rotation | Mainnet, span block 35,734,599 → 35,734,649 (set 6 → 7 signers): 1,041,365 gas, 10,628 B calldata |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 96 (mainnet), 25925 (testnet) | `eth_chainId`; `bkc-node/{mainnet,testnet}/genesis.json` |
| `epochLength` / `boundaryOffset` | 50 / 1 (span-commit block n has (n + 1) % 50 == 0) | genesis `clique.span: 50`; `clique.go` `needToUpdateValidatorList` |
| `sealFields` | 0 (all fields) | `clique.go` `encodeSigHeader` |
| `entrySize` | 40 (address20 ‖ power20) | `utils/utils.go` `ParseValidatorsAndPower` |
| `trailerSize` / `trailerSignerOffset` | 60 / 40 (third system address = super node) | `snapshot.go` (`contractBytesLength`, Basel `SuperNode = contracts[2]`) |
| Super node | Mainnet `0xcf723fe5a8118efe70d3fadd56c5e6d01adec7a3` | genesis `baselBlock.superNode`; live span blocks |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `eth_getBlockByNumber`, `eth_getProof`, `eth_chainId`. Public RPCs served `eth_getProof` 100 blocks
  back but not 1,000 (2026-10-01): fetch the proof while the state block is recent, or run a node.
- Runs of a few headers to a few dozen: the capture needed 6 (mainnet) and 3 (testnet) headers after the span block,
  29 in an earlier mainnet capture the same day.
- A span block every 50 blocks (150 s at 3 s blocks); including one in a bundle keeps the anchor current.

## Chain-specific trust and caveats

- Since Basel, the super node (a Bitkub-controlled key) may seal any block; it is one member of the set.
- `verifySealPoS` has no "recently signed" limit, so one key can seal many consecutive blocks. The verifier still
  counts distinct signers, so a single key cannot reach the majority.
- The span schedule is weighted by stake; the verifier uses only the distinct addresses, not the weights.
- Validator-contract changes inside a span take effect at the next span block.

## Live verification

- Fixtures: `test/e2e/fixtures/signer-replay-live/kub-mainnet.json`, `kub-testnet.json` (and `-vectors.json`),
  captured 2026-10-01. Probe contracts: mainnet stake manager `0x443502b3f7c0934576f49cda084f78640f56a80f`, testnet
  `0xc2c3e497cc97582b11efd517c4eaf99cc45f14a4` (code hash pinned, channel slots empty).
- Verified: config on span block B0 with an 11-header (mainnet) / 6-header (testnet) bootstrap run, a bundle whose
  run starts at the next span block B1 (rotation; the mainnet set changed from 6 to 7 signers), the same bundle under
  the rotated anchor.
- Refresh: `npx tsx test/e2e/relay/buildSignerReplayLiveProof.ts --refresh --network kub-mainnet` (or `kub-testnet`).
  Replay: `npm run test:e2e:signer-kaia-live`, `forge test --match-contract SignerReplayLive -vv`.

## Hiero → KUB Chain

Not built. KUB runs an EVM, so the reference Hiero verifier could be deployed there; it is blocked on the same Hiero
proof source as Hiero → Ethereum.
