# GRX Chain → Hiero

GRX Chain → Hiero · status: live-verified on GRX Chain mainnet (2026-10-01)

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `1110` / `eip155:1110` (testnet RPC `testnet.grxchain.io` did not answer on 2026-10-01) |
| Chain type | L1, go-ethereum fork reporting `Geth/v1.3.0-unstable`; HECO Congress layout (DPoS with system contracts) |
| Finality source | None; Congress seal by a current validator |
| Verifier | `SignerReplayVerifier` with `SignerReplayProfiles.grx` ([family README](../../src/verifiers/evm/signer/README.md)) |
| Trust tier | Majority of 3 validators (2 needed) |
| Typical bundle | Mainnet: 1,427,520 gas, 16,516 B calldata (2-header run) |
| Rotation | Mainnet, epoch block 12,265,200 → 12,265,400 (same 3 validators): 1,434,413 gas, 16,516 B calldata |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 1110 | `eth_chainId` on `rpc.grxchain.io` |
| `epochLength` / `boundaryOffset` | 200 / 0 | Live epoch blocks (only multiples of 200 carry a validator list) |
| `sealFields` | 15 (no baseFee in the seal hash) | Live headers recover the miner only with the 15-field encoding; matches HECO Congress `encodeSigHeader` |
| `entrySize` / `trailerSize` | 20 / 0 | Live epoch `extraData` |
| Validators (2026-10-01) | `0x0d2ef3b338297dc40671fc91f8766ed564c957ae`, `0x46b24c9cf02f01a721cee95fd30458deedbe161d`, `0x7fdfaad52c7f1301c0c61fe922278f5c4f55fcb7` | Epoch blocks 12,265,200 and 12,265,400 |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `eth_getBlockByNumber`, `eth_getProof`, `eth_chainId`. The public RPC served state 1,000,000 blocks
  back.
- `rpc.grxchain.io` served an expired TLS certificate on 2026-10-01; the capture script skips certificate checks for
  that host only (the data is verified by hash links, seals and MPT proofs). A production relayer should use its own
  node.
- Runs of 2 headers (2 of 3 validators); an epoch block every 200 blocks.

## Chain-specific trust and caveats

- The node source is not published (no public repository found). The profile was derived from live data: the
  15-field seal hash, the 20-byte epoch list, and Congress system contracts deployed at `0x…f000`, `0x…f001`,
  `0x…f002`. A protocol change on GRX would not be visible in source before it ships.
- Three validators: two colluding operators can produce an accepted run.

## Live verification

- Fixtures: `test/e2e/fixtures/signer-replay-live/grx-mainnet.json` (and `-vectors.json`), captured 2026-10-01.
  Probe contract: the Congress `Validators` system contract `0x000000000000000000000000000000000000f000` (no user
  transactions appeared in the 400 most recent blocks; code hash pinned, channel slots empty).
- Verified: config on epoch block B0 with a 2-header bootstrap run, a bundle whose run starts at the next epoch block
  B1 (rotation, same set), the same bundle under the rotated anchor; the all-fields seal rule is rejected on the same
  data.
- Refresh: `npx tsx test/e2e/relay/buildSignerReplayLiveProof.ts --refresh --network grx-mainnet`. Replay:
  `npm run test:e2e:signer-kaia-live`, `forge test --match-contract SignerReplayLive -vv`.

## Hiero → GRX Chain

Not built. GRX runs an EVM, so the reference Hiero verifier could be deployed there; it is blocked on the same Hiero
proof source as Hiero → Ethereum.
