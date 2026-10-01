# Flare → Hiero

Status: live-verified on Flare mainnet and Coston2 (2026-10-01), using a self-run signature aggregator.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `14` / `eip155:14`; Coston2 `114` / `eip155:114` |
| Chain type | L1, go-flare (an avalanchego fork with coreth and the Warp stack) |
| Finality source | Snowman acceptance, attested by a Warp BLS aggregate of at least 67% of the validator stake |
| Verifier | `AvalancheWarpVerifier`, unmodified ([family README](../../src/verifiers/evm/avalanche/README.md)) |
| Trust tier | Fewer than 1/3 of tracked stake malicious; **validator-set changes trusted to t-of-n attestors**; bootstrap set trusted |
| Typical bundle | Mainnet: 2,307,686 gas (`eth_estimateGas`), 38,660 B. Coston2: 1,541,142 gas, 15,780 B |
| Rotation | Mainnet: 2,548,571 gas, 38,884 B (+240,885 gas). Coston2: 1,596,222 gas, 16,004 B (+55,080 gas) |

## Deployment profile

| Parameter | Mainnet | Coston2 | Source |
|---|---|---|---|
| `evmChainId` | 14 | 114 | Fixture `evmChainId`; `_requireChainBinding` |
| `networkId` | 14 | 114 | Fixture `networkId` |
| `sourceChainId` | `0x77d3074d…3fc625` (`FLARE_C_CHAIN_ID`), cb58 `umkbhSrjVw5nUvy1eo25AdrjRkPBdtzAMewuxA2rqEx4YMo4c` | `0x78db5c30…552479` (`COSTON2_C_CHAIN_ID`), cb58 `vE8M98mEQH6wk56sStD1ML8HApTgSqfJZLk9gQ3Fsd4i6m3Bi` | Constants in `AvalancheWarpVerifier.sol`; fixture `sourceChainIdCb58` |
| Bootstrap set | 180 keys at P-Chain height 2,105,648 in the fixture | 8 keys at 13,603 | `platform.getValidatorsAt` on `{flare,coston2}-api.flare.network/ext/bc/P` |
| `totalWeight` | Above uint64 (about 2.2 x 10^19 nFLR), stored as uint256 | 2.5 x 10^17 | P-Chain API |
| `maxSetAge` | 604,800 s (7 days) in the fixture; minimum stake duration is 60 days after Granite | same | Fixture `maxSetAge`; go-flare `txs/executor/inflation_settings.go` |
| Attestors | Operator choice; t-of-n | 2-of-3 test keys in the fixture | Fixture `attestorThreshold` |
| Live probe account | WFLR `0x1D80c49BbBCd1C0911346656B529DF9E5c2F783d` | WC2FLR `0xC67DCE33D7A8efA5FfEB961899C73fe01bCe9273` | `buildAvalancheLiveProof.ts` |

## Relayer requirements

- C-Chain RPC: `eth_getBlockByNumber`, `eth_getProof` (public Flare RPCs serve proofs only for recent state; go-flare's
  coreth has no ACP-194 fields, so the state root is the block's own).
- P-Chain API: `platform.getValidatorsAt(height)`.
- **A self-run signature aggregator.** No public aggregator serves Flare. `tools/flare-signature-aggregator/run.sh`
  runs Ava Labs' `signature-aggregator` (icm-services `bd47aec`, avalanchego v1.15.0). It needs no Flare node and no
  keys: it reads peer IPs from `info.peers`, dials validators on port 9651 with an ephemeral TLS staking cert, and
  sends ACP-118 requests. On mainnet a weight proxy divides P-Chain weights by 16 for the aggregator only, because
  avalanchego v1.15 decodes weights as uint64; the verifier checks the exact weights.
- Pin the aggregator to the anchor's P-Chain height. The set changes at almost every height through delegations, but
  an anchor's set stays usable while its signers hold 67% of its weights and `maxSetAge` has not passed.

## Chain-specific trust and caveats

- Same trust as the family. All 180 Flare and 8 Coston2 validators have BLS keys; the Warp precompile answers
  `getBlockchainID()` on live RPCs.
- Coston2 has 8 validators, so 5 signers hold the quorum in the fixture (67.05%).
- Coston2's P-Chain can go hours without a block, which is why the fixtures use a 7-day `maxSetAge`.
- Songbird and Coston run the same go-flare code and are likely covered; they were not captured.

## Live verification

- Fixtures: `test/e2e/fixtures/flare-live/flare/` (captured 2026-10-01T05:20Z, block 71,039,852) and
  `test/e2e/fixtures/flare-live/coston2/` (2026-10-01T05:19Z, block 36,059,992).
- Refresh: start `tools/flare-signature-aggregator/run.sh flare` (or `coston2`), then `npm run flare-live:refresh`.
- Replay: `forge test --match-contract FlareWarpLive -vv` and `npm run test:e2e:flare-live` (28 tests).
- Verified: mainnet aggregate of 91 of 180 validators (67.08% of stake) and Coston2 aggregate of 5 of 8 (67.05%) over
  real blocks; a real set change (weights only on mainnet, 2,105,647 → 2,105,648; Coston2 13,559 → 13,603); account
  and channel-slot exclusion proofs; negative cases (replay, threshold, wrong set, replaced signer key, tampered
  signature, dropped signer, swapped state root, stale set, code hash, wrong network id).

## Hiero → Flare

Not built on this branch. Flare runs the EVM, so the direction would use the reference Hiero verifier deployed on
Flare. It is blocked on the same Hiero proof source as Hiero → Ethereum.
