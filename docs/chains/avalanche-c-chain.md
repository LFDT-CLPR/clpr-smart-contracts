# Avalanche C-Chain → Hiero

Status: live-verified on Fuji (2026-10-01). Avalanche mainnet: validator-set size and signer count measured live
(2026-10-01), no full bundle run.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `43114` / `eip155:43114`; Fuji `43113` / `eip155:43113` |
| Chain type | L1, Avalanche Primary Network C-Chain (coreth, Snowman consensus) |
| Finality source | Snowman acceptance, attested by a Warp BLS aggregate of at least 67% of the Primary Network stake over the block hash |
| Verifier | `AvalancheWarpVerifier` ([family README](../../src/verifiers/evm/avalanche/README.md)) |
| Trust tier | Fewer than 1/3 of tracked stake malicious; **validator-set changes trusted to t-of-n attestors**; bootstrap set trusted |
| Typical bundle | Fuji live: 1,738,297 gas (`eth_estimateGas`), 23,172 B. Mainnet scale (synthetic, 588 keys, 170 signers, 1-leaf MPT): 2,040,114 gas, 63,236 B |
| Rotation | Fuji live: 1,861,747 gas, 23,396 B (+123,450 gas, +224 B). Mainnet scale (synthetic): 2,723,824 gas, 63,460 B |

## Deployment profile

| Parameter | Mainnet | Fuji | Source |
|---|---|---|---|
| `evmChainId` | 43114 | 43113 | `eth_chainId`; `_requireChainBinding` in the verifier |
| `networkId` | 1 | 5 | avalanchego network ids; fixture `networkId` |
| `sourceChainId` (C-Chain blockchain id) | `0x0427d4b2…3fd652` (`MAINNET_C_CHAIN_ID`) | `0x7fc93d85…ac10d5` (`FUJI_C_CHAIN_ID`), cb58 `yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp` | Constants in `AvalancheWarpVerifier.sol`; fixture `sourceChainIdCb58` |
| Bootstrap set | `platform.getValidatorsAt(height)`; 588 unique keys on 2026-10-01 | 71 keys (72 nodes, one key shared) at P-Chain height 298,993 in the fixture | P-Chain API |
| `maxSetAge` | At most the minimum stake duration: 48 h after Helicon (14 days before) | 43,200 s (12 h) in the fixture | Fixture `vectors.json`; avalanchego staking config |
| Attestors | Operator choice; t-of-n | 2-of-3 test keys (anvil accounts 0-2) in the fixture | Fixture `attestorThreshold` |
| ClprService code hash | Deployment | Fixture pins the WAVAX probe account's code hash | `eth_getProof` |
| Live probe account | – | WAVAX `0xd00ae08403B9bbb9124bB305C09058E32C39A48c` | `DEFAULT_ACCOUNT` in `buildAvalancheLiveProof.ts` |

## Relayer requirements

- C-Chain RPC: `eth_getBlockByNumber`, `eth_getProof`. On Fuji (ACP-194) the proof is taken at the header's
  `settledHeight`; public RPCs keep only recent states, so call `eth_getProof` right after choosing the block.
- P-Chain API: `platform.getValidatorsAt(height)` with a numeric height (the fixture uses the publicnode P-Chain
  endpoint, because the Ava Labs endpoint rejects numeric heights).
- Signature aggregator: Ava Labs' hosted ACP-118 aggregator (Glacier API), pinned to the anchor's P-Chain height.
- Attestors: each recomputes the set from its own node and signs rotations.
- Rotation cadence: when the anchor's signers can no longer reach 67% of its weights, or before `maxSetAge` ends.

## Chain-specific trust and caveats

- ACP-194 (SAE) is live on Fuji: the header's `stateRoot` is the settled state a few blocks back. The verifier is
  unaffected.
- On mainnet the packed set is about 61 KB and rides in every bundle; above about 1,100 keys it would not fit in
  128 KB with the proofs.
- Avalanche L1s on subnet-evm (ACP-77) use the same contract with the L1's own set, `networkId` and blockchain id; the
  config check is then self-consistency only.

## Live verification

- Fixtures: `test/e2e/fixtures/avalanche-live/capture.json` (captured 2026-10-01T03:23Z, block 58,917,766) and
  `vectors.json`.
- Refresh: `npm run avalanche-live:refresh`. Replay: `forge test --match-contract AvalancheWarpLive -vv` and
  `npm run test:e2e:avalanche-live` (14 tests).
- Verified: a real Warp aggregate (12 of 71 keys, 67.03% of stake) over a real accepted block; a real set change
  (70 keys at P-Chain 298,945 → 71 keys at 298,993) applied by test attestors; the WAVAX account proof and channel-slot
  exclusion proofs; negative cases (replayed rotation, too few attestations, wrong set, replaced signer key, tampered
  signature, dropped signer, swapped state root, stale set, code hash, other network id).

## Hiero → Avalanche C-Chain

Not built on this branch. The C-Chain runs the EVM, so the direction would use the reference Hiero verifier deployed
on the C-Chain. It is blocked on the same Hiero proof source as Hiero → Ethereum.
