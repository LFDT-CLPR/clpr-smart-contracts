# NEAR → Hiero

NEAR → Hiero · status: live-verified on NEAR mainnet and testnet (2026-10-01, fixture capture timestamps)

NEAR finalizes blocks with Doomslug approvals from the epoch's block producers. `NearVerifier` is a
NEP-25 light client on Hedera: it keeps the producer-set hashes of the current and next epoch, checks
that more than 2/3 of the stake approved a light-client block, and proves the CLPR Service's storage
with a NEAR state-trie proof under that block's state root. Full design:
[family README](../../src/verifiers/evm/neartons/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `near:mainnet`, `near:testnet` |
| Chain type | L1, sharded (10 shards on both networks at capture), Nightshade + Doomslug |
| Finality source | Light-client block approved (`approvals_after_next`) by > 2/3 of the epoch's block-producer stake |
| Verifier contract | `src/verifiers/evm/neartons/NearVerifier.sol` · [family README](../../src/verifiers/evm/neartons/README.md) |
| Trust tier | > 2/3 of each followed producer set's stake; deploy-time epoch-window checkpoint |
| Typical bundle | Mainnet: 1.26M gas, 18.1 KB with 49 cached approvals, after 3 cache transactions (8.90M, 8.90M, 4.02M gas). Testnet: 2.94M gas, 9.8 KB with 6 inline approvals |
| Rotation | Epoch change inside the bundle: +600 gas, no extra calldata |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `chainId` | `near:mainnet` / `near:testnet` | `test/e2e/relay/buildNearLiveFixture.ts` (`NEAR_TARGETS`) |
| Checkpoint (mainnet, tests) | epoch `0x91c6266c…fc36`, next `0x734e9549…b2df`, bp hashes `0x635a7fad…86f7`, `0x54294a4e…d5a1` (epoch ending at height 218,001,133) | `test/e2e/fixtures/near-live/mainnet.json` (`derived.checkpointPrev`) |
| Checkpoint (testnet, tests) | epoch `0x555edfd6…3e5e`, next `0x9cf0f2d7…2d12`, bp hashes `0xe3047f6a…e96d`, `0xfc0e5e1f…3e03` (epoch ending at height 270,992,454) | `test/e2e/fixtures/near-live/testnet.json` |
| Checkpoint source | Last block of an epoch: `epoch_id`, `next_epoch_id`, sha256 of borsh producers of both epochs (`EXPERIMENTAL_validators_ordered`), checked against `next_bp_hash` | `buildNearLiveFixture.ts:buildLightClientPart` |
| `Ed25519Verifier` | The shared pure-Solidity verifier | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `ClprEd25519SignatureCache` | Required on mainnet (49 approvals > one transaction); optional on testnet | `src/verifiers/evm/neartons/ClprEd25519SignatureCache.sol` |
| Epoch length | 43,200 blocks; 100 producer seats on mainnet, 20 on testnet | `EXPERIMENTAL_protocol_config` (protocol 86 mainnet, 87 testnet) |
| Service storage keys | `"q" ‖ channelId` → borsh `ChannelQueue`, `"m"` → manifest commitment, `"c"` → keccak256(ControlMessage) | `NearVerifier.sol` header |

## Relayer requirements

- NEAR JSON-RPC: `block` (final head and chunk `prev_state_root`s), `next_light_client_block`,
  `validators`, `EXPERIMENTAL_validators_ordered`, and `query` `view_state` with `include_proof` at
  the light-client block's `prev_block_hash`. The public `rpc.mainnet.near.org` and
  `rpc.testnet.near.org` serve all of them; `view_state` refuses contracts above the RPC's state-size
  limit (not a concern for a small CLPR Service contract).
- One light-client block per epoch at least (43,200 blocks); older blocks need an archive RPC.
- Mainnet: record the chosen approvals in `ClprEd25519SignatureCache` first, 20 per transaction
  (2–3 transactions per block).
- Choose the heaviest approvers until > 2/3 of stake (the builder picks 49 of 73 signers on mainnet).

## Chain-specific trust and caveats

- Trusts block producers' approvals only; chunk validity is trusted to them as in any NEP-25 light
  client.
- The proven state is the state after the light-client block's parent (`prev_state_root`).
- Only Ed25519 producer keys can approve; `BlockHeaderInnerLite` V1 and `ValidatorStake::V1` are
  decoded strictly.
- No CLPR Service exists on NEAR; the live fixtures prove `lockup.near` (mainnet) and
  `hello.near-examples.testnet` (testnet) `STATE` entries.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/near-live/mainnet.json`, `testnet.json` |
| Captured | mainnet 2026-10-01T05:36:06Z (height 218,019,176), testnet 2026-10-01T05:35:40Z (height 271,030,645) |
| Refresh | `npm run neartons-live:refresh` (or `npx tsx test/e2e/relay/buildNearLiveFixture.ts --refresh`) |
| Replay | `forge build && npm run test:e2e:neartons-live`; forge: `forge test --match-path test/verifiers/evm/neartons/NearLive.t.sol -vv` |
| What was verified | Real light-client blocks with real Ed25519 approvals (mainnet 49 of 100 producers via the cache, testnet 6 of 20 inline), a real epoch rotation (the same block from the previous epoch's anchor), chunk-root merklization over 10 shards, and trie proofs of 17 (mainnet) and 22 (testnet) nodes |

## Hiero → NEAR direction

Not started on this branch. It needs a Hiero verifier deployed as a NEAR contract.
