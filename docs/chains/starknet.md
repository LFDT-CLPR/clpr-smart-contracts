# Starknet

Starknet → Hiero · status: live-verified on Starknet Sepolia over Ethereum Sepolia (2026-10-01, fixture capture
timestamp)

Starknet mainnet uses the same contracts with its own core address and pins. Its core proxy layout, `identify()` and
upgrade delay were checked by hand; there is no committed mainnet fixture.

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | mainnet `SN_MAIN` (`starknet:SN_MAIN`); testnet `SN_SEPOLIA` (`starknet:SN_SEPOLIA`) |
| Chain type | L2, Starknet validity rollup (Cairo VM), settles on Ethereum |
| Finality source | `globalRoot` and `blockNumber` stored by the Starknet core contract on Ethereum after the STARK verifier accepts the state transition, read through the Ethereum sync committee |
| Verifier | `StarknetVerifier` + `StarknetStateProver` + `EthL1StateVerifier`; family README: [Starknet verifier](../../src/verifiers/evm/starknet/README.md) |
| Trust tier | Ethereum sync committee (2/3 of 512) + Starknet validity proofs + Starknet governance (upgrade delay 0), optionally pinned |
| Typical bundle | live, ACK-only, 8 keys: 7,145,849 gas (`eth_estimateGas`), 28,900 B calldata. Synthetic dense tries: 4,676,296 execution gas, 9,210 B proof |
| Rotation | in-bundle; synthetic ACK-only + rotation: 9,062,012 execution gas, 76,109 B proof; live: not measured |

## Deployment profile

| Parameter | Starknet Sepolia | Starknet mainnet | Read from |
|---|---|---|---|
| L1 network | Ethereum Sepolia | Ethereum mainnet | `test/e2e/relay/buildStarknetLiveProof.ts` (`STARKNET_SEPOLIA`) |
| `profile.core` | `0xE2Bb56ee936fd6433DC0F6e7e3b8365C906AA057` | `0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4` | Starknet docs "Important addresses"; Sepolia also `capture.json` (`l1.core`) |
| Implementation (proxy) | `0x63bc073a57c7f875d9d61bd5cb15e84c0da9b967` at capture time | read the implementation slot at deployment | `capture.json` (`l1.implementation`) |
| `profile.coreImplCodeHash` | `0x3e4c29452ca89b3642b0dd4911da842b6a7c6cb94bff23775ac96abc9ffa4dc7`, or zero | read `eth_getProof(implementation)` at deployment, or zero | `capture.json` (`l1.implProof.codeHash`) |
| `profile.pinnedSlots` | `programHash` slot `0x8cde0e99a4532474b22bd3952cb1c6b00478babd3678337325283f4f48110fc4`, `aggregatorProgramHash` slot `0x7634922d6dfbfe3f0fece14b6593833696a54066c50dd58583d30f3d2ce6dd9c` | same slots | `StarknetCoreProof.sol` constants; `buildStarknetLiveProof.ts` (`LIVE_PINNED_SLOTS`) |
| `profile.pinnedValues` | `0x1420d23187254d4dcf4006fa6ad997b0728f845416bcfd1478c7e8f804fb429`, `0x2526c12112a2d7f57f7ae74af7be1fe1b2766e4c34b0c88ceda16b70ed2d6c2` at capture time | read at deployment; they change with every Starknet OS release | `capture.json` (`l1.coreProof.storageProof[3..4]`) |
| `layout` | CLPR Starknet layout v0 | same | `test/e2e/relay/starknet.ts` (`CLPR_LAYOUT_V0`); family README |
| `EthL1StateVerifier` constructor | `(802, 9, 87, 6, 8192)` (Electra/Fulu) | same | `starknet-live-sepolia.spec.ts`, `EthL1StateVerifier.sol` NatSpec |
| Anchor GVR | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` | read `/eth/v1/beacon/genesis` on a mainnet beacon node | `capture.json` (`beacon.genesisValidatorsRoot`) |
| Anchor fork version | Fulu `0x90000075` | read the current fork version from mainnet `/eth/v1/config/spec` | `capture.json` (`beacon.spec`) |
| Anchor bootstrap committee | `light_client/bootstrap` of a finalized root | same | `test/e2e/relay/buildEthLiveProof.ts` |
| Anchor `codeHash` | the Cairo ClprService's class hash, or zero. The live fixture pins the STRK token's class `0x02e77ee6…98fc` as a stand-in | same procedure | `starknet_getStorageProof` `contract_leaves_data[].class_hash` |

Pinning the program hashes makes the verifier stop at the next Starknet OS release; leave `pinnedSlots` empty to
follow governance. Re-read every value at deployment.

## Relayer requirements

- **Ethereum beacon API:** `/eth/v1/beacon/light_client/finality_update`, `/eth/v1/beacon/light_client/bootstrap/{root}`,
  `/eth/v1/beacon/light_client/updates` (rotation), `/eth/v1/beacon/genesis`, `/eth/v1/config/spec`.
- **Ethereum execution RPC:** `eth_getStorageAt` and `eth_getProof` on the core contract and its implementation at
  the signed block, `eth_getBlockByNumber`, `eth_getLogs` (`LogStateUpdate`, to learn the posting stride). A full node
  works if proofs are fetched while the block is recent.
- **Starknet RPC:** `starknet_blockNumber`, `starknet_getBlockWithTxHashes`, `starknet_getStorageProof` (RPC v0.8+).
  Public endpoints (Cartridge, PublicNode) serve storage proofs only for recent blocks, so the relayer must fetch the
  proof of each block the core contract will post while the Starknet head is near it, and keep it until L1 posts the
  block. A Pathfinder or Juno node that keeps storage proofs removes this timing constraint.
- **Cadence:** one sync-committee rotation per Ethereum period (8,192 slots, about 27 hours). Starknet Sepolia posted
  a state update every 1,000 Starknet blocks, about every 29 minutes, on 2026-10-01 (`LogStateUpdate` events).

## Chain-specific trust and caveats

- Same as the family baseline.
- The core contract's upgrade delay is 0 on Sepolia and mainnet: governance can change the implementation, the
  program hashes and the verifier address in one transaction. Pin them to stop on such a change, or leave them
  unpinned to trust governance.
- Latency: a Starknet block is deliverable once the core contract posts it. On 2026-10-01 Sepolia posted blocks about
  10 minutes after the Starknet head passed them; earlier the same day the core contract stayed on one block for more
  than 2 hours. Neither is measured by a test.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/starknet-sepolia-live/capture.json`, `capturedAt` 2026-10-01T07:44:08Z |
| Data | Sepolia signature slot 11258919, execution block 11820404, 512/512 participation, Fulu; core contract at Starknet block 15909215 (Starknet 0.14.4), global root `0x1f8ac88f…f5333`, equal to that block's `new_root`; STRK token storage proof (23 contract + 59 storage nodes) staged at that block |
| Second live proof | `test/verifiers/evm/starknet/fixtures/sepolia-storage-proof-15900215.json` (Foundry `test_live_sepoliaStorageProof`): block 15900215, STRK token, 23 contract + 41 storage nodes |
| Refresh | `npm run starknet-live:stage` until a block is staged, then `npm run starknet-live:refresh` |
| Replay | `forge build && npm run test:e2e:starknet-live` |
| Verified | sync committee → L1 state root → core contract `globalRoot`/`blockNumber`, implementation code hash and program-hash pins → global root formula → STRK contract leaf (class hash pinned) → storage trie: total supply present, the 8 CLPR channel keys proven absent; full ACK-only `verifyBundle` returning zeroed metadata; rejections for another class hash, another channel, another implementation code hash, a changed program hash and the previous fork version (Electra) |

There is no ClprService on Starknet Sepolia, so the STRK token stands in. Every cryptographic link runs on real data.

## Hiero → Starknet direction

Not covered by this branch. It needs a Hiero verifier written in Cairo and deployed on Starknet, and a relayer that
submits Hiero bundles there.
