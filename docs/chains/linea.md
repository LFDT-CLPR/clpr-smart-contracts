# Linea

Linea → Hiero · status: live-verified on Ethereum mainnet (2026-10-01)

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | `eip155:59144` |
| Chain type | L2, zk rollup (Consensys), settles on Ethereum |
| Finality source | `LineaRollup.stateRootHashes[L2 block]`, written by `finalizeBlocks` after the PLONK proof, read through the Ethereum sync committee |
| Verifier | `LineaRollupVerifier` + `LineaStateTrieVerifier` + LineaPoseidon2 hasher + `EthL1StateVerifier`; family README: [L1-settled rollup verifiers](../../src/verifiers/evm/zkrollup/README.md) |
| Trust tier | Ethereum sync committee (2/3 of 512) + Linea's validity proofs, its operator and verifier-setter roles, and its upgrade timelock (min delay 0 on 2026-10-01) |
| Typical bundle | live (stand-in, 5 absent slots): 8,174,997 gas, 18,660 B calldata. With a real ClprService (derived): 7.85M to 9.88M gas |
| Rotation | in-bundle; +4,777,726 gas and +66,080 B over a plain bundle (measured on the L1 light client); derived Linea rotation bundle 12.6M to 14.7M gas |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `rollup` | `0xd19d4B5d358258f05D7B411E21A1460D11B0876F` (LineaRollup proxy) | Linea's L1 contract; `test/e2e/relay/zkrollup.ts` (`LINEA_MAINNET`) |
| `stateRootsSlot` | 282 (`ZkEvmV2.stateRootHashes`) | Found by scanning storage: `currentL2BlockNumber` is slot 281; `storage[keccak(n ‖ 282)] == stateRootHashes(n)` checked on mainnet |
| `implementation` | `0x052b73d934E9412045Bf731574463Fd026D74645` | EIP-1967 slot of the proxy, 2026-10-01; verified source on Blockscout (`LineaRollup`, solc 0.8.33) |
| `minKey` | 0 | Older (MiMC) roots cannot be opened with Poseidon2 proofs, so they fail closed |
| Mapping key | L2 block number (`currentL2BlockNumber` = newest finalized block) | `LineaRollupBase._finalizeBlocks` |
| `EthL1StateVerifier` | `(802, 9, 87, 6, 8192)` | Electra/Fulu layout |
| Anchor GVR | `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95` | `capture.json` (`beacon.genesisValidatorsRoot`) |
| Anchor fork version | Fulu `0x06000000` | `capture.json` (`beacon.spec.FULU_FORK_VERSION`) |
| Anchor `codeHash` | keccak256 code hash of the ClprService on Linea (account field `keccakCodeHash`) | `linea_getProof` account value |
| ProxyAdmin / owner | `0xF5058616517C068C7b8c7EbC69FF636Ade9066d6` / TimeLock `0xd6B95c960779c72B8C6752119849318E5d550574` (`getMinDelay() = 0`) | mainnet reads, 2026-10-01 |

## Relayer requirements

- Ethereum beacon API (`light_client/finality_update`, `bootstrap`, `updates`, `genesis`, `config/spec`) and an Ethereum
  execution RPC with `eth_getStorageAt` (slot 281) and `eth_getProof` at the signed header's block.
- Linea RPC with `linea_getProof` at the finalized block (and `eth_getBlockByNumber`). `rpc.linea.build` served it for a
  block 3.7 hours old on 2026-10-01; `linea-rpc.publicnode.com` does not offer the method. A Linea node with the state
  manager (Shomei) is the production option.
- Proof conversion: the relayer hashes the RPC's node openings into sibling hashes and merges the slot proofs into one
  multiproof (`test/e2e/relay/linea.ts`).
- Cadence: one sync-committee rotation per Ethereum period (about 27 hours).

## Chain-specific trust and caveats

- The finalized root is Linea's Poseidon2 state-trie root, not the MPT root in Linea block headers; proofs come from
  `linea_getProof`, not `eth_getProof`.
- Finalization is permissioned (OPERATOR_ROLE); after six months without finalization a liveness-recovery operator gets
  the role. The PLONK verifier per proof type is set by VERIFIER_SETTER_ROLE.
- Latency: the finalized block was 13,426 s (3.7 h) older than the L1 block at capture.
- Gas: each absent Channel slot costs two leaf paths of Poseidon2 hashing (about 24,700 gas per 32-byte block). A
  rotation bundle with absent slots can approach 15M.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/linea-live/capture.json`, captured 2026-10-01T08:36:38Z |
| Data | L1 block 26,096,313 (slot 15,334,979, 508/512 signers, Fulu); finalized L2 block 32,197,714, root `0x1844…0b4f`; stand-in Linea L2 TimeLock `0xc808BfCBeD34D90fa9579CAa664e67B9A03C56ca` (21-leaf storage trie) |
| Refresh | `npm run zkrollup-live:refresh:linea` |
| Replay | `forge build && npm run test:e2e:zkrollup-live`; `forge test --match-contract LineaLiveTest -vv` |
| Verified | sync committee → L1 state root → finalized Linea root at the pinned implementation → account leaf → 5 absent Channel slots (8 leaves, 43 siblings); rejections: not-finalized key, below-threshold participation, other fork version, other committee, other code hash, other channel, other service address, upgraded implementation, other rollup, other mapping slot, key below `minKey`, rotated (stale) anchor, other account, tampered sibling, non-canonical key alias, non-adjacent bracket, absent slot claimed present, unsorted leaves, extra sibling |

## Hiero → Linea direction

Not covered by this branch. Linea runs the EVM, so a Hiero verifier deployed on Linea (as on other EVM chains) and a
relayer submitting Hiero bundles there would serve it.
