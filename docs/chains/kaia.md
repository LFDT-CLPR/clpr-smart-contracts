# Kaia → Hiero

Kaia → Hiero · status: live-verified on Kaia mainnet and Kairos (2026-10-01)

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `8217` / `eip155:8217`; Kairos `1001` / `eip155:1001` |
| Chain type | L1, Klaytn lineage, Istanbul BFT (kaiachain/kaia) |
| Finality source | Committed seals from 2f + 1 of the qualified validator set (f = ⌈N/3⌉ − 1); committed blocks are final |
| Verifier | `KaiaIstanbulVerifier` ([family README](../../src/verifiers/evm/kaia/README.md)) |
| Trust tier | BFT: at most f of each qualified set malicious; f + 1 of the trusted set vouch for each set change; bootstrap header trusted |
| Typical bundle | Mainnet, no rotation: 1,501,674 gas, 14,500 B calldata |
| Rotation | Mainnet, set change 30 → 31 validators: 1,609,912 gas, 14,468 B calldata |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `CHAIN_ID` (constructor) | 8217 (mainnet), 1001 (Kairos) | `eth_chainId` on the public RPCs; `params/config.go` |
| Bootstrap header | Any recent header; its qualified set becomes the anchor | `kaia_getBlockByNumber` at deployment (must carry 2f + 1 seals) |
| Qualified validators | Mainnet 31, Kairos 4 (2026-10-01) | `extraData` of live headers |
| Committee size (governance) | 50 on mainnet | `kaia_getParams` (`istanbul.committeesize`) |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- RPC methods: `kaia_getBlockByNumber` (Kaia header fields), `eth_getProof`, `eth_blockNumber`, `eth_chainId`.
- Archive depth: the mainnet public RPC (`public-en.node.kaia.io`) served state 1,000,000 blocks back; the Kairos
  public RPC only about the last 100 blocks. Fetch the proof right after choosing the state block on Kairos.
- Rotations: include the first header of each newer qualified set since the anchor. Set changes are rare: the newest
  mainnet change before the capture was at block 227,942,837, 697,021 blocks (about 8 days at 1 s blocks) before the
  recent fixture block.
- No signature aggregator is needed; committed seals are in every header.

## Chain-specific trust and caveats

- Kaia counts committed seals against its council before the permissionless fork; the verifier counts only the
  qualified set in the header (stricter).
- The quorum uses the full qualified count. If governance lowers `istanbul.committeesize` below it, valid blocks with
  fewer seals than the verifier requires can appear (liveness only).
- The scheduled-but-unset `PermissionlessCompatibleBlock` fork changes the seal preimage (adds the round) and the
  committee rule; the verifier needs an update before it activates.
- The proposer is one of the qualified validators; Kaia's governance (GC members) controls who qualifies.

## Live verification

- Fixtures: `test/e2e/fixtures/kaia-live/kaia-mainnet.json`, `kairos.json` (and `-vectors.json`), captured
  2026-10-01.
- Mainnet: bootstrap at block 227,942,836 (30 validators), rotation at 227,942,837 (31 validators, 21 committed
  seals, all 21 from the old set), plain bundle at 228,639,858 under the rotated anchor. Kairos: bootstrap at
  229,187,609, bundle at 229,197,609 (4 validators, 3 seals). The bundles prove the AddressBook system contract
  `0x0000000000000000000000000000000000000400` (Kaia SmartContractAccount leaf, code hash pinned) and empty channel
  slots.
- Refresh: `npm run kaia-live:refresh`. Replay: `npm run test:e2e:signer-kaia-live` (anvil) and
  `forge test --match-contract KaiaIstanbulLive -vv`.

## Hiero → Kaia

Not built. Kaia runs an EVM, so the reference Hiero verifier could be deployed there; it is blocked on the same Hiero
proof source as Hiero → Ethereum.
