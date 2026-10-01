# Plasma → Hiero

Plasma → Hiero · status: live-verified on Plasma mainnet (2026-10-01)

Plasma is a stablecoin L1 with reth execution and PlasmaBFT consensus, a Fast HotStuff variant
with a two-chain commit. `PlasmaBftVerifier` checks the BLS quorum certificates on block B and on
its child B+1, opens B's EVM `stateRoot` from the SSZ consensus block, and proves the ClprService
queue slots in the Merkle-Patricia state. Full design:
[PlasmaBftVerifier README](../../src/verifiers/evm/plasma/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 9745 / `eip155:9745` (mainnet) |
| Chain type | L1, EVM execution (reth), PlasmaBFT consensus (closed source) |
| Finality source | Two consecutive QCs (B and B+1), BLS12-381 min-pk aggregate, quorum `n − ⌊(n−1)/3⌋` |
| Verifier contract | `src/verifiers/evm/plasma/PlasmaBftVerifier.sol` · [family README](../../src/verifiers/evm/plasma/README.md) |
| Trust tier | Honest quorum of one committee pinned at deploy by its SSZ root; no rotation |
| Typical bundle | 3,320,812 gas, 9,316 B calldata (mainnet height 33,898,400, 10 members, 7 + 7 votes) |
| Rotation | Not supported; a committee change halts the channel |

## Deployment profile

| Parameter | Mainnet value | Read from |
|---|---|---|
| `chainId` | `"9745"` | `test/e2e/fixtures/plasma-live/mainnet.json` (`chainId`) |
| `bootstrapCommitteeRoot` | `0x19d2fc7b04d244918d66d2ad97bcdc8da5145abc5640a427be8772283488c7cf` (10 members) | `test/e2e/fixtures/plasma-live/mainnet.json` (`committeeRoot`); equals header leaves 9 and 10 |
| `bootstrapHeight` | `33898400` in the tests | `test/e2e/fixtures/plasma-live/mainnet.json` (`height`) |
| Committee contract | `0x6c50b8ca8EeAa1c75dEe5b5EA79772AcAbc92F48`, `getValidators()` (`0xb7ab4db5`) | `test/e2e/relay/buildPlasmaLiveFixture.ts` (`PLASMA_COMMITTEE_CONTRACT`) |
| Bootstrap source | `getValidators()` at the bootstrap height, keys sorted by compressed bytes, SSZ `List[Bytes48, 1024]` root | `test/e2e/relay/plasma.ts` (`committeeRoot`, `sortKeys`) |

## Relayer requirements

- Consensus data: libp2p gossipsub topic `consensus-block` from the public mainnet observer
  bootnodes (`*.plasmalabs.tech:34070`, listed in `buildPlasmaLiveFixture.ts`), or an own
  non-validator node. No RPC serves consensus blocks or QCs, and nothing archives them: the relayer
  must keep B, B+1 and B+2 as they are gossiped.
- RPC methods: `eth_call` (`getValidators()`), `eth_getBlockByNumber`, `eth_getProof`.
  `rpc.plasma.to` serves `eth_getProof` only at the head block; production needs an own reth node
  with a proof window.
- Rotations: none. Watch the committee contract; after a change, a new verifier deployment is
  needed.
- Signature handling: the relayer uncompresses committee keys (G1) and QC signatures (G2) to the
  EIP-2537 form; no aggregation is needed (QCs carry the aggregate).

## Chain-specific trust and caveats

- Consensus formats are derived from the `plasma-consensus` 1.1.0 release and live gossip, not from
  source code. A format change fails closed.
- The committee was set at block 32,618,986 (2026-09-16); historical `eth_call` returns an empty
  list before that. The same 10 members are returned at 33,000,000 and 33,898,400.
- No ClprService is deployed on Plasma. The fixture uses the validator-set proxy as a stand-in.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/plasma-live/mainnet.json`; Foundry export `test/verifiers/evm/plasma/fixtures/plasma-mainnet.json` |
| Captured | 2026-10-01T07:23:08Z (`capturedAt`) |
| Refresh | `npm run plasma-live:refresh && npx tsx test/e2e/relay/exportPlasmaForgeFixture.ts` (needs `go`) |
| Replay | `forge build && npm run test:e2e:plasma-live`; forge: `forge test --match-path 'test/verifiers/evm/plasma/*'` |
| What was verified | Mainnet block 33,898,400 (view 33,901,966, EVM hash `0x99bfd0c0…fb06`): gossip blocks re-hash to their envelope hashes; QC1 (voters 1,3,4,5,6,7,8) and QC2 (voters 1,2,3,4,5,7,8) verify with the EIP-2537 pairing; payload `state_root` equals the RPC block; MPT exclusion proofs for the stand-in's channel slots |

## Hiero → Plasma direction

Not started on this branch. Plasma is EVM, so a Hiero verifier deployed on Plasma is the expected
path; not evaluated here.
