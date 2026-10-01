# Arc → Hiero

Arc → Hiero · status: live-verified on Arc testnet (2026-10-01)

Arc is Circle's EVM L1. Blocks are final on commit by Malachite, a Rust implementation of the
Tendermint algorithm. `ArcMalachiteVerifier` checks the Ed25519 commit certificate against the
validator set held in `ValidatorRegistry` storage at the parent block, then proves the ClprService
queue slots in the block's Merkle-Patricia state. Full design:
[ArcMalachiteVerifier README](../../src/verifiers/evm/arc/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 5042002 / `eip155:5042002` (testnet). Mainnet: not checked, no public RPC answered on 2026-10-01 |
| Chain type | L1, EVM execution (reth, `circlefin/arc-node`), Malachite consensus |
| Finality source | Malachite commit certificate: Ed25519 precommits over SSZ votes, more than 2/3 of voting power |
| Verifier contract | `src/verifiers/evm/arc/ArcMalachiteVerifier.sol` · [family README](../../src/verifiers/evm/arc/README.md) |
| Trust tier | Honest 2/3+ of a permissioned, owner-managed validator set; set pinned by registry storage; deploy-time checkpoint |
| Typical bundle | 7,862,185 gas, 12,036 B calldata (testnet height 64,897,201, 11 signatures) |
| Rotation | Bundle + rotation 11,973,337 gas, 28,804 B calldata (live) |

## Deployment profile

| Parameter | Testnet value | Read from |
|---|---|---|
| `chainId` | `"5042002"` | `test/e2e/fixtures/arc-live/testnet.json` (`chainId`) |
| `ed25519Verifier` | Address of a deployed `Ed25519Verifier` on Hedera | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `registry` | `0x3600000000000000000000000000000000000002` (`ValidatorRegistry` proxy) | `test/e2e/fixtures/arc-live/testnet.json` (`registry`); `arc-node` `contracts/src/validator-manager` |
| `bootstrapSetHash` | `0xe1d31b8fb107e8ed88886ebee85822ca33966991b8db2246d6afbd10c05f5b5f` (21 validators) | `test/verifiers/evm/arc/fixtures/arc-testnet.json` (`setHash`) |
| `bootstrapRegistryRoot` | `0xe18966ea78c12c6b21fbf968dcbbb1ee713df5bf8d91b3287e7f1c761c9ce825` | `test/verifiers/evm/arc/fixtures/arc-testnet.json` (`registryRoot`) |
| `bootstrapHeight` | `64897127` in the tests | `test/verifiers/evm/arc/fixtures/arc-testnet.json` (`h1.height`) |
| Bootstrap source | `getActiveValidatorSet()` and the registry `storageHash` (`eth_getProof`) at the bootstrap height − 1 | `test/e2e/relay/buildArcLiveFixture.ts` |

## Relayer requirements

- RPC methods: `eth_getBlockByNumber` (H-1 and H), `arc_getCertificate(H)`
  (`https://rpc.testnet.arc.network`), `eth_getProof` for the registry at H-1 (and at H on a
  rotation) and for ClprService at H.
- Proof window: the public RPCs (`rpc.blockdaemon.testnet.arc.network`,
  `arc-testnet-rpc.publicnode.com`) serve `eth_getProof` only at the head. The official RPC does
  not serve it. Production needs an own reth node with a proof window.
- Rotations: a rotation bundle at every block where the registry storage changes. Watch registry
  events. Submit each rotation as its own transaction (a hop plus a bundle is 19.2M gas).
- No signature aggregation. The relayer picks the power-ordered minimal subset of certificate
  signatures.

## Chain-specific trust and caveats

- The validator set is permissioned: `ValidatorRegistry` is `onlyOwner` (Circle).
- Pure-Solidity Ed25519 costs about 0.64M gas per signature. A certificate with many low-power
  signers can need 16 signatures; a rotation bundle would then be about 15.2M gas (estimate), just
  over Hedera's limit.
- No ClprService is deployed on Arc. The fixture uses the `0x3600…0001` system proxy as a stand-in.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/arc-live/testnet.json`; Foundry export `test/verifiers/evm/arc/fixtures/arc-testnet.json` |
| Captured | 2026-10-01T05:32:11Z (`capturedAt`) |
| Refresh | `npm run arc-live:refresh && npx tsx test/e2e/relay/exportArcForgeFixture.ts` |
| Replay | `forge build && npm run test:e2e:arc-live`; forge: `forge test --match-path 'test/verifiers/evm/arc/*'` |
| What was verified | Certificates for testnet heights 64,897,127 and 64,897,201 (11 of 20 signatures sent, 21 validators, power 22,000 of 30,002); the set re-derived from a registry storage multiproof equals `getActiveValidatorSet()` at H-1; MPT exclusion proofs for the channel slots of the stand-in |

## Hiero → Arc direction

Not started on this branch. Arc is EVM, so a Hiero verifier deployed on Arc is the expected path;
not evaluated here.
