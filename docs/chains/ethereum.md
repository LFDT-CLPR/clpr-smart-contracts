# Ethereum → Hiero · status: live-verified on Sepolia data (anvil) and Hedera testnet (2026-09-30)

A bundle from a CLPR Service on Ethereum is accepted on Hiero by `EthMainnetVerifier`, an on-chain
sync-committee light client. The family README explains the proof chain in full:
[src/verifiers/evm/ethereum/README.md](../../src/verifiers/evm/ethereum/README.md).

## Quick facts

| | |
|---|---|
| Chain id / CAIP-2 | Ethereum mainnet `eip155:1`; live data from Sepolia `eip155:11155111` |
| Chain type | L1, proof of stake (beacon chain + execution layer) |
| Finality source | Sync-committee BLS aggregate (≥ 342 of 512) over the attested beacon header |
| Verifier | `EthMainnetVerifier` ([source](../../src/verifiers/evm/ethereum/EthMainnetVerifier.sol)), 19,338 B runtime |
| Trust tier | Light client: trusts 2/3 of the current sync committee and the bootstrap committee |
| Typical bundle | 1,645,052 gas, 19,140 B calldata (486/512 signers, ACK-only; same on anvil and Hedera testnet) |
| Rotation | 4,836,081 gas, 66,902 B rotation items (once per 8,192 slots, about 27 h) |

## Deployment profile

`EthMainnetVerifier` has no constructor arguments. The chain-specific values go into the trust anchor
through `verifyConfig`.

| Value | Sepolia (live fixture) | Mainnet | Read from |
|---|---|---|---|
| `genesisValidatorsRoot` | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` | read at deployment | `GET /eth/v1/beacon/genesis` |
| `forkVersion` | `0x90000075` (Fulu, epoch 272640) | current fork version at deployment | `GET /eth/v1/config/spec`, `compute_fork_version(epoch(signature_slot − 1))` |
| Bootstrap committee and slot | period of the finalized header | same | `GET /eth/v1/beacon/light_client/bootstrap/{root}`, branch checked at gindex 86 |
| Peer `ClprService` code hash | Sepolia deposit contract `0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D` (no ClprService on Sepolia yet) | the deployed `ClprService` runtime code hash | `eth_getProof` account `codeHash` |
| Generalized indices | 802 (execution `state_root` in body), 87 (`next_sync_committee` in state) | same | Contract constants; match Electra/Fulu |
| Sync-committee size, period | 512 keys, 8,192 slots | same | `config/spec` `SYNC_COMMITTEE_SIZE`, `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` = 256 |

## Relayer requirements

- **Beacon API** (any public node): `light_client/finality_update`, `light_client/bootstrap/{root}`,
  `light_client/updates?start_period=P&count=1`, `beacon/genesis`, `config/spec`.
- **Execution RPC**: `eth_getProof` and `eth_getBlockByNumber` at the attested execution block. A
  non-archive node is enough for normal bundles. A rotation in the same transaction as a full bundle needs
  `eth_getProof` at the rotation update's block, which needs an archive node.
- **BLS work off-chain**: decompress the committee keys and the signature to EIP-2537 uncompressed form;
  build one 416-byte non-signer entry per clear participation bit.
- **Cadence**: at least one rotation bundle per sync-committee period (about 27 h). Missing a whole
  period strands the anchor.

## Chain-specific trust and caveats

This is the family baseline. The fork version is
fixed in the anchor, so an Ethereum fork that changes it needs an anchor update; Gloas (EIP-7732) needs new
verifier code.

## Live verification

| | |
|---|---|
| Fixture | `test/e2e/fixtures/sepolia-live/capture.json` (Sepolia, Fulu, captured 2026-09-30, slot 11254195, 486/512) |
| Hedera measurement | `test/e2e/fixtures/sepolia-live/hiero-gas-hedera-testnet.json` (2026-09-30) |
| Replay | `forge build && npm run test:e2e:eth-live` (8 checks: full `verifyBundle`, wrong code hash, wrong fork version, tampered branch, flipped bit, dropped non-signer, real rotation) |
| Refresh | `npm run eth-live:refresh` |
| On Hedera | `npm run gas:eth-verifier:testnet` |

What was verified: the real sync-committee signature, the real execution branch and the real account
proof, all through the unmodified production `verifyBundle`. The storage step checks MPT exclusion proofs
because the target account has no CLPR channel. On Hedera testnet `verifyBundle` succeeded twice with
1,645,052 gas each (tx `0xaf0b0238d6a430d2750e60648d5b2d7af92990e948303dd662e0b1ee38b71d91`).

## Hiero → Ethereum direction

`HieroVerifier` (deployed on the Ethereum side) needs a Hiero state proof with a WRAPS-settled hinTS
signature (3,432 B) and native CLPR state items. On the local Solo network the reply's real hinTS
signature verifies on anvil, but Solo's block node has no proof service and its block proofs use the
genesis Schnorr form (2,920 B), so the production `TSSVerifier` stops with `ClprHieroWrapsProofRequired`.
It needs a block node with a state-proof service and WRAPS-enabled consensus nodes. See
`test/e2e/README.md`.
