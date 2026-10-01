# Stacks → Hiero

Status: live-verified on Stacks mainnet (2026-10-01) for signer signatures, signer-set rotation and MARF state
proofs. The CLPR queue record path runs on synthetic data because no Clarity CLPR service is deployed yet.

**Trust rests on the Stacks signer set, not on Bitcoin proof-of-work.**

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `stacks:1` (mainnet, chain id `0x00000001`); testnet `stacks:2147483648` (`0x80000000`) |
| Chain type | Bitcoin L2 with its own consensus (Nakamoto release, Proof of Transfer); Clarity contracts |
| Finality source | Signatures from signers holding at least 70% of the reward cycle's signer weight over the block hash |
| Verifier | `StacksVerifier` ([family README](../../src/verifiers/stacks/README.md)) |
| Trust tier | 70%-of-weight signer committee (Stacked STX). Bitcoin anchoring is not checked |
| Typical bundle | 12,084,553 gas, 56,868 B calldata (live mainnet map entry, one MARF segment) |
| Rotation | 13,136,304 gas, 59,844 B calldata per reward cycle (live 143 → 144, 31 signers) |

## Deployment profile

| Parameter | Mainnet | Where it was read |
|---|---|---|
| `hasher` | A deployed `ClprSha512t256Hasher` (13,456 B runtime) | Deploy once per Hedera network |
| `chainId` | `stacks:1` | stacks-common `CHAIN_ID_MAINNET` |
| `signersContract` | `SP000000000000000000002Q6VF78.signers` | stacks-core `signers.clar`, boot address |
| `principalVersion` | 22 | p2pkh single-sig mainnet version (`SP…`) |
| `genesis` | Signer set of a recent cycle: `/v3/stacker_set/{cycle}` keys → addresses, weights, in order | Any stacks-node; the fixture uses cycle 143 |
| Queue map | `clpr-queue`, key `(buff 32)` channel id (fixed in the verifier) | Proposed Clarity service layout |
| Manifest commitment | data-var `clpr-manifest-commitment`, `(buff 32)` = keccak256(manifest protobuf) | Proposed Clarity service layout |
| Header versions | 0 and 1 (mainnet blocks are version 1, 217-byte preimages) | stacks-core `NAKAMOTO_BLOCK_VERSION_EPOCH_4` |
| Reward cycle | 2,100 Bitcoin blocks, prepare phase 100 | `/v2/pox` |

Testnet: `stacks:2147483648`, `ST000000000000000000002AMW42H.signers`, principal version 26. Not live-verified.

## Relayer requirements

- stacks-node RPC (public Hiro API worked): `POST /v2/map_entry/{addr}/{contract}/{map}?proof=1[&tip=]`,
  `GET /v3/blocks/{index_block_hash}`, `GET /v3/stacker_set/{cycle}`, `GET /v2/pox`.
- Prove the queue record at the block that last wrote it (its proof has one segment). Take a proof at the tip; its
  first back-pointer names that block. Proofs through back-pointers cost 16M gas or more.
- Strip the signer signatures from the header, recover each signer's key and send `index ‖ v ‖ r ‖ s` in ascending
  index order.
- Once per reward cycle (about two weeks), call `registerRotation` with the block that wrote
  `cycle-signer-set[N+1]` (in cycle N's prepare phase). Missed cycles need proofs at historical tips.
- Move each channel's anchor to the new set soon after a rotation (see caveats).

## Chain-specific trust and caveats

- Signers sign with secp256k1 over the 32-byte block hash; the verifier uses `ecrecover` and a 70% weight threshold,
  as stacks-core `verify_signer_signatures` does.
- A signer set stays acceptable for a channel until that channel's anchor moves on. Signers who held 70% of an old
  cycle can sign blocks such a channel would still accept.
- Bitcoin anchoring (sortition, block-commits, tenure changes) is ignored.
- The verifier proves only the queue record. The Clarity service itself must be correct.
- Endpoint manifests are proven at channel setup only (the `clpr-manifest-commitment` data-var); bundles return
  manifest version 0.

## Live verification

- Fixture: `test/e2e/fixtures/stacks-live/mainnet.json`, captured 2026-10-01 from `https://api.hiro.so`
  (stacks-node 4.0.4): signer sets of cycles 143 (29 signers) and 144 (31 signers), the cycle-143 block at chain
  length 9,051,704 that wrote `cycle-signer-set[144]` (signed by 2,809 of 4,000 weight), and a map entry of
  `SP21EK0KSQG7HEHBGCVRJGPGFMV8SCA2B85X01DK2.blocksurvey-proof-of-submission` written at chain length 9,101,542
  (2,875 of 4,000), also proven at 9,101,543 (2 segments) and 9,101,546 (3 segments).
- Refresh: `npm run stacks-live:refresh`; offline check: `npx tsx test/e2e/relay/buildStacksProof.ts --check`.
- Replay: `forge test --match-path 'test/verifiers/stacks/*'` (45 tests, including the SHA-512/256 hasher vectors),
  the compliance suite `test/verifiers/compliance/StacksComplianceTest.t.sol` (21 cases, synthetic) and
  `npm run test:e2e:stacks-live` (7 tests on anvil: rotation as a transaction, entries with 1, 2 and 3 segments,
  rejections).

## Hiero → Stacks

Not started. A Clarity contract would have to verify Hiero state proofs, which are hinTS aggregate BLS12-381
signatures (see `src/verifiers/hiero/TSSVerifier.sol`). Clarity's crypto builtins are hashes (SHA-256, SHA-512,
SHA-512/256, Keccak-256), `secp256k1-verify` and, from Clarity 4, `secp256r1-verify`; there is no BLS12-381 or pairing
operation, and adding one needs a Stacks hard fork. The options today are a t-of-n attestor contract on Stacks
(weaker trust) or a Clarity upgrade with BLS12-381.
