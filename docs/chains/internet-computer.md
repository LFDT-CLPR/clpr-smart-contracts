# Internet Computer → Hiero

Internet Computer → Hiero · status: live-verified on ICP mainnet (2026-10-01, fixture capture timestamp)

An Internet Computer subnet certifies its state with a threshold BLS signature over a hash-tree root,
and the NNS root key certifies the subnet key through a delegation. `IcpVerifier` checks that chain on
Hedera with EIP-2537 and reads a CLPR canister's queue record from the canister's certified data.
Full design: [family README](../../src/verifiers/icpmvx/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | No CAIP-2 namespace is registered for ICP (ChainAgnostic/namespaces, 2026-10-01). The verifier takes the chain id as a constructor string; the tests use `icp:mainnet` |
| Chain type | L1, subnets of replicas; chain-key certification |
| Finality source | Certificate: subnet threshold BLS signature (BLS12-381, signature in G1, key in G2, `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`) on `domain_sep("ic-state-root") · root`, delegated from the NNS root key |
| Verifier contract | `src/verifiers/icpmvx/IcpVerifier.sol` · [family README](../../src/verifiers/icpmvx/README.md) |
| Trust tier | NNS root key + the signing threshold of the canister's subnet + the CLPR canister's controllers |
| Typical bundle | Live certificate + witness (ckBTC ledger): 844,507 gas, 2,980 B per transaction. Synthetic `verifyBundle` with 10 × 256 B messages: 566,385 gas execution, 4,804 B calldata |
| Rotation | None: every certificate carries its delegation (0 gas, 0 B) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `chainId_` | `icp:mainnet` (placeholder, see above) | `test/e2e/tests/verifiers/icp-live.spec.ts` |
| `rootKeyDer` | `308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6e…0baaae` (133 bytes) | agent-js `IC_ROOT_KEY` (`packages/core/src/agent/agent/http/index.ts`) |
| `rootKeyUncompressed` | the same key as an EIP-2537 G2 point (256 bytes) | `test/e2e/fixtures/icp-live/mainnet.json` (`rootKeyUncompressed`), computed by `buildIcpLiveFixture.ts` |
| `maxDelegationAgeNanos` | 86,400 s in the anvil replay (delegations were 206 s and 210 s old); 0 disables | `icp-live.spec.ts` |
| Trust anchor | `keccak256(rootKeyDer)` | `IcpVerifier.ROOT_KEY_ID` |
| Service address | the CLPR canister principal (1–29 bytes) | `IcpVerifier._checkPrincipal` |
| Canister witness | `clpr/queue/<channelId>` (89-byte record), `clpr/manifest`, `clpr/config` (keccak256 commitments) | `IcpVerifier.sol` header |

## Relayer requirements

- Anonymous query calls to a boundary node (`https://icp-api.io/api/v2/canister/<id>/query`): the CLPR
  canister must expose a query that returns `ic0.data_certificate()` and the witness of the requested
  labels. No keys and no archive are needed; certificates are fresh on every query.
- For tooling: `read_state` (`/api/v3/canister/<id>/read_state`) for non-certified-data paths.
- Off-chain work: decompress the BLS signatures (G1) and the subnet key (G2) to EIP-2537 form, re-encode
  trees as definite-length CBOR, and pick the `/canister_ranges` shard when the delegation uses the
  sharded form (`buildIcpLiveFixture.ts:certToJson`).
- No rotation cadence.

## Chain-specific trust and caveats

- The CLPR canister's controllers can change its code; a blackholed or governance-controlled canister
  removes that trust.
- Root-subnet canisters have certificates without delegation, signed by the root key.
- The verifier does not check certificate age; `ClprService` rejects older queue states.
- No CLPR canister exists on ICP yet; the live fixture proves the ckBTC ledger's ICRC-3 tip and two
  `module_hash` values through the same certificate code.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/icp-live/mainnet.json` |
| Captured | 2026-10-01T08:31:48Z; ckBTC ledger (`mxzaz-hqaaa-aaaar-qaada-cai`) tip index 4,683,245, subnet `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`; ICP ledger (`ryjl3-tyaaa-aaaaa-aaaba-cai`) on the NNS subnet |
| Refresh | `npm run icp-live:refresh` |
| Replay | `forge build && npm run test:e2e:icp-live`; Foundry: `forge test --match-path test/verifiers/icpmvx/IcpLive.t.sol -vv` |
| What was verified | A delegated data certificate (legacy canister ranges) with the ledger's witness to `last_block_hash`; a delegated read_state v3 certificate scoped by a `/canister_ranges` shard; a root-subnet read_state certificate; rejections of a tampered witness, a foreign signature, a canister outside the ranges, a foreign subnet key, a delegation signed by another key, and an old delegation |

## Hiero → Internet Computer direction

Not started on this branch. It needs a Hiero verifier written as a canister.
