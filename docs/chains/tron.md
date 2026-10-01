# TRON → Hiero

Status: live-verified on TRON mainnet and Nile (2026-10-01). The attestation step used a stand-in transaction,
because no ClprService or attestor is deployed on TRON yet.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | Mainnet `tron:0x2b6653dc`; Nile `tron:0xcd8690dc`; Shasta not captured |
| Chain type | L1, DPoS with 27 Super Representatives (java-tron, TVM) |
| Finality source | java-tron solidification: 19 distinct active SRs have produced at or above the block |
| Verifier | `TronVerifier` ([family README](../../src/verifiers/evm/tron/README.md)) with `ClprTronAttestor` on TRON |
| Trust tier | 19 of the 27 anchored SR keys honest; attestor contract correct; bootstrap SR set trusted |
| Typical bundle | Mainnet: 959,816 gas (`eth_estimateGas`), 5,508 B calldata. Nile: 944,214 gas, 5,668 B |
| Rotation | Mainnet rotation + bundle: 2,750,499 gas, 13,796 B. Nile: 2,737,953 gas, 13,988 B |

## Deployment profile

| Parameter | Mainnet | Nile | Source |
|---|---|---|---|
| `srCount` | 27 | 27 | Active SR count; the fixture rotation windows name 27 distinct witnesses |
| `threshold` | 19 | 19 | `DposService.updateSolidBlock`: position `(int)(27 x 0.3) = 8` of 27 |
| `maintenanceIntervalMs` | 21,600,000 | 1,800,000 | `/wallet/getchainparameters`; `NETWORKS` in `buildTronLiveProof.ts` |
| `maintenanceOffsetMs` | 0 | 600,000 | Maintenance grid, `/wallet/getnextmaintenancetime`; `NETWORKS` in the capture script |
| `chainId` | `tron:0x2b6653dc` | `tron:0xcd8690dc` | Fixture `caip2` |
| Bootstrap SR set | 27 (witness, key) pairs at a recent period; 6 SRs sign with a permission key | 27 pairs; 1 SR signs with FN-DSA (key 0) | `verifyConfig` input, built from headers by the capture script |
| Attestor | `ClprTronAttestor` address, not deployed yet | not deployed yet | Deployment |

Shasta uses an interval of 600,000 ms and an offset of 480,000 ms; it was not captured.

## Relayer requirements

- TronGrid HTTP API: `/wallet/getblockbynum`, `/wallet/getblockbylimitnext`, `/wallet/getnowblock`,
  `/wallet/getchainparameters`, `/wallet/getnextmaintenancetime`. No archive node or `eth_getProof` is needed: only
  headers and transactions.
- A funded TRON account to send `attestQueue` once per bundle (energy for about one `getChannel` plus one manifest
  encode).
- Wait about 19 blocks after the attestation for confirmation.
- Rotation: only when the set or a signing key changes at a maintenance (every 6 h on mainnet, 30 min on Nile).

## Chain-specific trust and caveats

- 6 of the 27 mainnet SRs sign blocks with a permission key that differs from their witness address; key changes
  are followed by proven `AccountPermissionUpdateContract` transactions.
- Nile has one SR signing with FN-DSA-512 (TIP-899). Those blocks link the chain but never count toward the 19.
- The attestor's bytecode cannot be proven, because TRON does not commit to code; the address is pinned at
  configuration.

## Live verification

- Fixtures: `test/e2e/fixtures/tron-live/mainnet.json` (captured 2026-10-01T03:02Z), `nile.json`
  (2026-10-01T03:01Z).
- Refresh: `npm run tron-live:refresh`. Replay: `npm run test:e2e:tron-live`.
- Verified: `verifyConfig` from 27 real headers; a real maintenance boundary rotation (mainnet p82907 → p82908, Nile
  p994900 → p994901, membership unchanged in both); a real successful `TriggerSmartContract` with 19 confirmations
  in mainnet block 86,713,456 (324 transactions, Merkle depth 9) and Nile block 71,431,684 (7 transactions, depth 3).
  The call stands in for `attestQueue`, so `verifyBundle` passes every step and stops at `WrongAttestationCall`.

## Hiero → TRON

Not built. This is an assessment only; nothing is deployed.

| Item | TVM status (java-tron develop, live chain parameters) | Impact on a CLPR port |
|---|---|---|
| Compiler | `tronprotocol/solidity` tv_0.8.31 (Aug 2026); Shanghai, Cancun, Prague and Osaka flags enabled | ClprService should compile (source-level assessment; the compiler was not run) |
| Address format | 20 bytes in the ABI and VM; users see 21-byte `0x41…` / base58 | Use the 20-byte form; relayers convert |
| `CREATE2` | Prefix `0x41`, not `0xff` | CLPR core does not use it |
| `tx.gasprice` | Returns 0 unless `AllowTvmCompatibleEvm` (off on mainnet and Nile) | Connector charging based on `tx.gasprice` would pay endpoints nothing; a port must price energy another way |
| `{gas: X}` forwarding | No 63/64 retention unless `AllowTvmCompatibleEvm` | Recheck stipend guards around application callbacks |
| Units | `msg.value` in sun (1e-6 TRX); `TIMESTAMP` in seconds | Rescale bonds and stakes |
| Precompiles | 0x01-0x08 as on Ethereum; 0x09/0x0a are TRON-specific; no EIP-2537 (TIP-2537 closed as not planned, May 2026) | The BLS12-381 Hiero verifier cannot run |
| BN254 cost | Pure-Java BN254: a 2-pair pairing about 47-63 ms, a Groth16 about 103 ms (java-tron#6374) | The 80 ms per-transaction CPU cap (`getMaxCpuTimeOfOneTx`) binds, so the WRAPS check would hit `OUT_OF_TIME` |

What a port needs: a TVM build of ClprService with energy-based charging, and a Hiero verifier that fits in 80 ms of
TVM CPU without BLS12-381. Options are a Groth16 wrapper (still a 3-4 pair BN254 check, above the cap unless TRON
speeds up BN254 or raises the cap by proposal, up to 400 ms), splitting verification across transactions, or a
revived TIP-2537. Until then, Hiero → TRON cannot be verified trustlessly on TRON.
