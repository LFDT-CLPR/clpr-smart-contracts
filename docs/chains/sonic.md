# Sonic → Hiero

Sonic → Hiero · status: blocked (no BLS finality certificate on mainnet)

Sonic was planned for this family because of its certification chain (`scc`), which defined
committees that sign blocks with BLS. That component was a prototype whose certificates were never
signed, and it was removed from the client in commit `2f9a629b` ("Remove deprecated SCC component",
#1057). No Sonic code is on this branch. See the
[family README](../../src/verifiers/evm/blscommittees/README.md), "Limits and known gaps".

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 146 / `eip155:146` |
| Chain type | L1, EVM, Lachesis aBFT consensus |
| Finality source | None usable on-chain today (see below) |
| Contract | None |
| Trust tier | — |
| Typical bundle / rotation | — |

## Deployment profile

None.

## Relayer requirements

What was checked on 2026-10-01 against `https://rpc.soniclabs.com`:
- `web3_clientVersion` → `Sonic/v2.2.2-…`.
- `sonic_getBlockCertificates` → "the method sonic_getBlockCertificates does not exist/is not available".
- `eth_getProof` (wS `0x039e…aD38`, slot 0, `latest`) returns an Ethereum-style MPT account and
  storage proof, so the storage half could reuse `ClprEvmBundleVerifier` once a finality source exists.

## Chain-specific trust and caveats

The remaining finality evidence is the validators' secp256k1 signatures on Lachesis events. Turning
those into an on-chain proof of a finalized block (event DAG, stake-weighted quorum, epoch
validator sets) was not researched on this branch.

## Live verification

None.

## Hiero → Sonic direction

Not started. Sonic is EVM-compatible, so the Hiero-side verifiers used on other EVM chains apply.
