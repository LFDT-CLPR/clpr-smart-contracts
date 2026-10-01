# Hyperliquid (HyperEVM) → Hiero

Hyperliquid (HyperEVM) → Hiero · status: live-verified on HyperEVM mainnet (2026-10-01), attestor-trusted

> **Weaker trust tier: t-of-n attestors.** HyperEVM finality is not proven. The verifier trusts any
> block that K of N CLPR attestors sign. If K attestors collude they can forge any queue state.

`HyperEvmVerifier` proves a `ClprQueueRecord` log, emitted by `ClprHyperEvmBeacon` on HyperEVM,
out of an attested block: header → `receiptsRoot` → receipt → log. Full design:
[HyperEvmVerifier README](../../src/verifiers/evm/hyperliquid/README.md).

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | 999 / `eip155:999` (mainnet); 998 (testnet, not live-checked) |
| Chain type | L1 execution layer of Hyperliquid (HyperBFT); EVM; headers have `stateRoot = 0x0` |
| Finality source | None proven. K-of-N secp256k1 attestor signatures over `(chainId, number, blockHash)` |
| Verifier contract | `src/verifiers/evm/hyperliquid/HyperEvmVerifier.sol` + `ClprHyperEvmBeacon.sol` on HyperEVM · [family README](../../src/verifiers/evm/hyperliquid/README.md) |
| Trust tier | **t-of-n attestors** (K > N/2) |
| Typical bundle | 556,441 gas, 3,332 B (live block, 13-of-19 test attestors) |
| Rotation | 734,875 gas, 4,612 B (bundle + one 13-of-19 → 13-of-19 rotation) |

## Deployment profile

| Parameter | Value | Read from |
|---|---|---|
| `caip2` | `"eip155:999"` | `test/e2e/tests/verifiers/hyperevm-live.spec.ts` |
| `hyperEvmChainId` | `999` | same; bound into every attestation digest |
| `beacon` (anchor) | Address of `ClprHyperEvmBeacon` on HyperEVM; **not deployed yet** | `src/verifiers/evm/hyperliquid/ClprHyperEvmBeacon.sol` |
| Attestor set (anchor `setHash`) | `keccak256(abi.encode(threshold, attestors))`, attestors ascending, threshold > N/2; **no set exists yet** | `src/libraries/proof/attestor/ClprAttestorQuorum.sol` |
| `epoch`, `minBlock` | 0 at setup; advanced by rotations | `HyperEvmVerifier.sol:_rotate` |

## Relayer requirements

- RPC: `eth_getBlockByNumber` and `eth_getBlockReceipts` (`https://rpc.hyperliquid.xyz/evm`); no
  archive or `eth_getProof` needed.
- A transaction calling `ClprHyperEvmBeacon.publish(channelId)` on HyperEVM for each bundle (any
  account).
- Collect K attestor signatures on the block digest. Each attestor should check the block on its own
  HyperEVM node.
- Attestor-set changes: a rotation signed by the current set, carried in a bundle.

## Chain-specific trust and caveats

- Hyperliquid's validators sign nothing that covers HyperEVM blocks (Bridge2 validators sign bridge
  actions only), so no validator-based light client is possible today.
- HyperEVM has no EIP-2537 precompiles; irrelevant here (attestors use secp256k1).
- Upgrade path: validator-signed HyperEVM block hashes, or a real state root, would replace the
  attestors.

## Live verification

| Item | Value |
|---|---|
| Fixture | `test/e2e/fixtures/hyperevm-live/mainnet.json` |
| Captured | 2026-10-01T05:47:16Z (`capturedAt`) |
| Refresh | `npm run hyperevm-live:refresh` |
| Replay | `forge build && npm run test:e2e:hyperevm-live` |
| What was verified | Block 47,353,393: the re-encoded header hashes to the real block hash, `stateRoot` is zero, the receipts trie rebuilt from all 7 receipts matches `receiptsRoot`, and the real log of transaction 2 is proven. Attestations and the rotation use **test attestor keys**; the real log is not a `ClprQueueRecord` (no beacon deployed), so `verifyBundle` stops at the event check |

## Hiero → Hyperliquid direction

Not built on this branch. HyperEVM is EVM, so a Hiero verifier deployed on HyperEVM is the expected
path. HyperEVM lacks the EIP-2537 BLS precompiles, which limits which Hiero proof formats can be
checked there; not evaluated here.
